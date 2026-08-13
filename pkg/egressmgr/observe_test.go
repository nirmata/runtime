package egressmgr

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return a
}

// ipKey builds an allow-decision observation key; ipKeyDeny a deny-decision one.
func ipKey(t *testing.T, s string) egressfilter.IPEventKey {
	t.Helper()
	return egressfilter.IPEventKey{Addr: addr(t, s), Decision: runtimeevent.DecisionAllow}
}

func ipKeyDeny(t *testing.T, s string) egressfilter.IPEventKey {
	t.Helper()
	return egressfilter.IPEventKey{Addr: addr(t, s), Decision: runtimeevent.DecisionDeny}
}

// a monitor policy observes without enforcing: nothing reaches the allow/deny
// maps and the default-deny bit stays clear, so the bpf program cannot return
// -EPERM for a policy the user believes is only watching.
func TestObservePolicyProgramsNoIpsButSetsObserveFlag(t *testing.T) {
	mode := compiler.ModeMonitor
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")

	mustRpEvent(t, e, rp("rp-1", mode, webLabels, []string{"1.1.1.1"}, []string{"9.9.9.9", "*"}), events.EventTypeCreate)

	wantPairs(t, "AddIps", f.adds, nil)
	wantPairs(t, "DeleteIps", f.deletes, nil)
	wantLiveIps(t, f, []string{}, []string{})
	wantDefaultDeny(t, f, false)
	wantDefaultDenyOwners(t, e, "pod-1")
	wantObserveFlag(t, f, true)
	wantAttachedRps(t, e, "pod-1", "rp-1")
	// the only flag write is the observe bit
	want := []flagToggle{{idx: egressfilter.OBSERVE, val: true}}
	if diff := cmp.Diff(want, f.toggles, cmp.AllowUnexported(flagToggle{})); diff != "" {
		t.Errorf("flag toggles (-want +got):\n%s", diff)
	}

	// and a pod that matches nothing is not observed
	other := addPod(t, e, "pod-2", apiLabels, "/cg/pod-2")
	wantObserveFlag(t, other, false)
	wantAttachedRps(t, e, "pod-2")
}

func TestObserveFlagFollowsTheAttachedPolicies(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)
	wantAttachedRps(t, e, "pod-1", "rp-1", "rp-2")

	// the first one leaving keeps observation on
	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)
	wantObserveFlag(t, f, true)
	wantAttachedRps(t, e, "pod-1", "rp-2")

	// the selector of the last one moving away stops it
	mustRpEvent(t, e, rp("rp-2", compiler.ModeMonitor, apiLabels, nil, nil), events.EventTypeUpdate)
	wantObserveFlag(t, f, false)
	wantAttachedRps(t, e, "pod-1")
	// an observe policy detaching may never touch the ip maps: it never
	// programmed anything, so a DeleteIps here would remove another policy's ips
	wantPairs(t, "DeleteIps", f.deletes, nil)
}

// crossing the enforce/observe line must rebuild the pod's programming rather
// than diff it: an enforce -> monitor switch has to unprogram everything.
func TestModeTransitionsRebuildProgramming(t *testing.T) {
	t.Run("enforce to monitor unprograms and observes", func(t *testing.T) {
		e, _, _ := newTestManager()
		f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
		mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)
		f.reset()

		mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeUpdate)

		wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair([]string{"1.1.1.1"}, nil)})
		wantPairs(t, "AddIps", f.adds, nil)
		wantLiveIps(t, f, []string{}, []string{})
		wantDefaultDeny(t, f, false)
		wantDefaultDenyOwners(t, e, "pod-1")
		wantObserveFlag(t, f, true)
		assertSharedPointer(t, e, "rp-1", "pod-1")
	})

	t.Run("monitor to enforce programs and keeps observing", func(t *testing.T) {
		e, _, _ := newTestManager()
		f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
		mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)
		f.reset()

		mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeUpdate)

		wantPairs(t, "AddIps", f.adds, []ipPair{pair([]string{"1.1.1.1"}, []string{"*"})})
		wantLiveIps(t, f, []string{"1.1.1.1"}, []string{})
		wantDefaultDeny(t, f, true)
		wantDefaultDenyOwners(t, e, "pod-1", "rp-1")
		wantObserveFlag(t, f, true)
	})
}

func TestCollectObservationsEmitsNetEventsWithPodUidAndCounts(t *testing.T) {
	e, _, _ := newTestManager()
	f1 := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	f2 := addPod(t, e, "pod-2", webLabels, "/cg/pod-2")
	// pod-3 matches nothing, so it is not polled
	f3 := addPod(t, e, "pod-3", apiLabels, "/cg/pod-3")
	mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)

	f1.ipEvents = map[egressfilter.IPEventKey]uint32{
		ipKey(t, "10.0.0.2"):     3,
		ipKeyDeny(t, "10.0.0.2"): 2, // same destination, denied by the kernel
		ipKey(t, "10.0.0.1"):     1,
		ipKey(t, "10.0.0.3"):     0, // never counted, must not be emitted
	}
	f2.ipEvents = map[egressfilter.IPEventKey]uint32{ipKey(t, "8.8.8.8"): 7}

	got, err := e.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations: %v", err)
	}

	want := []runtimeevent.Event{
		{
			Kind: runtimeevent.KindNet, Time: testTime, Count: 1,
			Net: &runtimeevent.NetFacts{DestIP: addr(t, "10.0.0.1")},
			Pod: runtimeevent.PodIdentity{UID: "pod-1", Labels: webLabels},
		},
		{
			Kind: runtimeevent.KindNet, Time: testTime, Count: 3,
			Net: &runtimeevent.NetFacts{DestIP: addr(t, "10.0.0.2")},
			Pod: runtimeevent.PodIdentity{UID: "pod-1", Labels: webLabels},
		},
		{
			// the deny counter for the same destination is its own event, sorted
			// after the allow one
			Kind: runtimeevent.KindNet, Time: testTime, Count: 2, KernelDenied: true,
			Net: &runtimeevent.NetFacts{DestIP: addr(t, "10.0.0.2")},
			Pod: runtimeevent.PodIdentity{UID: "pod-1", Labels: webLabels},
		},
		{
			Kind: runtimeevent.KindNet, Time: testTime, Count: 7,
			Net: &runtimeevent.NetFacts{DestIP: addr(t, "8.8.8.8")},
			Pod: runtimeevent.PodIdentity{UID: "pod-2", Labels: webLabels},
		},
	}
	if diff := cmp.Diff(want, got, cmp.Comparer(func(a, b netip.Addr) bool { return a == b })); diff != "" {
		t.Errorf("observations (-want +got):\n%s", diff)
	}
	if f3.reads != 0 {
		t.Errorf("an unobserved pod was polled %d times", f3.reads)
	}

	// the read is destructive: a second poll reports the next delta only
	again, err := e.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("second CollectObservations: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second poll returned stale observations: %v", again)
	}
}

// enforce-mode policies are observed too: gating observation on monitor mode left
// a pod whose only policies enforce with no ip events at all.
func TestCollectObservationsIncludesEnforceOnlyPods(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)
	wantObserveFlag(t, f, true)
	f.ipEvents = map[egressfilter.IPEventKey]uint32{
		ipKey(t, "1.1.1.1"):      5,
		ipKeyDeny(t, "10.0.0.9"): 2,
	}

	got, err := e.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations: %v", err)
	}
	want := []runtimeevent.Event{
		{
			Kind: runtimeevent.KindNet, Time: testTime, Count: 5,
			Net: &runtimeevent.NetFacts{DestIP: addr(t, "1.1.1.1")},
			Pod: runtimeevent.PodIdentity{UID: "pod-1", Labels: webLabels},
		},
		{
			Kind: runtimeevent.KindNet, Time: testTime, Count: 2, KernelDenied: true,
			Net: &runtimeevent.NetFacts{DestIP: addr(t, "10.0.0.9")},
			Pod: runtimeevent.PodIdentity{UID: "pod-1", Labels: webLabels},
		},
	}
	if diff := cmp.Diff(want, got, cmp.Comparer(func(a, b netip.Addr) bool { return a == b })); diff != "" {
		t.Errorf("observations (-want +got):\n%s", diff)
	}
	if f.reads != 1 {
		t.Errorf("filter was polled %d times, want 1", f.reads)
	}
}

// a pod no policy matches at all is never polled.
func TestCollectObservationsSkipsPodsWithoutPolicies(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", apiLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	f.ipEvents = map[egressfilter.IPEventKey]uint32{ipKey(t, "10.0.0.1"): 5}

	got, err := e.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("events emitted for a pod with no attached policy: %v", got)
	}
	if f.reads != 0 {
		t.Errorf("filter was polled %d times, want 0", f.reads)
	}
}

// one unreadable pod may not hide the observations of the others.
func TestCollectObservationsKeepsGoingAfterAReadError(t *testing.T) {
	e, _, _ := newTestManager()
	bad := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	good := addPod(t, e, "pod-2", webLabels, "/cg/pod-2")
	mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)

	bad.readErr = errors.New("map read boom")
	good.ipEvents = map[egressfilter.IPEventKey]uint32{ipKey(t, "8.8.8.8"): 2}

	got, err := e.CollectObservations(context.Background())
	if err == nil {
		t.Fatal("expected the read error to be reported")
	}
	if len(got) != 1 || got[0].Pod.UID != "pod-2" {
		t.Errorf("observations of the healthy pod were lost: %v", got)
	}
}

func TestCollectObservationsRespectsCancelledContext(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)
	f.ipEvents = map[egressfilter.IPEventKey]uint32{ipKey(t, "8.8.8.8"): 2}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := e.CollectObservations(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error: got %v, want context.Canceled", err)
	}
	if len(got) != 0 {
		t.Errorf("events emitted for a cancelled poll: %v", got)
	}
	if f.reads != 0 {
		t.Errorf("filter was polled despite a cancelled context")
	}
}

// a target the runtime cannot honor reaches the policy's status, not only a log
// line nobody reads.
func TestUnsupportedTargetsAreReportedOnPolicyStatus(t *testing.T) {
	tests := []struct {
		name       string
		allow      []string
		deny       []string
		wantStatus metav1.ConditionStatus
		wantReason string
		wantIn     []string
	}{
		{
			name:       "all targets supported",
			allow:      []string{"1.1.1.1", "10.0.0.0/24"},
			deny:       []string{"*"},
			wantStatus: metav1.ConditionTrue,
			wantReason: v1alpha1.ReasonAllTargetsSupported,
		},
		{
			name:       "no targets at all",
			wantStatus: metav1.ConditionTrue,
			wantReason: v1alpha1.ReasonNoTargets,
		},
		{
			name:       "ipv6 target",
			deny:       []string{"2001:db8::1"},
			wantStatus: metav1.ConditionFalse,
			wantReason: v1alpha1.ReasonUnsupportedTargets,
			wantIn:     []string{"2001:db8::1", egressfilter.ReasonIPv6},
		},
		{
			name:       "cidr wider than /24",
			deny:       []string{"10.0.0.0/8"},
			wantStatus: metav1.ConditionFalse,
			wantReason: v1alpha1.ReasonUnsupportedTargets,
			wantIn:     []string{"10.0.0.0/8", egressfilter.ReasonCIDRTooWide},
		},
		{
			name:       "hostname is a supported target",
			allow:      []string{"api.example.com"},
			wantStatus: metav1.ConditionTrue,
			wantReason: v1alpha1.ReasonAllTargetsSupported,
		},
		{
			name:       "wildcard hostname",
			allow:      []string{"*.example.com"},
			wantStatus: metav1.ConditionFalse,
			wantReason: v1alpha1.ReasonUnsupportedTargets,
			wantIn:     []string{"*.example.com", egressfilter.ReasonWildcard},
		},
		{
			name:       "mixed: the supported half is still programmed",
			allow:      []string{"1.1.1.1", "not an address"},
			wantStatus: metav1.ConditionFalse,
			wantReason: v1alpha1.ReasonUnsupportedTargets,
			wantIn:     []string{"not an address", egressfilter.ReasonNotAnIP},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _, status := newTestManager()
			f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")

			mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, tc.allow, tc.deny), events.EventTypeCreate)

			cond, ok := status.latest("rp-1", v1alpha1.ConditionTargetsValid)
			if !ok {
				t.Fatalf("no %s condition was recorded for rp-1 (all: %v)", v1alpha1.ConditionTargetsValid, status.all("rp-1"))
			}
			if cond.Status != tc.wantStatus {
				t.Errorf("condition status: got %s, want %s (message %q)", cond.Status, tc.wantStatus, cond.Message)
			}
			if cond.Reason != tc.wantReason {
				t.Errorf("condition reason: got %s, want %s", cond.Reason, tc.wantReason)
			}
			if !cond.LastTransitionTime.Time.Equal(testTime) {
				t.Errorf("condition time: got %v, want %v", cond.LastTransitionTime.Time, testTime)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(cond.Message, want) {
					t.Errorf("condition message %q does not mention %q", cond.Message, want)
				}
			}
			// the supported targets still reach the maps
			if tc.name == "mixed: the supported half is still programmed" {
				wantLiveIps(t, f, []string{"1.1.1.1"}, []string{})
			}
		})
	}
}

// a nil status recorder does not stop the manager: the daemon may run without one.
func TestNilStatusRecorderIsTolerated(t *testing.T) {
	ff := &fakeFactory{}
	pff := &fakeProtoFactory{}
	e := NewEgressManager(logr.Discard(), nil, nil)
	e.newFilter = ff.new
	e.newProtoFilter = pff.new
	e.clock = func() time.Time { return testTime }
	addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"2001:db8::1"}, nil), events.EventTypeCreate)
	if _, ok := e.rps["rp-1"]; !ok {
		t.Error("policy was not tracked when the status recorder is nil")
	}
}

// the domain the filter resolved has to survive onto the event, otherwise a
// finding can name only an address the operator has to look up by hand.
func TestCollectObservationsCarriesTheResolvedDomain(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)

	named := ipKey(t, "10.0.0.1")
	named.Domain = "api.example.com"
	f.ipEvents = map[egressfilter.IPEventKey]uint32{
		named:                3,
		ipKey(t, "10.0.0.2"): 1, // no domain was attributed
	}

	got, err := e.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations: %v", err)
	}

	want := []runtimeevent.Event{
		{
			Kind: runtimeevent.KindNet, Time: testTime, Count: 3,
			Net: &runtimeevent.NetFacts{DestIP: addr(t, "10.0.0.1"), Domain: "api.example.com"},
			Pod: runtimeevent.PodIdentity{UID: "pod-1", Labels: webLabels},
		},
		{
			Kind: runtimeevent.KindNet, Time: testTime, Count: 1,
			Net: &runtimeevent.NetFacts{DestIP: addr(t, "10.0.0.2")},
			Pod: runtimeevent.PodIdentity{UID: "pod-1", Labels: webLabels},
		},
	}
	if diff := cmp.Diff(want, got, cmp.Comparer(func(a, b netip.Addr) bool { return a == b })); diff != "" {
		t.Errorf("observations (-want +got):\n%s", diff)
	}
}

// one address can be reached under several names, so the domain has to take
// part in the ordering or those entries come out in map iteration order.
func TestSortedIPEventKeysBreaksTiesOnDomain(t *testing.T) {
	counts := make(map[egressfilter.IPEventKey]uint32)
	for _, domain := range []string{"b.example.com", "", "a.example.com"} {
		key := ipKey(t, "10.0.0.1")
		key.Domain = domain
		counts[key] = 1
	}
	denied := ipKeyDeny(t, "10.0.0.1")
	denied.Domain = "a.example.com"
	counts[denied] = 1

	want := []string{"", "a.example.com", "b.example.com", "deny/a.example.com"}
	for i := 0; i < 32; i++ {
		got := make([]string, 0, len(counts))
		for _, key := range sortedIPEventKeys(counts) {
			if key.Decision == runtimeevent.DecisionDeny {
				got = append(got, "deny/"+key.Domain)
				continue
			}
			got = append(got, key.Domain)
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("run %d order (-want +got):\n%s", i, diff)
		}
	}
}

// the kernel's own drop counter is the only signal that a pod's observations
// are incomplete; dropping it makes a truncated view look like a quiet one.
func TestCollectObservationsReportsKernelDrops(t *testing.T) {
	e, _, _ := newTestManager()
	var got []loss
	e.onLoss = func(reason string, delta uint64) { got = append(got, loss{reason: reason, delta: delta}) }
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)

	f.lost = 7
	if _, err := e.CollectObservations(context.Background()); err != nil {
		t.Fatalf("CollectObservations: %v", err)
	}
	want := []loss{{reason: runtimeevent.ReasonCountMapFull, delta: 7}}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(loss{})); diff != "" {
		t.Errorf("losses (-want +got):\n%s", diff)
	}

	// the kernel counter is cumulative, so a second poll with no new drops must
	// report nothing rather than the running total again
	if _, err := e.CollectObservations(context.Background()); err != nil {
		t.Fatalf("second CollectObservations: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("losses after an unchanged counter = %v, want only the first", got)
	}
}

// a filter whose objects never loaded reports the same thing on every poll, so
// it must not turn every poll into an error.
func TestCollectObservationsToleratesUnloadedDropCounter(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)

	f.lostErr = egressfilter.ErrNotLoaded
	if _, err := e.CollectObservations(context.Background()); err != nil {
		t.Errorf("CollectObservations returned %v, want nil", err)
	}
}
