package egressmgr

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

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

// ipKey builds an allow-verdict observation key; ipKeyDeny a deny-verdict one.
func ipKey(t *testing.T, s string) egressfilter.IPEventKey {
	t.Helper()
	return egressfilter.IPEventKey{Addr: addr(t, s), Verdict: runtimeevent.VerdictAllow}
}

func ipKeyDeny(t *testing.T, s string) egressfilter.IPEventKey {
	t.Helper()
	return egressfilter.IPEventKey{Addr: addr(t, s), Verdict: runtimeevent.VerdictDeny}
}

// A monitor policy must observe, not enforce. Nothing may be
// programmed into the allow/deny maps and the default-deny bit must stay clear,
// otherwise the BPF program can return -EPERM for a policy the user believes is
// only watching.
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
	wantObserveOwners(t, e, "pod-1", "rp-1")
	wantAttachedRps(t, e, "pod-1", "rp-1")
	// the only flag write is the observe bit
	want := []flagToggle{{idx: egressfilter.OBSERVE, val: true}}
	if diff := cmp.Diff(want, f.toggles, cmp.AllowUnexported(flagToggle{})); diff != "" {
		t.Errorf("flag toggles (-want +got):\n%s", diff)
	}

	// and a pod that does not match is not observed either
	other := addPod(t, e, "pod-2", apiLabels, "/cg/pod-2")
	wantObserveFlag(t, other, false)
	wantObserveOwners(t, e, "pod-2")
}

func TestObserveFlagIsRefcountedAcrossPolicies(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", compiler.ModeMonitor, webLabels, nil, nil), events.EventTypeCreate)
	wantObserveOwners(t, e, "pod-1", "rp-1", "rp-2")

	// the first one leaving must NOT stop observation
	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)
	wantObserveFlag(t, f, true)
	wantObserveOwners(t, e, "pod-1", "rp-2")

	// the selector of the last one moving away stops it
	mustRpEvent(t, e, rp("rp-2", compiler.ModeMonitor, apiLabels, nil, nil), events.EventTypeUpdate)
	wantObserveFlag(t, f, false)
	wantObserveOwners(t, e, "pod-1")
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

		wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair([]string{"1.1.1.1"}, []string{"*"})})
		wantPairs(t, "AddIps", f.adds, nil)
		wantLiveIps(t, f, []string{}, []string{})
		wantDefaultDeny(t, f, false)
		wantDefaultDenyOwners(t, e, "pod-1")
		wantObserveFlag(t, f, true)
		wantObserveOwners(t, e, "pod-1", "rp-1")
		assertSharedPointer(t, e, "rp-1", "pod-1")
	})

	t.Run("monitor to enforce programs and stops observing", func(t *testing.T) {
		e, _, _ := newTestManager()
		f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
		mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)
		f.reset()

		mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeUpdate)

		wantPairs(t, "AddIps", f.adds, []ipPair{pair([]string{"1.1.1.1"}, []string{"*"})})
		wantLiveIps(t, f, []string{"1.1.1.1"}, []string{})
		wantDefaultDeny(t, f, true)
		wantDefaultDenyOwners(t, e, "pod-1", "rp-1")
		wantObserveFlag(t, f, false)
		wantObserveOwners(t, e, "pod-1")
	})
}

func TestCollectObservationsEmitsNetEventsWithPodUidAndCounts(t *testing.T) {
	e, _, _ := newTestManager()
	f1 := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	f2 := addPod(t, e, "pod-2", webLabels, "/cg/pod-2")
	// pod-3 matches nothing: it is not observed and must not be polled
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
			// the deny counter for the same destination is its own event,
			// sorted after the allow one, with the kernel verdict carried over
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

func TestCollectObservationsWithoutObservePoliciesIsEmpty(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	f.ipEvents = map[egressfilter.IPEventKey]uint32{ipKey(t, "10.0.0.1"): 5}

	got, err := e.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("events emitted for a pod with no observe-mode policy: %v", got)
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

// A target the runtime cannot honor must reach the policy's status, not just a
// log line nobody sees.
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
			wantReason: ReasonAllTargetsSupported,
		},
		{
			name:       "no targets at all",
			wantStatus: metav1.ConditionTrue,
			wantReason: ReasonNoTargets,
		},
		{
			name:       "ipv6 target",
			deny:       []string{"2001:db8::1"},
			wantStatus: metav1.ConditionFalse,
			wantReason: ReasonUnsupportedTargets,
			wantIn:     []string{"2001:db8::1", egressfilter.ReasonIPv6},
		},
		{
			name:       "cidr wider than /24",
			deny:       []string{"10.0.0.0/8"},
			wantStatus: metav1.ConditionFalse,
			wantReason: ReasonUnsupportedTargets,
			wantIn:     []string{"10.0.0.0/8", egressfilter.ReasonCIDRTooWide},
		},
		{
			name:       "hostname",
			allow:      []string{"api.example.com"},
			wantStatus: metav1.ConditionFalse,
			wantReason: ReasonUnsupportedTargets,
			wantIn:     []string{"api.example.com", egressfilter.ReasonNotAnIP},
		},
		{
			name:       "mixed: the supported half is still programmed",
			allow:      []string{"1.1.1.1", "api.example.com"},
			wantStatus: metav1.ConditionFalse,
			wantReason: ReasonUnsupportedTargets,
			wantIn:     []string{"api.example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _, status := newTestManager()
			f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")

			mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, tc.allow, tc.deny), events.EventTypeCreate)

			cond, ok := status.latest("rp-1", ConditionTargetsValid)
			if !ok {
				t.Fatalf("no %s condition was recorded for rp-1 (all: %v)", ConditionTargetsValid, status.all("rp-1"))
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

// a nil status recorder must not stop the manager: the daemon may run without
// one, and the log line is still emitted.
func TestNilStatusRecorderIsTolerated(t *testing.T) {
	ff := &fakeFactory{}
	e := NewEgressManager(logr.Discard(), nil, withFilterFactory(ff.new), WithClock(func() time.Time { return testTime }))
	addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"2001:db8::1"}, nil), events.EventTypeCreate)
	if _, ok := e.rps["rp-1"]; !ok {
		t.Error("policy was not tracked when the status recorder is nil")
	}
}
