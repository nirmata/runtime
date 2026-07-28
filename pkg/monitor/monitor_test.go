package monitor

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/reporter"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr/testr"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// --- fakes -----------------------------------------------------------------

type fakeSink struct {
	mu       sync.Mutex
	findings []reporter.Finding
	panics   bool
}

func (f *fakeSink) Report(fi reporter.Finding) {
	if f.panics {
		panic("boom: reporting finding")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.findings = append(f.findings, fi)
}

func (f *fakeSink) all() []reporter.Finding {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]reporter.Finding(nil), f.findings...)
}

type violation struct{ PolicyUID, PodUID string }

type fakeStatus struct {
	mu         sync.Mutex
	violations []violation
	conditions int
	panics     bool
}

func (f *fakeStatus) RecordViolation(policyUID, podUID string) {
	if f.panics {
		panic("boom: recording violation")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.violations = append(f.violations, violation{policyUID, podUID})
}

func (f *fakeStatus) RecordCondition(policyUID string, cond metav1.Condition) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.conditions++
}

func (f *fakeStatus) all() []violation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]violation(nil), f.violations...)
}

// --- helpers ---------------------------------------------------------------

func testMonitor(t *testing.T) (*Monitor, *fakeSink, *fakeStatus, *metrics.Metrics) {
	t.Helper()
	sink := &fakeSink{}
	status := &fakeStatus{}
	m := metrics.New(prometheus.NewRegistry())
	return New(testr.New(t), sink, status, m), sink, status, m
}

func sel(t *testing.T, kv map[string]string) labels.Selector {
	t.Helper()
	s, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: kv})
	if err != nil {
		t.Fatalf("building selector: %v", err)
	}
	return s
}

func pair(allow, deny []string) *compiler.AllowDenyPair {
	return &compiler.AllowDenyPair{Allow: allow, Deny: deny}
}

// monitorPolicy returns a monitor-mode EvaluationResult selecting app=ai pods.
func monitorPolicy(t *testing.T, uid, name string, ips, open, exec *compiler.AllowDenyPair) *compiler.EvaluationResult {
	t.Helper()
	return &compiler.EvaluationResult{
		UID:      uid,
		Name:     name,
		IPs:      ips,
		Open:     open,
		Exec:     exec,
		Selector: sel(t, map[string]string{"app": "ai"}),
		Mode:     compiler.ModeMonitor,
	}
}

func netEvent(ip string, port uint16) runtimeevent.Event {
	return runtimeevent.Event{
		Kind:  runtimeevent.KindNet,
		Time:  time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC),
		Count: 1,
		Net:   &runtimeevent.NetFacts{DestIP: netip.MustParseAddr(ip), DestPort: port, Protocol: "tcp"},
		Pod:   testPod(),
	}
}

func openEvent(path string) runtimeevent.Event {
	return runtimeevent.Event{
		Kind: runtimeevent.KindOpen,
		Time: time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC),
		Comm: "cat",
		Open: &runtimeevent.OpenFacts{Path: path},
		Pod:  testPod(),
	}
}

func execEvent(filename string, argv ...string) runtimeevent.Event {
	return runtimeevent.Event{
		Kind: runtimeevent.KindExec,
		Time: time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC),
		Comm: "sh",
		Exec: &runtimeevent.ExecFacts{Filename: filename, Argv: argv},
		Pod:  testPod(),
	}
}

func testPod() runtimeevent.PodIdentity {
	return runtimeevent.PodIdentity{
		UID:       "pod-uid-1",
		Namespace: "team-a",
		Name:      "agent-0",
		Labels:    map[string]string{"app": "ai"},
	}
}

// --- behavior kind x match shape table -------------------------------------

func TestHandleEvent_ViolationDecisionTable(t *testing.T) {
	tests := []struct {
		name          string
		ips           *compiler.AllowDenyPair
		open          *compiler.AllowDenyPair
		exec          *compiler.AllowDenyPair
		ev            runtimeevent.Event
		wantViolation bool
		wantBehavior  string
		wantMessage   string
	}{
		// network
		{
			name:          "net explicit deny matches destination",
			ips:           pair(nil, []string{"10.0.0.5"}),
			ev:            netEvent("10.0.0.5", 443),
			wantViolation: true,
			wantBehavior:  BehaviorNetwork,
			wantMessage:   "monitor mode: egress to 10.0.0.5:443 would have been denied by policy p",
		},
		{
			name:          "net explicit deny cidr contains destination",
			ips:           pair(nil, []string{"10.0.0.0/24"}),
			ev:            netEvent("10.0.0.77", 80),
			wantViolation: true,
			wantBehavior:  BehaviorNetwork,
			wantMessage:   "monitor mode: egress to 10.0.0.77:80 would have been denied by policy p",
		},
		{
			name:          "net default deny with destination not allowed",
			ips:           pair([]string{"10.0.0.1"}, []string{compiler.StarTarget}),
			ev:            netEvent("93.184.216.34", 443),
			wantViolation: true,
			wantBehavior:  BehaviorNetwork,
			wantMessage:   "monitor mode: egress to 93.184.216.34:443 would have been denied by policy p (default deny)",
		},
		{
			name: "net default deny with destination allowed",
			ips:  pair([]string{"93.184.216.34"}, []string{compiler.StarTarget}),
			ev:   netEvent("93.184.216.34", 443),
		},
		{
			name: "net default deny with destination allowed by cidr",
			ips:  pair([]string{"93.184.216.0/24"}, []string{compiler.StarTarget}),
			ev:   netEvent("93.184.216.34", 443),
		},
		{
			name: "net no match: destination absent from deny list",
			ips:  pair(nil, []string{"10.0.0.5"}),
			ev:   netEvent("10.0.0.6", 443),
		},
		{
			name: "net event but policy only has open entries",
			open: pair(nil, []string{"/etc/shadow"}),
			ev:   netEvent("10.0.0.5", 443),
		},
		// open
		{
			name:          "open explicit deny matches path",
			open:          pair(nil, []string{"/etc/shadow"}),
			ev:            openEvent("/etc/shadow"),
			wantViolation: true,
			wantBehavior:  BehaviorOpen,
			wantMessage:   "monitor mode: open of /etc/shadow would have been denied by policy p",
		},
		{
			name:          "open default deny with path not allowed",
			open:          pair([]string{"/etc/hosts"}, []string{compiler.StarTarget}),
			ev:            openEvent("/etc/shadow"),
			wantViolation: true,
			wantBehavior:  BehaviorOpen,
			wantMessage:   "monitor mode: open of /etc/shadow would have been denied by policy p (default deny)",
		},
		{
			name: "open default deny with path allowed",
			open: pair([]string{"/etc/shadow"}, []string{compiler.StarTarget}),
			ev:   openEvent("/etc/shadow"),
		},
		{
			name: "open no match: path absent from deny list",
			open: pair(nil, []string{"/etc/shadow"}),
			ev:   openEvent("/etc/hosts"),
		},
		// exec
		{
			name:          "exec explicit deny matches filename",
			exec:          pair(nil, []string{"/usr/bin/curl"}),
			ev:            execEvent("/usr/bin/curl", "curl", "https://example.com"),
			wantViolation: true,
			wantBehavior:  BehaviorExec,
			wantMessage:   "monitor mode: exec of /usr/bin/curl would have been denied by policy p",
		},
		{
			name:          "exec default deny with filename not allowed",
			exec:          pair([]string{"/bin/sh"}, []string{compiler.StarTarget}),
			ev:            execEvent("/usr/bin/curl"),
			wantViolation: true,
			wantBehavior:  BehaviorExec,
			wantMessage:   "monitor mode: exec of /usr/bin/curl would have been denied by policy p (default deny)",
		},
		{
			name: "exec default deny with filename allowed",
			exec: pair([]string{"/usr/bin/curl"}, []string{compiler.StarTarget}),
			ev:   execEvent("/usr/bin/curl"),
		},
		{
			name: "exec no match: filename absent from deny list",
			exec: pair(nil, []string{"/usr/bin/curl"}),
			ev:   execEvent("/bin/ls"),
		},
		{
			name: "exec event but policy only has exec allow entries",
			exec: pair([]string{"/usr/bin/curl"}, nil),
			ev:   execEvent("/bin/ls"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sink, status, _ := testMonitor(t)
			if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-p", "p", tc.ips, tc.open, tc.exec), events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}

			m.HandleEvent(tc.ev)

			got := sink.all()
			if !tc.wantViolation {
				if len(got) != 0 {
					t.Fatalf("expected no findings, got %d: %+v", len(got), got)
				}
				if v := status.all(); len(v) != 0 {
					t.Fatalf("expected no violations, got %+v", v)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected exactly one finding, got %d: %+v", len(got), got)
			}
			if got[0].Behavior != tc.wantBehavior {
				t.Errorf("behavior = %q, want %q", got[0].Behavior, tc.wantBehavior)
			}
			if got[0].Message != tc.wantMessage {
				t.Errorf("message = %q, want %q", got[0].Message, tc.wantMessage)
			}
			if got[0].Result != reporter.ResultFail {
				t.Errorf("result = %q, want %q", got[0].Result, reporter.ResultFail)
			}
			want := []violation{{PolicyUID: "uid-p", PodUID: "pod-uid-1"}}
			if diff := cmp.Diff(want, status.all()); diff != "" {
				t.Errorf("violations (-want +got):\n%s", diff)
			}
		})
	}
}

// --- selector gating -------------------------------------------------------

func TestHandleEvent_SelectorGatesOnPodLabels(t *testing.T) {
	tests := []struct {
		name          string
		podLabels     map[string]string
		wantViolation bool
	}{
		{name: "labels match the selector", podLabels: map[string]string{"app": "ai"}, wantViolation: true},
		{name: "extra labels still match", podLabels: map[string]string{"app": "ai", "tier": "x"}, wantViolation: true},
		{name: "different value does not match", podLabels: map[string]string{"app": "web"}},
		{name: "missing label does not match", podLabels: map[string]string{"tier": "x"}},
		{name: "no labels at all", podLabels: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sink, status, _ := testMonitor(t)
			if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil), events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}
			ev := netEvent("10.0.0.5", 443)
			ev.Pod.Labels = tc.podLabels

			m.HandleEvent(ev)

			gotViolation := len(sink.all()) == 1 && len(status.all()) == 1
			if gotViolation != tc.wantViolation {
				t.Errorf("violation = %v, want %v (findings=%d violations=%d)",
					gotViolation, tc.wantViolation, len(sink.all()), len(status.all()))
			}
		})
	}
}

// The label map belongs to pkg/attribution's index and is shared with every
// other sink (HANDOFFS: A7 -> sinks). Monitor must treat it as read-only.
func TestHandleEvent_DoesNotMutatePodLabels(t *testing.T) {
	m, _, _, _ := testMonitor(t)
	if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-p", "p", pair(nil, []string{compiler.StarTarget}), nil, nil), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	shared := map[string]string{"app": "ai", "pod-template-hash": "abc"}
	want := map[string]string{"app": "ai", "pod-template-hash": "abc"}
	ev := netEvent("10.0.0.5", 443)
	ev.Pod.Labels = shared

	m.HandleEvent(ev)

	if diff := cmp.Diff(want, shared); diff != "" {
		t.Errorf("pod labels were mutated (-want +got):\n%s", diff)
	}
}

// --- finding contents ------------------------------------------------------

func TestHandleEvent_FindingContents(t *testing.T) {
	m, sink, _, _ := testMonitor(t)
	if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-net", "block-egress", pair(nil, []string{"10.0.0.5"}), nil, nil), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	ev := netEvent("10.0.0.5", 8443)
	ev.Count = 7

	m.HandleEvent(ev)

	want := []reporter.Finding{{
		PolicyName: "block-egress",
		PolicyUID:  "uid-net",
		Behavior:   BehaviorNetwork,
		Severity:   reporter.SeverityMedium,
		Result:     reporter.ResultFail,
		Message:    "monitor mode: egress to 10.0.0.5:8443 (7 occurrences) would have been denied by policy block-egress",
		Pod:        testPod(),
		Net:        &reporter.NetSummary{DestIP: "10.0.0.5", DestPort: 8443},
		Timestamp:  time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC),
	}}
	if diff := cmp.Diff(want, sink.all()); diff != "" {
		t.Errorf("findings (-want +got):\n%s", diff)
	}
}

func TestHandleEvent_ExecFindingCarriesProcessSummary(t *testing.T) {
	m, sink, _, _ := testMonitor(t)
	if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-exec", "no-curl", nil, nil, pair(nil, []string{"/usr/bin/curl"})), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}

	m.HandleEvent(execEvent("/usr/bin/curl", "curl", "-s", "https://example.com"))

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	want := &reporter.ProcessSummary{Comm: "sh", Argv: "curl -s https://example.com"}
	if diff := cmp.Diff(want, got[0].Process); diff != "" {
		t.Errorf("process summary (-want +got):\n%s", diff)
	}
	if got[0].Net != nil {
		t.Errorf("exec finding carries a net summary: %+v", got[0].Net)
	}
}

// --- once per (policy, pod) per event --------------------------------------

func TestRecordViolationOncePerPolicyPodPerEvent(t *testing.T) {
	m, sink, status, _ := testMonitor(t)
	// two policies, both selecting the pod and both violated by the same event
	a := monitorPolicy(t, "uid-a", "a", pair(nil, []string{"10.0.0.5"}), nil, nil)
	b := monitorPolicy(t, "uid-b", "b", pair([]string{"10.0.0.9"}, []string{compiler.StarTarget}), nil, nil)
	for _, rp := range []*compiler.EvaluationResult{a, b} {
		if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
			t.Fatalf("RuntimePolicyEvent: %v", err)
		}
	}

	m.HandleEvent(netEvent("10.0.0.5", 443))

	if got := len(sink.all()); got != 2 {
		t.Errorf("findings = %d, want 2 (one per policy)", got)
	}
	perPolicy := map[string]int{}
	for _, v := range status.all() {
		perPolicy[v.PolicyUID+"/"+v.PodUID]++
	}
	want := map[string]int{"uid-a/pod-uid-1": 1, "uid-b/pod-uid-1": 1}
	if diff := cmp.Diff(want, perPolicy); diff != "" {
		t.Errorf("violations per (policy,pod) (-want +got):\n%s", diff)
	}
}

func TestRecordViolationOncePerEvent_RepeatEventRecordsAgain(t *testing.T) {
	m, _, status, _ := testMonitor(t)
	if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}

	m.HandleEvent(netEvent("10.0.0.5", 443))
	m.HandleEvent(netEvent("10.0.0.5", 443))

	if got := len(status.all()); got != 2 {
		t.Errorf("violations = %d, want 2 (one per event)", got)
	}
}

func TestHandleEvent_SecondPodOfSamePolicyRecordsItsOwnViolation(t *testing.T) {
	m, _, status, _ := testMonitor(t)
	if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	first := netEvent("10.0.0.5", 443)
	second := netEvent("10.0.0.5", 443)
	second.Pod.UID = "pod-uid-2"

	m.HandleEvent(first)
	m.HandleEvent(second)

	want := []violation{{"uid-p", "pod-uid-1"}, {"uid-p", "pod-uid-2"}}
	if diff := cmp.Diff(want, status.all()); diff != "" {
		t.Errorf("violations (-want +got):\n%s", diff)
	}
}

// --- non-monitor policies are ignored entirely -----------------------------

func TestRuntimePolicyEvent_IgnoresNonMonitorPolicies(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		eventType string
	}{
		{name: "enforce mode", mode: compiler.ModeEnforce, eventType: events.EventTypeCreate},
		{name: "discover mode", mode: compiler.ModeDiscover, eventType: events.EventTypeCreate},
		{name: "empty mode", mode: "", eventType: events.EventTypeCreate},
		{name: "unknown mode", mode: "audit", eventType: events.EventTypeCreate},
		{name: "monitor mode but delete event", mode: compiler.ModeMonitor, eventType: events.EventTypeDelete},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sink, status, _ := testMonitor(t)
			rp := monitorPolicy(t, "uid-p", "p", pair(nil, []string{compiler.StarTarget}), nil, nil)
			rp.Mode = tc.mode
			if err := m.RuntimePolicyEvent(rp, tc.eventType); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}
			if m.Len() != 0 {
				t.Fatalf("tracked %d policies, want 0", m.Len())
			}

			m.HandleEvent(netEvent("10.0.0.5", 443))

			if len(sink.all()) != 0 || len(status.all()) != 0 {
				t.Errorf("non-monitor policy produced output: findings=%+v violations=%+v", sink.all(), status.all())
			}
		})
	}
}

func TestRuntimePolicyEvent_UntracksWhenPolicyLeavesMonitorMode(t *testing.T) {
	m, sink, _, _ := testMonitor(t)
	rp := monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil)
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	m.HandleEvent(netEvent("10.0.0.5", 443))
	if got := len(sink.all()); got != 1 {
		t.Fatalf("findings after create = %d, want 1", got)
	}

	// the same policy switched to enforce: the kernel blocks now, monitor must
	// stop deciding for it
	enforcing := monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil)
	enforcing.Mode = compiler.ModeEnforce
	if err := m.RuntimePolicyEvent(enforcing, events.EventTypeUpdate); err != nil {
		t.Fatalf("update: %v", err)
	}
	if m.Len() != 0 {
		t.Fatalf("tracked %d policies after leaving monitor mode, want 0", m.Len())
	}

	m.HandleEvent(netEvent("10.0.0.5", 443))
	if got := len(sink.all()); got != 1 {
		t.Errorf("findings after switching to enforce = %d, want 1", got)
	}
}

func TestRuntimePolicyEvent_UpdateReplacesValues(t *testing.T) {
	m, sink, _, _ := testMonitor(t)
	rp := monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil)
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	updated := monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.6"}), nil, nil)
	if err := m.RuntimePolicyEvent(updated, events.EventTypeUpdate); err != nil {
		t.Fatalf("update: %v", err)
	}
	if m.Len() != 1 {
		t.Fatalf("tracked %d policies, want 1", m.Len())
	}

	m.HandleEvent(netEvent("10.0.0.5", 443)) // old value: no longer denied
	m.HandleEvent(netEvent("10.0.0.6", 443)) // new value: denied

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	if got[0].Net.DestIP != "10.0.0.6" {
		t.Errorf("finding destIP = %q, want 10.0.0.6", got[0].Net.DestIP)
	}
}

// A tracked policy snapshots the pair values: egressmgr mutates the
// EvaluationResult it holds in place (#53), and monitor must not see that.
func TestRuntimePolicyEvent_SnapshotsBehaviorValues(t *testing.T) {
	m, sink, _, _ := testMonitor(t)
	rp := monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil)
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}

	// another consumer mutates the shared result in place
	rp.IPs.Deny = []string{"10.0.0.9"}
	rp.IPs.Allow = []string{"10.0.0.5"}
	rp.Name = "renamed-by-someone-else"

	m.HandleEvent(netEvent("10.0.0.5", 443))

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if got[0].PolicyName != "p" {
		t.Errorf("policy name = %q, want p", got[0].PolicyName)
	}
}

func TestRuntimePolicyEvent_IgnoresPoliciesThatCanNeverViolate(t *testing.T) {
	tests := []struct {
		name string
		mut  func(rp *compiler.EvaluationResult)
	}{
		{name: "no behavior entries", mut: func(rp *compiler.EvaluationResult) {
			rp.IPs, rp.Open, rp.Exec = &compiler.AllowDenyPair{}, nil, nil
		}},
		{name: "nil selector", mut: func(rp *compiler.EvaluationResult) { rp.Selector = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sink, status, _ := testMonitor(t)
			rp := monitorPolicy(t, "uid-p", "p", pair(nil, []string{compiler.StarTarget}), nil, nil)
			tc.mut(rp)
			if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}
			if m.Len() != 0 {
				t.Fatalf("tracked %d policies, want 0", m.Len())
			}
			m.HandleEvent(netEvent("10.0.0.5", 443))
			if len(sink.all()) != 0 || len(status.all()) != 0 {
				t.Errorf("unexpected output: findings=%+v violations=%+v", sink.all(), status.all())
			}
		})
	}
}

func TestRuntimePolicyEvent_NilResultIsAnError(t *testing.T) {
	m, _, _, _ := testMonitor(t)
	if err := m.RuntimePolicyEvent(nil, events.EventTypeCreate); err == nil {
		t.Error("expected an error for a nil evaluation result")
	}
}

func TestPodEventIsANoOp(t *testing.T) {
	m, sink, status, _ := testMonitor(t)
	if err := m.PodEvent(corev1.Pod{}, nil, events.EventTypeCreate); err != nil {
		t.Errorf("PodEvent: %v", err)
	}
	if len(sink.all()) != 0 || len(status.all()) != 0 || m.Len() != 0 {
		t.Error("PodEvent changed monitor state")
	}
}

// --- kinds monitor mode does not decide on --------------------------------

func TestHandleEvent_IgnoresUndecidableEvents(t *testing.T) {
	tests := []struct {
		name string
		ev   runtimeevent.Event
	}{
		{name: "dns kind", ev: runtimeevent.Event{Kind: runtimeevent.KindDNS, Pod: testPod(),
			DNS: &runtimeevent.DNSFacts{QName: "api.openai.com"}}},
		{name: "http kind", ev: runtimeevent.Event{Kind: runtimeevent.KindHTTP, Pod: testPod()}},
		{name: "net kind with nil facts", ev: runtimeevent.Event{Kind: runtimeevent.KindNet, Pod: testPod()}},
		{name: "net kind with zero destination", ev: runtimeevent.Event{Kind: runtimeevent.KindNet, Pod: testPod(),
			Net: &runtimeevent.NetFacts{}}},
		{name: "open kind with nil facts", ev: runtimeevent.Event{Kind: runtimeevent.KindOpen, Pod: testPod()}},
		{name: "open kind with empty path", ev: runtimeevent.Event{Kind: runtimeevent.KindOpen, Pod: testPod(),
			Open: &runtimeevent.OpenFacts{}}},
		{name: "exec kind with nil facts", ev: runtimeevent.Event{Kind: runtimeevent.KindExec, Pod: testPod()}},
		{name: "empty kind", ev: runtimeevent.Event{Pod: testPod()}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sink, status, _ := testMonitor(t)
			rp := monitorPolicy(t, "uid-p", "p",
				pair(nil, []string{compiler.StarTarget}),
				pair(nil, []string{compiler.StarTarget}),
				pair(nil, []string{compiler.StarTarget}))
			if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}

			m.HandleEvent(tc.ev)

			if len(sink.all()) != 0 || len(status.all()) != 0 {
				t.Errorf("undecidable event produced output: findings=%+v violations=%+v", sink.all(), status.all())
			}
		})
	}
}

// --- degraded wiring -------------------------------------------------------

func TestHandleEvent_ToleratesNilSinkStatusAndMetrics(t *testing.T) {
	m := New(testr.New(t), nil, nil, nil)
	if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	// must not panic and must not need any collaborator
	m.HandleEvent(netEvent("10.0.0.5", 443))
	ev := netEvent("10.0.0.5", 443)
	ev.Pod.Namespace = ""
	m.HandleEvent(ev)
}

func TestHandleEvent_NeverPanicsOutward(t *testing.T) {
	tests := []struct {
		name         string
		sinkPanics   bool
		statusPanics bool
	}{
		{name: "panicking finding sink", sinkPanics: true},
		{name: "panicking status recorder", statusPanics: true},
		{name: "both panic", sinkPanics: true, statusPanics: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink := &fakeSink{panics: tc.sinkPanics}
			status := &fakeStatus{panics: tc.statusPanics}
			m := New(testr.New(t), sink, status, metrics.New(prometheus.NewRegistry()))
			if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil), events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}

			m.HandleEvent(netEvent("10.0.0.5", 443)) // must return normally
		})
	}
}

// A panicking collaborator for one policy must not hide the violation of the
// next policy: each call is guarded individually.
func TestHandleEvent_PanickingStatusDoesNotSkipRemainingPolicies(t *testing.T) {
	sink := &fakeSink{}
	m := New(testr.New(t), sink, &fakeStatus{panics: true}, nil)
	for _, uid := range []string{"uid-a", "uid-b"} {
		if err := m.RuntimePolicyEvent(monitorPolicy(t, uid, uid, pair(nil, []string{"10.0.0.5"}), nil, nil), events.EventTypeCreate); err != nil {
			t.Fatalf("RuntimePolicyEvent: %v", err)
		}
	}

	m.HandleEvent(netEvent("10.0.0.5", 443))

	if got := len(sink.all()); got != 2 {
		t.Errorf("findings = %d, want 2 despite the panicking status recorder", got)
	}
}

// Findings without a DNS-1123 namespace are dropped by the reporter
// (HANDOFFS: A8), so monitor counts them instead of emitting silently. The
// violation itself still happened and is still recorded.
func TestHandleEvent_DropsFindingWithoutUsableNamespaceButRecordsViolation(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
	}{
		{name: "empty namespace", namespace: ""},
		{name: "invalid namespace", namespace: "Not A Namespace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sink, status, mtx := testMonitor(t)
			if err := m.RuntimePolicyEvent(monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil), events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}
			ev := netEvent("10.0.0.5", 443)
			ev.Pod.Namespace = tc.namespace

			m.HandleEvent(ev)

			if got := len(sink.all()); got != 0 {
				t.Errorf("findings = %d, want 0", got)
			}
			if got := len(status.all()); got != 1 {
				t.Errorf("violations = %d, want 1", got)
			}
			if got := testutil.ToFloat64(mtx.EventsDropped.WithLabelValues(sinkName, "unattributed")); got != 1 {
				t.Errorf("events_dropped_total{source=monitor,reason=unattributed} = %v, want 1", got)
			}
		})
	}
}

func TestNameIsMonitor(t *testing.T) {
	m, _, _, _ := testMonitor(t)
	if got := m.Name(); got != "monitor" {
		t.Errorf("Name() = %q, want monitor", got)
	}
}

// --- concurrency -----------------------------------------------------------

// The collector fans events out while the informer updates policies; -race
// must stay clean across that overlap.
func TestHandleEvent_ConcurrentWithPolicyUpdates(t *testing.T) {
	m, _, _, _ := testMonitor(t)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			rp := monitorPolicy(t, "uid-p", "p", pair(nil, []string{"10.0.0.5"}), nil, nil)
			_ = m.RuntimePolicyEvent(rp, events.EventTypeUpdate)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			m.HandleEvent(netEvent("10.0.0.5", 443))
		}
	}()
	wg.Wait()
}
