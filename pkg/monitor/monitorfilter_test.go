package monitor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// noServices resolves nothing: these policies name no cluster Service.
type noServices struct{}

func (noServices) ResolveService(string, string) ([]string, bool) { return nil, false }

func (noServices) ResolveEndpoint(string, string, string) ([]string, bool) { return nil, false }

func cond(name, expression string) v1alpha1.MonitorFilterExpression {
	return v1alpha1.MonitorFilterExpression{Name: name, Expression: expression}
}

// compileFilter builds a filter through the real compiler, so these tests run
// the CEL programs a daemon would run rather than a stand-in for them.
func compileFilter(t *testing.T, exprs ...v1alpha1.MonitorFilterExpression) *compiler.MonitorFilter {
	t.Helper()
	c, err := compiler.NewCompiler(dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()), noServices{})
	if err != nil {
		t.Fatalf("NewCompiler: %v", err)
	}
	mode := v1alpha1.PolicyModeMonitor
	compiled, err := c.Compile(v1alpha1.RuntimePolicy{Spec: v1alpha1.RuntimePolicySpec{
		Mode:          &mode,
		MonitorFilter: &v1alpha1.MonitorFilter{Expressions: exprs},
	}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	res, err := compiled.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.MonitorFilter == nil {
		t.Fatal("Evaluate produced no monitor filter")
	}
	return res.MonitorFilter
}

// denyEverything is the discovery shape a filter exists to narrow.
func denyEverything() *compiler.AllowDenyPair {
	return pair(nil, []string{compiler.StarTarget})
}

func TestHandleEvent_FilterExpressionsAreANDed(t *testing.T) {
	tests := []struct {
		name        string
		ev          runtimeevent.Event
		wantFinding bool
	}{
		{name: "both expressions true", ev: openEvent("/root/.mcp-auth/abc_debug.log"), wantFinding: true},
		{name: "second expression false", ev: openEvent("/etc/passwd")},
		{name: "first expression false", ev: execEvent("/usr/bin/curl")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sink, _ := testMonitor(t)
			rp := monitorPolicy(t, "uid-p", "p", nil, denyEverything(), denyEverything())
			rp.MonitorFilter = compileFilter(t,
				cond("open-only", `has(event.open)`),
				cond("mcp-credential-cache", `event.open.path.contains("/.mcp-auth/")`))
			if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}

			m.HandleEvent(tc.ev)

			if got := len(sink.all()); (got == 1) != tc.wantFinding {
				t.Errorf("findings = %d, want a finding: %v", got, tc.wantFinding)
			}
		})
	}
}

func TestHandleEvent_FilteredFindingReachesNoSink(t *testing.T) {
	m, sink, mtx := testMonitor(t)
	rp := monitorPolicy(t, "uid-p", "p", nil, denyEverything(), nil)
	rp.MonitorFilter = compileFilter(t, cond("mcp-only", `event.open.path.contains("mcp")`))
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}

	m.HandleEvent(openEvent("/etc/passwd"))

	if got := sink.reports(); got != 0 {
		t.Errorf("Report calls = %d, want 0", got)
	}
	if got := testutil.CollectAndCount(mtx.MonitorFilterEvalErrors); got != 0 {
		t.Errorf("monitor_filter_eval_errors_total series = %d, want 0", got)
	}
}

// A filter that cannot answer must widen what an operator sees, and the failure
// must be visible rather than mistaken for a narrowing that worked.
func TestHandleEvent_FilterEvalErrorReportsTheFindingAndCountsTheExpression(t *testing.T) {
	m, sink, mtx := testMonitor(t)
	rp := monitorPolicy(t, "uid-p", "p", nil, denyEverything(), nil)
	rp.MonitorFilter = compileFilter(t, cond("boom", `event.pod.labels["absent"] == "x"`))
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}

	m.HandleEvent(openEvent("/etc/passwd"))

	if got := len(sink.all()); got != 1 {
		t.Errorf("findings = %d, want 1 (a broken filter reports anyway)", got)
	}
	if got := testutil.ToFloat64(mtx.MonitorFilterEvalErrors.WithLabelValues("p", "boom")); got != 1 {
		t.Errorf("monitor_filter_eval_errors_total{policy=p,expression=boom} = %v, want 1", got)
	}
}

// A daemon with no reporter still evaluates events, and a filter it cannot
// evaluate is still a broken filter an operator has to be told about.
func TestHandleEvent_FilterEvalErrorIsCountedWithoutASink(t *testing.T) {
	mtx := metrics.New(prometheus.NewRegistry())
	m := New(testr.New(t), nil, mtx)
	rp := monitorPolicy(t, "uid-p", "p", nil, denyEverything(), nil)
	rp.MonitorFilter = compileFilter(t, cond("boom", `event.pod.labels["absent"] == "x"`))
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}

	m.HandleEvent(openEvent("/etc/passwd"))

	if got := testutil.ToFloat64(mtx.MonitorFilterEvalErrors.WithLabelValues("p", "boom")); got != 1 {
		t.Errorf("monitor_filter_eval_errors_total{policy=p,expression=boom} = %v, want 1", got)
	}
}

// A dns finding is special-cased before the mode switch, so WouldDeny is never
// set on it: a filter guarding on event.wouldDeny drops every dns finding, and
// has(event.dns) is the guard that works.
func TestHandleEvent_DNSFindingIsFilterable(t *testing.T) {
	tests := []struct {
		name        string
		expression  v1alpha1.MonitorFilterExpression
		wantFinding bool
	}{
		{name: "has(event.dns) passes", expression: cond("dns-only", `has(event.dns)`), wantFinding: true},
		{name: "event.wouldDeny drops it", expression: cond("would-deny", `event.wouldDeny`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sink, mtx := testMonitor(t)
			rp := dnsPolicy(t, "uid-dns", "discover", pair(nil, []string{compiler.StarTarget}))
			rp.MonitorFilter = compileFilter(t, tc.expression)
			if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}

			m.HandleEvent(dnsEvent("api.openai.com"))

			if got := len(sink.all()); (got == 1) != tc.wantFinding {
				t.Errorf("findings = %d, want a finding: %v", got, tc.wantFinding)
			}
			if got := testutil.CollectAndCount(mtx.MonitorFilterEvalErrors); got != 0 {
				t.Errorf("monitor_filter_eval_errors_total series = %d, want 0", got)
			}
		})
	}
}

// The guard is what lets a later expression dereference event.exec: on an open
// event the filter must stop at the guard, not fail open with an eval error.
func TestHandleEvent_FilterGuardShortCircuitsWithoutEvalError(t *testing.T) {
	m, sink, mtx := testMonitor(t)
	rp := monitorPolicy(t, "uid-p", "p", nil, denyEverything(), denyEverything())
	rp.MonitorFilter = compileFilter(t,
		cond("exec-events-only", `has(event.exec)`),
		cond("mcp-server-package", `event.exec.argv.exists(a, a.startsWith("mcp-server-"))`))
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}

	m.HandleEvent(openEvent("/etc/passwd"))

	if got := len(sink.all()); got != 0 {
		t.Errorf("findings = %d, want 0: %+v", got, sink.all())
	}
	if got := testutil.CollectAndCount(mtx.MonitorFilterEvalErrors); got != 0 {
		t.Errorf("monitor_filter_eval_errors_total series = %d, want 0", got)
	}
}

func TestRuntimePolicyEvent_UpdateReplacesTheFilter(t *testing.T) {
	m, sink, _ := testMonitor(t)
	rp := monitorPolicy(t, "uid-p", "p", nil, denyEverything(), nil)
	rp.MonitorFilter = compileFilter(t, cond("hosts-only", `event.open.path == "/etc/hosts"`))
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	updated := monitorPolicy(t, "uid-p", "p", nil, denyEverything(), nil)
	updated.MonitorFilter = compileFilter(t, cond("shadow-only", `event.open.path == "/etc/shadow"`))
	if err := m.RuntimePolicyEvent(updated, events.EventTypeUpdate); err != nil {
		t.Fatalf("update: %v", err)
	}

	m.HandleEvent(openEvent("/etc/hosts"))
	m.HandleEvent(openEvent("/etc/shadow"))

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1 (only the updated filter applies): %+v", len(got), got)
	}
	if !strings.Contains(got[0].Message, "/etc/shadow") {
		t.Errorf("finding message = %q, want the path the updated filter selects", got[0].Message)
	}
}

// Admission and the compiler both refuse a monitorFilter on an enforce-mode
// policy, so an enforced finding has no filter to consult and none is applied.
func TestHandleEvent_EnforcePolicyWithoutFilterReportsKernelDenies(t *testing.T) {
	m, sink, _ := testMonitor(t)
	rp := monitorPolicy(t, "uid-e", "e", nil, denyEverything(), nil)
	rp.Mode = compiler.ModeEnforce
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}

	ev := openEvent("/etc/shadow")
	ev.KernelDenied = true
	m.HandleEvent(ev)

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	if !got[0].Enforced {
		t.Error("kernel-deny finding does not carry Enforced=true")
	}
}

// An expression name is user-authored text that the reporter's fixed key set
// must never carry, on the reporting path and on the fail-open path alike.
func TestHandleEvent_FilterExpressionNameNeverReachesTheFinding(t *testing.T) {
	const name = "leaky-expression-name"
	tests := []struct {
		name       string
		expression v1alpha1.MonitorFilterExpression
	}{
		{name: "the expression passes", expression: cond(name, `has(event.open)`)},
		{name: "the expression errors", expression: cond(name, `event.pod.labels["absent"] == "x"`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sink, _ := testMonitor(t)
			rp := monitorPolicy(t, "uid-p", "p", nil, denyEverything(), nil)
			rp.MonitorFilter = compileFilter(t, tc.expression)
			if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}

			m.HandleEvent(openEvent("/etc/passwd"))

			got := sink.all()
			if len(got) != 1 {
				t.Fatalf("findings = %d, want 1: %+v", len(got), got)
			}
			encoded, err := json.Marshal(got[0])
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if strings.Contains(string(encoded), name) {
				t.Errorf("finding carries the expression name: %s", encoded)
			}
		})
	}
}
