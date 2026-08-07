package compiler

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
	apiservercel "k8s.io/apiserver/pkg/cel"
)

func monitorFilterPolicy(mode v1alpha1.RuntimePolicyMode, exprs ...v1alpha1.MonitorFilterExpression) v1alpha1.RuntimePolicy {
	return v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Mode:          &mode,
			MonitorFilter: &v1alpha1.MonitorFilter{Expressions: exprs},
		},
	}
}

func condition(name, expr string) v1alpha1.MonitorFilterExpression {
	return v1alpha1.MonitorFilterExpression{Name: name, Expression: expr}
}

// compileFilter compiles a monitor-mode policy carrying exprs and fails the
// test if the compiler rejects it.
func compileFilter(t *testing.T, exprs ...v1alpha1.MonitorFilterExpression) *MonitorFilter {
	t.Helper()
	c := newTestCompiler(t)
	compiled, err := c.Compile(monitorFilterPolicy(v1alpha1.PolicyModeMonitor, exprs...))
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if compiled.monitorFilter == nil {
		t.Fatal("Compile() produced a nil monitorFilter")
	}
	return compiled.monitorFilter
}

func openEvent(path string) runtimeevent.Event {
	return runtimeevent.Event{Kind: runtimeevent.KindOpen, Open: &runtimeevent.OpenFacts{Path: path}}
}

func TestCompileMonitorFilter_Rejections(t *testing.T) {
	tests := []struct {
		name     string
		mode     v1alpha1.RuntimePolicyMode
		exprs    []v1alpha1.MonitorFilterExpression
		wantPath string
		wantErr  string
	}{{
		name:     "string result",
		mode:     v1alpha1.PolicyModeMonitor,
		exprs:    []v1alpha1.MonitorFilterExpression{condition("a", `event.kind`)},
		wantPath: "spec.monitorFilter.expressions[0].expression",
		wantErr:  "must evaluate to bool, got string",
	}, {
		name:     "list result",
		mode:     v1alpha1.PolicyModeMonitor,
		exprs:    []v1alpha1.MonitorFilterExpression{condition("a", `["x"]`)},
		wantPath: "spec.monitorFilter.expressions[0].expression",
		wantErr:  "must evaluate to bool, got list(string)",
	}, {
		name:     "dyn result",
		mode:     v1alpha1.PolicyModeMonitor,
		exprs:    []v1alpha1.MonitorFilterExpression{condition("a", `dyn(true)`)},
		wantPath: "spec.monitorFilter.expressions[0].expression",
		wantErr:  "must evaluate to bool, got dyn",
	}, {
		name: "second expression is the one rejected",
		mode: v1alpha1.PolicyModeMonitor,
		exprs: []v1alpha1.MonitorFilterExpression{
			condition("a", `has(event.open)`),
			condition("b", `event.pid`),
		},
		wantPath: "spec.monitorFilter.expressions[1].expression",
		wantErr:  `expression "b": must evaluate to bool, got int`,
	}, {
		name: "duplicate expression name",
		mode: v1alpha1.PolicyModeMonitor,
		exprs: []v1alpha1.MonitorFilterExpression{
			condition("dup", `has(event.open)`),
			condition("dup", `has(event.exec)`),
		},
		wantPath: "spec.monitorFilter.expressions[1].name",
		wantErr:  "Duplicate value",
	}, {
		name:     "unknown field",
		mode:     v1alpha1.PolicyModeMonitor,
		exprs:    []v1alpha1.MonitorFilterExpression{condition("a", `event.open.paht == "x"`)},
		wantPath: "spec.monitorFilter.expressions[0].expression",
		wantErr:  "undefined field 'paht'",
	}, {
		name:     "unknown top-level field",
		mode:     v1alpha1.PolicyModeMonitor,
		exprs:    []v1alpha1.MonitorFilterExpression{condition("a", `event.cgroupID == 1`)},
		wantPath: "spec.monitorFilter.expressions[0].expression",
		wantErr:  "undefined field 'cgroupID'",
	}, {
		name:     "enforce mode",
		mode:     v1alpha1.PolicyModeEnforce,
		exprs:    []v1alpha1.MonitorFilterExpression{condition("a", `has(event.open)`)},
		wantPath: "spec.monitorFilter",
		wantErr:  "an enforce-mode policy reports only operations the kernel actually denied",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCompiler(t)
			_, err := c.Compile(monitorFilterPolicy(tt.mode, tt.exprs...))
			if err == nil {
				t.Fatal("Compile() error = nil, want a rejection")
			}
			if !strings.Contains(err.Error(), tt.wantPath) {
				t.Errorf("Compile() error = %q, want it to name %q", err, tt.wantPath)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Compile() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestFilterEnvOmitsIOLibraries pins the filter env against the I/O libraries
// newEnv registers: those run once per evaluation interval, where this env runs
// once per observed event.
func TestFilterEnvOmitsIOLibraries(t *testing.T) {
	for _, expr := range []string{
		`http.get("https://example.com")`,
		`resource.get("v1", "pods", "default", "x")`,
		`json.unmarshal("{}")`,
	} {
		t.Run(expr, func(t *testing.T) {
			c := newTestCompiler(t)
			if _, issues := c.env.Compile(expr); issues.Err() != nil {
				t.Fatalf("policy env rejected %q (%v), so this proves nothing about the filter env", expr, issues.Err())
			}
			if _, issues := c.filterEnv.Compile(expr); issues.Err() == nil {
				t.Fatalf("filter env accepted %q, want the I/O libraries absent", expr)
			}
		})
	}
}

func TestMonitorFilterDecide(t *testing.T) {
	execEvent := runtimeevent.Event{
		Kind: runtimeevent.KindExec,
		Exec: &runtimeevent.ExecFacts{Filename: "/usr/bin/npx", Argv: []string{"npx", "mcp-server-git"}},
	}

	tests := []struct {
		name     string
		exprs    []v1alpha1.MonitorFilterExpression
		ev       runtimeevent.Event
		want     FilterDecision
		wantErrs bool
	}{{
		name:  "single true reports",
		exprs: []v1alpha1.MonitorFilterExpression{condition("a", `has(event.open)`)},
		ev:    openEvent("/etc/passwd"),
		want:  FilterDecision{Report: true},
	}, {
		name: "anded, both true",
		exprs: []v1alpha1.MonitorFilterExpression{
			condition("a", `has(event.open)`),
			condition("b", `event.open.path.contains("/.mcp-auth/")`),
		},
		ev:   openEvent("/root/.mcp-auth/abc_debug.log"),
		want: FilterDecision{Report: true},
	}, {
		name: "anded, second false",
		exprs: []v1alpha1.MonitorFilterExpression{
			condition("a", `has(event.open)`),
			condition("b", `event.open.path.contains("/.mcp-auth/")`),
		},
		ev:   openEvent("/etc/passwd"),
		want: FilterDecision{Report: false, Expression: "b"},
	}, {
		name: "guard short-circuits the dereference of an absent arm",
		exprs: []v1alpha1.MonitorFilterExpression{
			condition("exec-only", `has(event.exec)`),
			condition("argv", `event.exec.argv.exists(a, a == "x")`),
		},
		ev:   openEvent("/etc/passwd"),
		want: FilterDecision{Report: false, Expression: "exec-only"},
	}, {
		name: "argv match on an exec event",
		exprs: []v1alpha1.MonitorFilterExpression{
			condition("exec-only", `has(event.exec)`),
			condition("argv", `event.exec.argv.exists(a, a.startsWith("mcp-server-"))`),
		},
		ev:   execEvent,
		want: FilterDecision{Report: true},
	}, {
		name:     "dereferencing an absent arm fails open",
		exprs:    []v1alpha1.MonitorFilterExpression{condition("unguarded", `event.exec.filename == "x"`)},
		ev:       openEvent("/etc/passwd"),
		want:     FilterDecision{Report: true, Expression: "unguarded"},
		wantErrs: true,
	}, {
		name: "an eval error after a passing expression still fails open",
		exprs: []v1alpha1.MonitorFilterExpression{
			condition("first", `has(event.open)`),
			condition("boom", `event.pod.labels["absent"] == "x"`),
		},
		ev:       openEvent("/etc/passwd"),
		want:     FilterDecision{Report: true, Expression: "boom"},
		wantErrs: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compileFilter(t, tt.exprs...).Decide(tt.ev)
			if (got.Err != nil) != tt.wantErrs {
				t.Fatalf("Decide() err = %v, want an error: %v", got.Err, tt.wantErrs)
			}
			got.Err = nil
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Decide() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMonitorFilterDecideErrImpliesReport pins the fail-open invariant: a filter
// that cannot answer must widen what an operator sees, never narrow it.
func TestMonitorFilterDecideErrImpliesReport(t *testing.T) {
	got := compileFilter(t, condition("boom", `event.exec.filename == "x"`)).Decide(openEvent("/etc/passwd"))
	if got.Err == nil {
		t.Fatal("Decide() err = nil, want the absent-arm dereference to error")
	}
	if !got.Report {
		t.Error("Decide() Report = false with a non-nil Err, want the finding reported anyway")
	}
	if got.Expression != "boom" {
		t.Errorf("Decide() Expression = %q, want %q", got.Expression, "boom")
	}
}

func TestMonitorFilterNilReportsEverything(t *testing.T) {
	var f *MonitorFilter
	want := FilterDecision{Report: true}
	if diff := cmp.Diff(want, f.Decide(openEvent("/etc/passwd"))); diff != "" {
		t.Errorf("Decide() mismatch (-want +got):\n%s", diff)
	}
}

func TestCompileMonitorFilterAbsentLeavesNilFilter(t *testing.T) {
	c := newTestCompiler(t)
	mode := v1alpha1.PolicyModeMonitor
	compiled, err := c.Compile(v1alpha1.RuntimePolicy{Spec: v1alpha1.RuntimePolicySpec{Mode: &mode}})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if compiled.monitorFilter != nil {
		t.Errorf("Compile() monitorFilter = %v, want nil when the spec sets none", compiled.monitorFilter)
	}
}

// fullEvent populates every field the CEL schema declares, so the coverage and
// drift tests both exercise a complete event.
func fullEvent() runtimeevent.Event {
	return runtimeevent.Event{
		Kind:         runtimeevent.KindNet,
		Time:         time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC),
		CgroupID:     4242,
		PID:          17,
		Comm:         "curl",
		Count:        3,
		KernelDenied: true,
		WouldDeny:    true,
		Net:          &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.0.0.5"), Domain: "api.example.com"},
		DNS:          &runtimeevent.DNSFacts{QName: "api.example.com"},
		Exec:         &runtimeevent.ExecFacts{Filename: "/usr/bin/curl", Argv: []string{"curl", "-s"}},
		Open:         &runtimeevent.OpenFacts{Path: "/etc/hosts"},
		Protocol:     &runtimeevent.ProtocolFacts{Protocol: "tls", ALPN: "h2"},
		Pod: runtimeevent.PodIdentity{
			UID:            "uid-1",
			Namespace:      "team-a",
			Name:           "agent-0",
			Labels:         map[string]string{"app": "ai"},
			Container:      "agent",
			ContainerID:    "containerd://abc",
			OwnerKind:      "Deployment",
			OwnerName:      "agent",
			NodeName:       "node-1",
			ServiceAccount: "agent-sa",
		},
	}
}

func TestMonitorFilterFieldCoverage(t *testing.T) {
	for _, expr := range []string{
		`event.kind == "net"`,
		`event.time == timestamp("2024-03-01T12:00:00Z")`,
		`event.comm == "curl"`,
		`event.pid == 17`,
		`event.count == 3`,
		`event.kernelDenied`,
		`event.wouldDeny`,
		`event.pod.namespace == "team-a"`,
		`event.pod.name == "agent-0"`,
		`event.pod.uid == "uid-1"`,
		`event.pod.container == "agent"`,
		`event.pod.containerID == "containerd://abc"`,
		`event.pod.ownerKind == "Deployment"`,
		`event.pod.ownerName == "agent"`,
		`event.pod.nodeName == "node-1"`,
		`event.pod.serviceAccount == "agent-sa"`,
		`event.pod.labels["app"] == "ai"`,
		`event.open.path == "/etc/hosts"`,
		`event.exec.filename == "/usr/bin/curl"`,
		`event.exec.argv == ["curl", "-s"]`,
		`event.net.destIP == "10.0.0.5"`,
		`event.net.domain == "api.example.com"`,
		`event.dns.qname == "api.example.com"`,
		`event.protocol.protocol == "tls"`,
		`event.protocol.alpn == "h2"`,
		`has(event.open) && has(event.exec) && has(event.net) && has(event.dns) && has(event.protocol)`,
	} {
		t.Run(expr, func(t *testing.T) {
			got := compileFilter(t, condition("c", expr)).Decide(fullEvent())
			if got.Err != nil {
				t.Fatalf("Decide() err = %v", got.Err)
			}
			if !got.Report {
				t.Errorf("Decide() Report = false, want the expression to be true over a fully populated event")
			}
		})
	}
}

func TestMonitorFilterUnionArmPresence(t *testing.T) {
	tests := []struct {
		name string
		ev   runtimeevent.Event
		arm  string
	}{
		{name: "open", ev: openEvent("/etc/hosts"), arm: "open"},
		{name: "exec", ev: runtimeevent.Event{Kind: runtimeevent.KindExec, Exec: &runtimeevent.ExecFacts{}}, arm: "exec"},
		{name: "net", ev: runtimeevent.Event{Kind: runtimeevent.KindNet, Net: &runtimeevent.NetFacts{}}, arm: "net"},
		{name: "dns", ev: runtimeevent.Event{Kind: runtimeevent.KindDNS, DNS: &runtimeevent.DNSFacts{}}, arm: "dns"},
		{name: "protocol", ev: runtimeevent.Event{Kind: runtimeevent.KindProtocol, Protocol: &runtimeevent.ProtocolFacts{}}, arm: "protocol"},
	}
	arms := []string{"open", "exec", "net", "dns", "protocol"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, arm := range arms {
				got := compileFilter(t, condition("c", fmt.Sprintf("has(event.%s)", arm))).Decide(tt.ev)
				if got.Err != nil {
					t.Fatalf("Decide() err = %v", got.Err)
				}
				if want := arm == tt.arm; got.Report != want {
					t.Errorf("has(event.%s) = %v, want %v", arm, got.Report, want)
				}
			}
		})
	}
}

// TestUnsetDestIPIsEmptyString pins the conversion of a zero netip.Addr: its
// String() is "invalid IP", which an expression would compare and match like an
// address.
func TestUnsetDestIPIsEmptyString(t *testing.T) {
	ev := runtimeevent.Event{Kind: runtimeevent.KindNet, Net: &runtimeevent.NetFacts{}}
	got := compileFilter(t, condition("c", `event.net.destIP == ""`)).Decide(ev)
	if got.Err != nil {
		t.Fatalf("Decide() err = %v", got.Err)
	}
	if !got.Report {
		t.Error(`event.net.destIP != "" for an unset address`)
	}
}

// TestFilterSchemaMatchesEventWire fails when a field is added to
// runtimeevent.Event without a matching CEL declaration, which would leave it
// silently unreachable from a monitorFilter expression.
func TestFilterSchemaMatchesEventWire(t *testing.T) {
	// cgroupID is a node-internal identifier a policy author cannot act on.
	excluded := map[string]struct{}{"cgroupID": {}}

	b, err := json.Marshal(fullEvent())
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	var walkWire func(prefix string, m map[string]any) []string
	walkWire = func(prefix string, m map[string]any) []string {
		var out []string
		for k, v := range m {
			if _, skip := excluded[k]; skip {
				continue
			}
			path := prefix + k
			out = append(out, path)
			if nested, ok := v.(map[string]any); ok && k != "labels" {
				out = append(out, walkWire(path+".", nested)...)
			}
		}
		return out
	}

	var walkDecl func(prefix string, t *apiservercel.DeclType) []string
	walkDecl = func(prefix string, dt *apiservercel.DeclType) []string {
		var out []string
		for name, f := range dt.Fields {
			path := prefix + name
			out = append(out, path)
			if f.Type.IsObject() {
				out = append(out, walkDecl(path+".", f.Type)...)
			}
		}
		return out
	}

	want := walkWire("", wire)
	got := walkDecl("", eventDeclType)
	sort.Strings(want)
	sort.Strings(got)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("declared CEL schema differs from the Event wire shape (-wire +declared):\n%s", diff)
	}
}
