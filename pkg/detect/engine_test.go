package detect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/detect/ai"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/reporter"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// --- fakes -----------------------------------------------------------------

type recordingFindings struct{ findings []reporter.Finding }

func (r *recordingFindings) Report(f reporter.Finding) { r.findings = append(r.findings, f) }

type recordingInventory struct{ events []runtimeevent.Event }

func (r *recordingInventory) Record(ev runtimeevent.Event) { r.events = append(r.events, ev) }

type recordingStatus struct {
	conditions map[string][]metav1.Condition
}

func (r *recordingStatus) RecordCondition(policyUID string, c metav1.Condition) {
	if r.conditions == nil {
		r.conditions = map[string][]metav1.Condition{}
	}
	r.conditions[policyUID] = append(r.conditions[policyUID], c)
}

type harness struct {
	engine    *Engine
	findings  *recordingFindings
	inventory *recordingInventory
	status    *recordingStatus
}

// failOnErrorSink turns any logged error into a test failure. HandleEvent
// converts panics into logged errors (the Sink contract forbids panicking
// outward), so a discarding logger would hide a nil dereference as "no finding
// was produced" — which is exactly how the ev.Net nil bug in messageFor got
// past a green test run once.
type failOnErrorSink struct {
	t *testing.T
	logr.LogSink
}

func (s failOnErrorSink) Enabled(int) bool { return true }

func (s failOnErrorSink) Error(err error, msg string, kv ...any) {
	s.t.Errorf("engine logged an error (a swallowed panic looks like this): %v: %s %v", err, msg, kv)
}

func (s failOnErrorSink) Info(int, string, ...any) {}

func (s failOnErrorSink) Init(logr.RuntimeInfo) {}

func (s failOnErrorSink) WithValues(...any) logr.LogSink { return s }

func (s failOnErrorSink) WithName(string) logr.LogSink { return s }

func strictLogger(t *testing.T) logr.Logger {
	t.Helper()
	return logr.New(failOnErrorSink{t: t})
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		findings:  &recordingFindings{},
		inventory: &recordingInventory{},
		status:    &recordingStatus{},
	}
	h.engine = NewEngine(Config{
		Findings:  h.findings,
		Inventory: h.inventory,
		Status:    h.status,
		Catalog:   ai.DefaultCatalog(),
		Log:       strictLogger(t),
	})
	return h
}

func agentLabels() map[string]string { return map[string]string{"app": "agent"} }

func selectorFor(t *testing.T, m map[string]string) labels.Selector {
	t.Helper()
	sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: m})
	if err != nil {
		t.Fatalf("building selector: %v", err)
	}
	return sel
}

// policy builds an EvaluationResult carrying one AI rule.
func policy(t *testing.T, uid, name, mode string, rule *compiler.AIRule) *compiler.EvaluationResult {
	t.Helper()
	return &compiler.EvaluationResult{
		UID:      uid,
		Name:     name,
		Mode:     mode,
		Selector: selectorFor(t, agentLabels()),
		AI:       []*compiler.AIRule{rule},
	}
}

// llmEvent is a classified hosted-provider TLS flow from a labeled pod.
func llmEvent() runtimeevent.Event {
	return runtimeevent.Event{
		Kind: runtimeevent.KindTLS,
		Time: time.Unix(1700000000, 0).UTC(),
		TLS:  &runtimeevent.TLSFacts{SNI: "api.openai.com"},
		Net: &runtimeevent.NetFacts{
			DestIP:   netip.MustParseAddr("104.18.7.192"),
			DestPort: 443,
		},
		Pod: runtimeevent.PodIdentity{
			UID: "pod-uid-1", Namespace: "default", Name: "agent-1",
			Labels: agentLabels(),
		},
		AI: &runtimeevent.AIFacts{
			Class:      runtimeevent.AIClassLLM,
			Provider:   "openai",
			Transport:  "https",
			Confidence: 90,
			Evidence:   []string{"sni:api.openai.com"},
		},
	}
}

// --- mode routing ----------------------------------------------------------

func TestModeRouting(t *testing.T) {
	tests := []struct {
		name          string
		mode          string
		wantFindings  int
		wantInventory int
		wantCondition bool
	}{
		{name: "discover records inventory only", mode: compiler.ModeDiscover, wantInventory: 1},
		{name: "monitor emits a finding", mode: compiler.ModeMonitor, wantFindings: 1},
		{
			name: "enforce is downgraded to monitor and says so",
			mode: compiler.ModeEnforce, wantFindings: 1, wantCondition: true,
		},
		{name: "omitted mode does nothing", mode: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			rule := &compiler.AIRule{Severity: reporter.SeverityHigh}
			if err := h.engine.RuntimePolicyEvent(policy(t, "uid-1", "p", tt.mode, rule), events.EventTypeCreate); err != nil {
				t.Fatalf("RuntimePolicyEvent: %v", err)
			}

			h.engine.HandleEvent(llmEvent())

			if got := len(h.findings.findings); got != tt.wantFindings {
				t.Errorf("findings = %d, want %d", got, tt.wantFindings)
			}
			if got := len(h.inventory.events); got != tt.wantInventory {
				t.Errorf("inventory records = %d, want %d", got, tt.wantInventory)
			}
			_, hasCond := h.status.conditions["uid-1"]
			if hasCond != tt.wantCondition {
				t.Errorf("AIEnforcementImplemented condition present = %v, want %v", hasCond, tt.wantCondition)
			}
		})
	}
}

// TestEnforceDowngradeConditionIsReportedOncePerPolicy keeps the status writer
// from being hammered once per event on a busy pod.
func TestEnforceDowngradeConditionIsReportedOncePerPolicy(t *testing.T) {
	h := newHarness(t)
	rule := &compiler.AIRule{Severity: reporter.SeverityHigh}
	if err := h.engine.RuntimePolicyEvent(policy(t, "uid-1", "p", compiler.ModeEnforce, rule), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	for range 5 {
		h.engine.HandleEvent(llmEvent())
	}

	if got := len(h.status.conditions["uid-1"]); got != 1 {
		t.Errorf("conditions recorded = %d, want 1", got)
	}
	if got := len(h.findings.findings); got != 5 {
		t.Errorf("findings = %d, want 5 (every event still reports)", got)
	}
	cond := h.status.conditions["uid-1"][0]
	if cond.Type != ConditionAIEnforcement || cond.Status != metav1.ConditionFalse {
		t.Errorf("condition = %s/%s, want %s/False", cond.Type, cond.Status, ConditionAIEnforcement)
	}
}

// --- gating ----------------------------------------------------------------

func TestClassAndConfidenceGating(t *testing.T) {
	tests := []struct {
		name       string
		classes    []string
		minConf    int32
		confidence int
		class      runtimeevent.AIClass
		wantFiring bool
	}{
		{name: "no class filter fires", confidence: 90, class: runtimeevent.AIClassLLM, wantFiring: true},
		{name: "matching class fires", classes: []string{"llm"}, confidence: 90, class: runtimeevent.AIClassLLM, wantFiring: true},
		{name: "class filter is case-insensitive", classes: []string{"LLM"}, confidence: 90, class: runtimeevent.AIClassLLM, wantFiring: true},
		{name: "non-matching class is skipped", classes: []string{"mcp"}, confidence: 90, class: runtimeevent.AIClassLLM},
		{name: "confidence at the floor fires", minConf: 90, confidence: 90, class: runtimeevent.AIClassLLM, wantFiring: true},
		{name: "confidence below the floor is skipped", minConf: 91, confidence: 90, class: runtimeevent.AIClassLLM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			rule := &compiler.AIRule{Classes: tt.classes, MinConfidence: tt.minConf, Severity: reporter.SeverityMedium}
			if err := h.engine.RuntimePolicyEvent(policy(t, "uid-1", "p", compiler.ModeMonitor, rule), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}

			ev := llmEvent()
			ev.AI.Class = tt.class
			ev.AI.Confidence = tt.confidence
			h.engine.HandleEvent(ev)

			fired := len(h.findings.findings) == 1
			if fired != tt.wantFiring {
				t.Errorf("rule fired = %v, want %v", fired, tt.wantFiring)
			}
		})
	}
}

func TestSelectorGatesOnPodLabels(t *testing.T) {
	h := newHarness(t)
	rule := &compiler.AIRule{Severity: reporter.SeverityMedium}
	if err := h.engine.RuntimePolicyEvent(policy(t, "uid-1", "p", compiler.ModeMonitor, rule), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	ev := llmEvent()
	ev.Pod.Labels = map[string]string{"app": "not-the-agent"}
	h.engine.HandleEvent(ev)

	if got := len(h.findings.findings); got != 0 {
		t.Errorf("findings = %d, want 0 for a pod the selector does not match", got)
	}
}

// TestAllowDenySemantics pins that the engine mirrors the kernel programs:
// default-deny consults the allow list, otherwise only an explicit deny fires.
func TestAllowDenySemantics(t *testing.T) {
	tests := []struct {
		name       string
		allow      []string
		deny       []string
		wantFiring bool
	}{
		{name: "no lists at all is a pure detector", wantFiring: true},
		{name: "explicit deny by hostname fires", deny: []string{"api.openai.com"}, wantFiring: true},
		{name: "explicit deny by provider fires", deny: []string{"provider:openai"}, wantFiring: true},
		{name: "deny that does not match is quiet", deny: []string{"api.anthropic.com"}},
		{
			name:  "default deny with the destination allowed is quiet",
			deny:  []string{StarTarget},
			allow: []string{"provider:openai"},
		},
		{
			name:       "default deny with the destination not allowed fires",
			deny:       []string{StarTarget},
			allow:      []string{"provider:anthropic"},
			wantFiring: true,
		},
		{
			// The proposal's central example: an approved-provider list alone
			// means anything else is reportable.
			name:       "allow list alone reports a destination not on it",
			allow:      []string{"provider:anthropic"},
			wantFiring: true,
		},
		{
			name:  "allow list alone is quiet for a destination on it",
			allow: []string{"provider:openai"},
		},
		{
			name:       "explicit deny wins over a matching allow entry",
			allow:      []string{"provider:openai"},
			deny:       []string{"api.openai.com"},
			wantFiring: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			rule := &compiler.AIRule{Allow: tt.allow, Deny: tt.deny, Severity: reporter.SeverityHigh}
			if err := h.engine.RuntimePolicyEvent(policy(t, "uid-1", "p", compiler.ModeMonitor, rule), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}

			h.engine.HandleEvent(llmEvent())

			fired := len(h.findings.findings) == 1
			if fired != tt.wantFiring {
				t.Errorf("rule fired = %v, want %v (allow=%v deny=%v)", fired, tt.wantFiring, tt.allow, tt.deny)
			}
		})
	}
}

// --- MatchTarget -----------------------------------------------------------

func TestMatchTarget(t *testing.T) {
	base := llmEvent()
	execEv := runtimeevent.Event{
		Kind: runtimeevent.KindExec,
		Exec: &runtimeevent.ExecFacts{
			Filename: "/usr/bin/npx",
			Argv:     []string{"npx", "@modelcontextprotocol/server-filesystem", "/data"},
		},
		AI: &runtimeevent.AIFacts{Class: runtimeevent.AIClassMCP, Transport: "stdio"},
	}

	tests := []struct {
		name  string
		entry string
		ev    *runtimeevent.Event
		want  bool
	}{
		{name: "star matches anything", entry: "*", ev: &base, want: true},
		{name: "empty entry matches nothing", entry: "", ev: &base},
		{name: "provider match", entry: "provider:openai", ev: &base, want: true},
		{name: "provider match is case-insensitive", entry: "provider:OpenAI", ev: &base, want: true},
		{name: "provider mismatch", entry: "provider:anthropic", ev: &base},
		{name: "exact hostname via SNI", entry: "api.openai.com", ev: &base, want: true},
		{name: "hostname glob", entry: "*.openai.com", ev: &base, want: true},
		{name: "hostname glob mismatch", entry: "*.anthropic.com", ev: &base},
		{name: "ipv4 literal match", entry: "104.18.7.192", ev: &base, want: true},
		{name: "ipv4 literal mismatch", entry: "1.2.3.4", ev: &base},
		{name: "cidr containment", entry: "104.18.0.0/16", ev: &base, want: true},
		{name: "cidr non-containment", entry: "10.0.0.0/8", ev: &base},
		{name: "mcp-server package in argv", entry: "mcp-server:@modelcontextprotocol/server-filesystem", ev: &execEv, want: true},
		{name: "mcp-server package not present", entry: "mcp-server:@modelcontextprotocol/server-git", ev: &execEv},
		{name: "mcp-server against a non-exec event", entry: "mcp-server:whatever", ev: &base},
		{name: "nil event never matches", entry: "*", ev: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchTarget(tt.entry, tt.ev, ai.DefaultCatalog()); got != tt.want {
				t.Errorf("MatchTarget(%q) = %v, want %v", tt.entry, got, tt.want)
			}
		})
	}
}

// --- predicate -------------------------------------------------------------

// compiledRuleFor runs the real compiler over a policy carrying an ai behavior
// with the given match expression, so the predicate under test is the one an
// author would actually get.
func compiledRuleFor(t *testing.T, match string) *compiler.AIRule {
	t.Helper()

	c, err := compiler.NewCompiler(nil)
	if err != nil {
		t.Fatalf("NewCompiler: %v", err)
	}
	compiled, err := c.Compile(v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ai-match"},
		Spec: v1alpha1.RuntimePolicySpec{
			PodSelector: &metav1.LabelSelector{MatchLabels: agentLabels()},
			Mode:        modePtr(v1alpha1.PolicyModeMonitor),
			Behaviors: []v1alpha1.PolicyBehavior{{
				AI: &v1alpha1.AIBehavior{Match: match, Severity: reporter.SeverityMedium},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Compile(%q): %v", match, err)
	}
	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate(%q): %v", match, err)
	}
	if len(res.AI) != 1 {
		t.Fatalf("compiled AI rules = %d, want 1", len(res.AI))
	}
	return res.AI[0]
}

func modePtr(m v1alpha1.RuntimePolicyMode) *v1alpha1.RuntimePolicyMode { return &m }

func TestMatchPredicateGatesTheRule(t *testing.T) {
	tests := []struct {
		name       string
		expr       string
		wantFiring bool
	}{
		{name: "true predicate fires", expr: `event.ai.confidence >= 60`, wantFiring: true},
		{name: "false predicate is quiet", expr: `event.ai.confidence >= 99`},
		{name: "predicate over provider", expr: `!(event.ai.provider in ["anthropic","bedrock"])`, wantFiring: true},
		{name: "predicate over destination port", expr: `event.net.destPort == 443`, wantFiring: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			if err := h.engine.RuntimePolicyEvent(
				policy(t, "uid-1", "p", compiler.ModeMonitor, compiledRuleFor(t, tt.expr)),
				events.EventTypeCreate,
			); err != nil {
				t.Fatal(err)
			}

			h.engine.HandleEvent(llmEvent())

			fired := len(h.findings.findings) == 1
			if fired != tt.wantFiring {
				t.Errorf("rule fired = %v, want %v for %q", fired, tt.wantFiring, tt.expr)
			}
		})
	}
}

// --- finding contents ------------------------------------------------------

func TestFindingCarriesClassifierFactsAndGovernedBit(t *testing.T) {
	h := newHarness(t)
	rule := &compiler.AIRule{Severity: reporter.SeverityHigh}
	if err := h.engine.RuntimePolicyEvent(policy(t, "uid-1", "unsanctioned-llm", compiler.ModeMonitor, rule), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	ev := llmEvent()
	ungoverned := false
	ev.Net.Governed = &ungoverned
	ev.AI.EndpointKind = "chat.completions"
	ev.AI.Model = "gpt-4o"
	h.engine.HandleEvent(ev)

	if len(h.findings.findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(h.findings.findings))
	}
	f := h.findings.findings[0]

	if f.PolicyName != "unsanctioned-llm" || f.Behavior != "ai" || f.Result != reporter.ResultFail {
		t.Errorf("finding envelope = %+v", f)
	}
	if f.Severity != reporter.SeverityHigh {
		t.Errorf("severity = %q, want %q", f.Severity, reporter.SeverityHigh)
	}
	if f.AI == nil {
		t.Fatal("finding.AI = nil")
	}
	if f.AI.Provider != "openai" || f.AI.Class != "llm" || f.AI.Model != "gpt-4o" {
		t.Errorf("AI summary = %+v", f.AI)
	}
	if f.AI.Governed == nil || *f.AI.Governed {
		t.Errorf("AI.Governed = %v, want a pointer to false", f.AI.Governed)
	}
	if f.Net == nil || f.Net.DestHost != "api.openai.com" || f.Net.DestPort != 443 {
		t.Errorf("net summary = %+v", f.Net)
	}
	if f.Pod.UID != "pod-uid-1" || f.Pod.Namespace != "default" {
		t.Errorf("pod identity = %+v", f.Pod)
	}
}

// TestGovernedBitStaysUnknownWhenResolverIsOff pins that a nil governed bit is
// carried through as nil: reporting "ungoverned" without having resolved the
// proxy would be worse than reporting nothing.
func TestGovernedBitStaysUnknownWhenResolverIsOff(t *testing.T) {
	h := newHarness(t)
	if err := h.engine.RuntimePolicyEvent(
		policy(t, "uid-1", "p", compiler.ModeMonitor, &compiler.AIRule{Severity: reporter.SeverityLow}),
		events.EventTypeCreate,
	); err != nil {
		t.Fatal(err)
	}

	h.engine.HandleEvent(llmEvent()) // Net.Governed is nil

	if len(h.findings.findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(h.findings.findings))
	}
	if got := h.findings.findings[0].AI.Governed; got != nil {
		t.Errorf("AI.Governed = %v, want nil (unknown)", *got)
	}
}

// --- lifecycle and robustness ---------------------------------------------

func TestPolicyLifecycle(t *testing.T) {
	h := newHarness(t)
	rule := &compiler.AIRule{Severity: reporter.SeverityMedium}
	res := policy(t, "uid-1", "p", compiler.ModeMonitor, rule)

	if err := h.engine.RuntimePolicyEvent(res, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if h.engine.Len() != 1 {
		t.Fatalf("tracked = %d, want 1", h.engine.Len())
	}

	if err := h.engine.RuntimePolicyEvent(res, events.EventTypeDelete); err != nil {
		t.Fatal(err)
	}
	if h.engine.Len() != 0 {
		t.Errorf("tracked after delete = %d, want 0", h.engine.Len())
	}

	h.engine.HandleEvent(llmEvent())
	if got := len(h.findings.findings); got != 0 {
		t.Errorf("findings after delete = %d, want 0", got)
	}
}

func TestPolicyWithoutAIRulesIsNotTracked(t *testing.T) {
	h := newHarness(t)
	res := &compiler.EvaluationResult{
		UID: "uid-1", Name: "net-only", Mode: compiler.ModeMonitor,
		Selector: selectorFor(t, agentLabels()),
	}
	if err := h.engine.RuntimePolicyEvent(res, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if h.engine.Len() != 0 {
		t.Errorf("tracked = %d, want 0 for a policy with no ai behavior", h.engine.Len())
	}
}

// TestRuleSnapshotSurvivesInPlaceMutation is the #53 bug class: the managers
// mutate EvaluationResult in place on update, so the engine must not alias it.
func TestRuleSnapshotSurvivesInPlaceMutation(t *testing.T) {
	h := newHarness(t)
	rule := &compiler.AIRule{Deny: []string{"api.openai.com"}, Severity: reporter.SeverityHigh}
	res := policy(t, "uid-1", "p", compiler.ModeMonitor, rule)
	if err := h.engine.RuntimePolicyEvent(res, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	// Someone else mutates the result the manager still holds.
	rule.Deny[0] = "mutated"
	rule.Severity = "critical"

	h.engine.HandleEvent(llmEvent())

	if len(h.findings.findings) != 1 {
		t.Fatalf("findings = %d, want 1 (the snapshot should still deny openai)", len(h.findings.findings))
	}
	if got := h.findings.findings[0].Severity; got != reporter.SeverityHigh {
		t.Errorf("severity = %q, want the snapshotted %q", got, reporter.SeverityHigh)
	}
}

// TestStdioMCPEventWithNoNetworkFactsProducesAFinding is the regression test for
// a nil dereference on ev.Net. stdio MCP is the one class with no network
// traffic at all — that is exactly why kyverno-runtime is the only layer that
// can see it — so every path from a classified event to a finding must tolerate
// nil Net facts.
func TestStdioMCPEventWithNoNetworkFactsProducesAFinding(t *testing.T) {
	h := newHarness(t)
	rule := &compiler.AIRule{
		Classes:  []string{"mcp"},
		Deny:     []string{StarTarget},
		Allow:    []string{"mcp-server:@modelcontextprotocol/server-git"},
		Severity: reporter.SeverityCritical,
	}
	if err := h.engine.RuntimePolicyEvent(policy(t, "uid-1", "mcp-allowlist", compiler.ModeMonitor, rule), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	ev := runtimeevent.Event{
		Kind: runtimeevent.KindExec,
		Time: time.Unix(1700000000, 0).UTC(),
		Comm: "uvx",
		Exec: &runtimeevent.ExecFacts{
			Filename: "/usr/local/bin/uvx",
			Argv:     []string{"uvx", "mcp-server-sqlite", "--db", "/data/app.db"},
		},
		Pod: runtimeevent.PodIdentity{
			UID: "pod-uid-5", Namespace: "ai-workloads", Name: "mcp-client",
			Labels: agentLabels(),
		},
		AI: &runtimeevent.AIFacts{
			Class: runtimeevent.AIClassMCP, EndpointKind: "mcp.stdio",
			Transport: "stdio", Confidence: 85,
			Evidence: []string{"argv:mcp-server-sqlite"},
		},
	}
	h.engine.HandleEvent(ev)

	if len(h.findings.findings) != 1 {
		t.Fatalf("findings = %d, want 1 for a non-allowlisted stdio MCP server", len(h.findings.findings))
	}
	f := h.findings.findings[0]
	if f.Net != nil {
		t.Errorf("finding.Net = %+v, want nil for an event with no network facts", f.Net)
	}
	if f.Process == nil || f.Process.Comm != "uvx" {
		t.Errorf("finding.Process = %+v, want the exec summary", f.Process)
	}
	if f.Message == "" {
		t.Error("finding.Message is empty; it should still name the server")
	}
}

// TestAllowlistedStdioServerIsQuiet is the other half: the allowed package must
// not produce a finding, or a default-deny MCP policy would be useless.
func TestAllowlistedStdioServerIsQuiet(t *testing.T) {
	h := newHarness(t)
	rule := &compiler.AIRule{
		Classes:  []string{"mcp"},
		Deny:     []string{StarTarget},
		Allow:    []string{"mcp-server:@modelcontextprotocol/server-git"},
		Severity: reporter.SeverityCritical,
	}
	if err := h.engine.RuntimePolicyEvent(policy(t, "uid-1", "mcp-allowlist", compiler.ModeMonitor, rule), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	h.engine.HandleEvent(runtimeevent.Event{
		Kind: runtimeevent.KindExec,
		Exec: &runtimeevent.ExecFacts{
			Filename: "/usr/bin/npx",
			Argv:     []string{"npx", "-y", "@modelcontextprotocol/server-git"},
		},
		Pod: runtimeevent.PodIdentity{UID: "pod-uid-5", Namespace: "ai-workloads", Name: "mcp-client", Labels: agentLabels()},
		AI:  &runtimeevent.AIFacts{Class: runtimeevent.AIClassMCP, EndpointKind: "mcp.stdio", Confidence: 85},
	})

	if got := len(h.findings.findings); got != 0 {
		t.Errorf("findings = %d, want 0 for an allowlisted stdio server", got)
	}
}

func TestUnclassifiedEventsAreIgnored(t *testing.T) {
	h := newHarness(t)
	if err := h.engine.RuntimePolicyEvent(
		policy(t, "uid-1", "p", compiler.ModeMonitor, &compiler.AIRule{Severity: reporter.SeverityLow}),
		events.EventTypeCreate,
	); err != nil {
		t.Fatal(err)
	}

	ev := llmEvent()
	ev.AI = nil // classifier said "not AI"
	h.engine.HandleEvent(ev)

	if got := len(h.findings.findings); got != 0 {
		t.Errorf("findings = %d, want 0 for an unclassified event", got)
	}
}

func TestNilSinksAreTolerated(t *testing.T) {
	e := NewEngine(Config{Catalog: ai.DefaultCatalog(), Log: logr.Discard()})
	if err := e.RuntimePolicyEvent(
		policy(t, "uid-1", "p", compiler.ModeEnforce, &compiler.AIRule{Severity: reporter.SeverityLow}),
		events.EventTypeCreate,
	); err != nil {
		t.Fatal(err)
	}

	// Must not panic with no findings sink, no inventory and no status recorder.
	e.HandleEvent(llmEvent())
}

func TestNilEvaluationResultIsAnError(t *testing.T) {
	h := newHarness(t)
	if err := h.engine.RuntimePolicyEvent(nil, events.EventTypeCreate); err == nil {
		t.Error("RuntimePolicyEvent(nil) = nil, want an error")
	}
}


func TestNameIsStable(t *testing.T) {
	if got := newHarness(t).engine.Name(); got != StageName {
		t.Errorf("Name() = %q, want %q", got, StageName)
	}
}

// TestOnePolicyEmitsOneFindingPerEvent guards against a policy whose two rules
// both match reporting the same observation twice.
func TestOnePolicyEmitsOneFindingPerEvent(t *testing.T) {
	h := newHarness(t)
	res := policy(t, "uid-1", "p", compiler.ModeMonitor, &compiler.AIRule{Severity: reporter.SeverityLow})
	res.AI = append(res.AI, &compiler.AIRule{Severity: reporter.SeverityHigh})
	if err := h.engine.RuntimePolicyEvent(res, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	h.engine.HandleEvent(llmEvent())

	if got := len(h.findings.findings); got != 1 {
		t.Errorf("findings = %d, want 1 even though both rules match", got)
	}
}
