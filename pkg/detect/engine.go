// Package detect routes classified AI events against the `ai` behaviors of
// tracked RuntimePolicies.
//
// The split of responsibility is deliberate. pkg/detect/ai decides *what* a
// flow is (class, provider, endpoint kind, confidence, evidence) and knows
// nothing about policy. This package decides what to *do* about it: which
// policies care, whether the destination was allowed, and whether the result is
// an inventory entry, a finding, or nothing at all.
//
// Two constraints shape the code:
//
//   - HandleEvent is on the event hot path and must never panic outward
//     (runtimeevent.Sink contract), so every policy-supplied CEL predicate runs
//     behind a guard and a predicate failure is treated as "no match" rather
//     than as a match.
//   - AI enforcement is NOT implemented. The proposal's compelled-routing phase
//     is what would make an `ai` behavior blockable; until then an enforce-mode
//     AI behavior behaves exactly like monitor and says so on the policy status,
//     rather than silently implying that traffic is being blocked.
package detect

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/detect/ai"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/reporter"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// StageName identifies this sink in logs and metrics.
const StageName = "detect"

// Target entry prefixes recognized by MatchTarget.
const (
	// ProviderPrefix matches on the classifier's provider name rather than on a
	// hostname, so a policy survives a provider changing its endpoints.
	ProviderPrefix = "provider:"
	// MCPServerPrefix matches a stdio MCP server package in exec argv. There is
	// no hostname for a local server on pipes, which is exactly why this form
	// exists.
	MCPServerPrefix = "mcp-server:"
	// StarTarget is the default-deny sentinel, same meaning as in the other
	// behaviors.
	StarTarget = compiler.StarTarget
)

// ConditionAIEnforcement is set to False on any policy whose ai behavior asks
// for enforce mode. See the package comment.
const (
	ConditionAIEnforcement    = "AIEnforcementImplemented"
	ReasonAIEnforceDowngraded = "DowngradedToMonitor"
)

// FindingSink receives findings; satisfied by *reporter.Reporter.
type FindingSink interface{ Report(reporter.Finding) }

// InventorySink receives classified events for discover mode; satisfied by
// *inventory.Rollup.
type InventorySink interface{ Record(ev runtimeevent.Event) }

// Config carries the engine's collaborators. Every field is optional: a nil
// sink is skipped rather than dereferenced, so the daemon can wire the engine
// before every consumer exists.
type Config struct {
	Findings  FindingSink
	Inventory InventorySink
	Status    runtimeevent.PolicyStatusRecorder
	Catalog   *ai.Catalog
	Metrics   *metrics.Metrics
	Log       logr.Logger
}

// trackedPolicy is the snapshot of a policy's AI rules taken when it is
// tracked. Snapshotting matters: the managers mutate EvaluationResult in place
// on update (see #53), so holding the pointer would race with matching.
type trackedPolicy struct {
	uid      string
	name     string
	mode     string
	selector labels.Selector
	rules    []*compiler.AIRule
	// enforceReported ensures the downgrade condition is recorded once per
	// policy rather than once per event.
	enforceReported bool
}

// Engine implements events.RuntimePolicyEventHandler and runtimeevent.Sink.
type Engine struct {
	mu       sync.RWMutex
	policies map[string]*trackedPolicy

	findings  FindingSink
	inventory InventorySink
	status    runtimeevent.PolicyStatusRecorder
	catalog   *ai.Catalog
	metrics   *metrics.Metrics
	log       logr.Logger
}

var _ runtimeevent.Sink = (*Engine)(nil)

// NewEngine returns an engine with no tracked policies.
func NewEngine(cfg Config) *Engine {
	return &Engine{
		policies:  map[string]*trackedPolicy{},
		findings:  cfg.Findings,
		inventory: cfg.Inventory,
		status:    cfg.Status,
		catalog:   cfg.Catalog,
		metrics:   cfg.Metrics,
		log:       cfg.Log,
	}
}

// Name implements runtimeevent.Sink.
func (e *Engine) Name() string { return StageName }

// Len reports how many policies are tracked. For tests and debugging.
func (e *Engine) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.policies)
}

// RuntimePolicyEvent tracks policies that carry AI rules, in any mode. A policy
// that loses its AI rules, or is deleted, is untracked.
func (e *Engine) RuntimePolicyEvent(res *compiler.EvaluationResult, eventType string) error {
	if res == nil {
		return fmt.Errorf("detect: nil evaluation result")
	}

	if eventType == events.EventTypeDelete || len(res.AI) == 0 {
		e.mu.Lock()
		delete(e.policies, res.UID)
		e.mu.Unlock()
		return nil
	}

	tp := &trackedPolicy{
		uid:      res.UID,
		name:     res.Name,
		mode:     res.Mode,
		selector: selectorOf(res),
		rules:    snapshotRules(res.AI),
	}

	e.mu.Lock()
	// Preserve the once-per-policy condition flag across updates so a policy
	// being re-evaluated on its interval does not re-report the downgrade.
	if prev, ok := e.policies[res.UID]; ok && prev.mode == tp.mode {
		tp.enforceReported = prev.enforceReported
	}
	e.policies[res.UID] = tp
	e.mu.Unlock()
	return nil
}

// HandleEvent implements runtimeevent.Sink.
func (e *Engine) HandleEvent(ev runtimeevent.Event) {
	if err := utils.Guard("detect: handling event", func() error {
		e.handleEvent(ev)
		return nil
	}); err != nil {
		e.log.Error(err, "handling event failed", "kind", string(ev.Kind), "podUid", ev.Pod.UID)
	}
}

func (e *Engine) handleEvent(ev runtimeevent.Event) {
	if ev.AI == nil {
		// Not AI traffic, or the classifier stage did not run.
		return
	}

	for _, tp := range e.tracked() {
		if tp.selector == nil || !tp.selector.Matches(labels.Set(ev.Pod.Labels)) {
			continue
		}
		for _, rule := range tp.rules {
			if !e.ruleApplies(tp, rule, &ev) {
				continue
			}
			e.act(tp, rule, ev)
			// One finding per policy per event: a policy with two rules that
			// both match describes one violation, not two.
			break
		}
	}
}

// ruleApplies decides whether a rule fires for this event: class gate,
// confidence gate, destination verdict, then the optional CEL predicate.
func (e *Engine) ruleApplies(tp *trackedPolicy, rule *compiler.AIRule, ev *runtimeevent.Event) bool {
	if !classAllowed(rule.Classes, ev.AI.Class) {
		return false
	}
	if int32(ev.AI.Confidence) < rule.MinConfidence {
		return false
	}
	if !e.denied(rule, ev) {
		return false
	}
	if rule.Match == nil {
		return true
	}

	ok, err := rule.Match.Eval(context.Background(), ev)
	if err != nil {
		// Fail closed: an unevaluatable predicate must not manufacture a
		// finding. It is already counted and logged by the predicate itself.
		e.log.V(2).Info("ai match predicate failed", "policy", tp.name, "err", err.Error())
		return false
	}
	return ok
}

// denied decides whether this event is a violation of the rule.
//
// Deny semantics mirror the kernel programs, with one addition that the AI case
// needs: an allow list on its own means "these destinations are sanctioned", so
// anything else is reportable. That is what makes the proposal's central example
// — alert on any LLM egress not on the approved provider list — expressible
// without also writing a "*" deny entry.
//
//	explicit deny match (not "*")     -> violation
//	"*" in deny, or allow list alone   -> violation unless explicitly allowed
//	neither list                       -> pure detector: every covered event
func (e *Engine) denied(rule *compiler.AIRule, ev *runtimeevent.Event) bool {
	if len(rule.Deny) == 0 && len(rule.Allow) == 0 {
		return true
	}

	explicitDeny := make([]string, 0, len(rule.Deny))
	defaultDeny := false
	for _, entry := range rule.Deny {
		if strings.TrimSpace(entry) == StarTarget {
			defaultDeny = true
			continue
		}
		explicitDeny = append(explicitDeny, entry)
	}

	if e.anyMatches(explicitDeny, ev) {
		return true
	}
	if defaultDeny || len(rule.Allow) > 0 {
		return !e.anyMatches(rule.Allow, ev)
	}
	return false
}

func (e *Engine) anyMatches(entries []string, ev *runtimeevent.Event) bool {
	for _, entry := range entries {
		if MatchTarget(entry, ev, e.catalog) {
			return true
		}
	}
	return false
}

// act applies the mode routing described in the package comment.
func (e *Engine) act(tp *trackedPolicy, rule *compiler.AIRule, ev runtimeevent.Event) {
	switch tp.mode {
	case compiler.ModeDiscover:
		if e.inventory != nil {
			e.inventory.Record(ev)
		}
		return
	case compiler.ModeEnforce:
		// Downgraded to monitor, and the policy says so once.
		e.reportEnforceDowngrade(tp)
	case compiler.ModeMonitor:
	default:
		// Unknown/omitted mode: an AI behavior with no mode does nothing, the
		// same as the other behaviors.
		return
	}

	if e.findings == nil {
		return
	}
	e.findings.Report(findingFor(tp, rule, ev))
}

func (e *Engine) reportEnforceDowngrade(tp *trackedPolicy) {
	e.mu.Lock()
	already := tp.enforceReported
	tp.enforceReported = true
	e.mu.Unlock()
	if already || e.status == nil {
		return
	}
	e.status.RecordCondition(tp.uid, metav1.Condition{
		Type:    ConditionAIEnforcement,
		Status:  metav1.ConditionFalse,
		Reason:  ReasonAIEnforceDowngraded,
		Message: "ai behaviors cannot block yet; this policy is observing and reporting only",
	})
	e.log.V(0).Info("ai behavior in enforce mode is observing only",
		"policy", tp.name, "condition", ConditionAIEnforcement)
}

// findingFor builds the finding. Only classifier-derived scalars and evidence
// tokens are copied: reporter.Finding has nowhere to put a header map or a body,
// and that is the point.
func findingFor(tp *trackedPolicy, rule *compiler.AIRule, ev runtimeevent.Event) reporter.Finding {
	f := reporter.Finding{
		PolicyName: tp.name,
		PolicyUID:  tp.uid,
		Behavior:   "ai",
		Severity:   rule.Severity,
		Result:     reporter.ResultFail,
		Message:    messageFor(ev),
		Pod:        ev.Pod,
		Timestamp:  ev.Time,
		AI: &reporter.AISummary{
			Class:        string(ev.AI.Class),
			Provider:     ev.AI.Provider,
			EndpointKind: ev.AI.EndpointKind,
			Model:        ev.AI.Model,
			Transport:    ev.AI.Transport,
			Confidence:   ev.AI.Confidence,
			Evidence:     ev.AI.Evidence,
			Sanctioned:   boolPtr(ev.AI.Sanctioned),
		},
	}
	if ev.Net != nil {
		f.Net = &reporter.NetSummary{
			DestIP:   addrString(ev.Net.DestIP),
			DestPort: ev.Net.DestPort,
			DestHost: destHost(&ev),
		}
		f.AI.Governed = ev.Net.Governed
	}
	if ev.Comm != "" || ev.Exec != nil {
		f.Process = &reporter.ProcessSummary{Comm: ev.Comm, Argv: argvString(&ev)}
	}
	return f
}

func messageFor(ev runtimeevent.Event) string {
	// An exec event (stdio MCP) has no network facts at all, which is precisely
	// why that class exists: there is no flow to name.
	host := destHost(&ev)
	if host == "" && ev.Net != nil {
		host = addrString(ev.Net.DestIP)
	}
	if host == "" && ev.Exec != nil {
		host = ev.Exec.Filename
	}
	var b strings.Builder
	b.WriteString("Unsanctioned ")
	b.WriteString(strings.ToUpper(string(ev.AI.Class)))
	b.WriteString(" traffic")
	if host != "" {
		b.WriteString(": ")
		b.WriteString(host)
	}
	details := make([]string, 0, 2)
	if ev.AI.Provider != "" {
		details = append(details, ev.AI.Provider)
	}
	if ev.AI.EndpointKind != "" {
		details = append(details, ev.AI.EndpointKind)
	}
	if len(details) > 0 {
		b.WriteString(" (")
		b.WriteString(strings.Join(details, ", "))
		b.WriteString(")")
	}
	return b.String()
}

// MatchTarget reports whether a policy target entry matches an event. Pure and
// exported so the target language is testable in isolation from the engine.
func MatchTarget(entry string, ev *runtimeevent.Event, cat *ai.Catalog) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" || ev == nil {
		return false
	}
	if entry == StarTarget {
		return true
	}

	switch {
	case strings.HasPrefix(entry, ProviderPrefix):
		want := strings.ToLower(strings.TrimPrefix(entry, ProviderPrefix))
		return ev.AI != nil && strings.EqualFold(ev.AI.Provider, want)

	case strings.HasPrefix(entry, MCPServerPrefix):
		want := strings.TrimPrefix(entry, MCPServerPrefix)
		return matchesArgv(ev, want)
	}

	// IPv4 literal or CIDR.
	if addr, err := netip.ParseAddr(entry); err == nil {
		return ev.Net != nil && ev.Net.DestIP.IsValid() && ev.Net.DestIP == addr
	}
	if pfx, err := netip.ParsePrefix(entry); err == nil {
		return ev.Net != nil && ev.Net.DestIP.IsValid() && pfx.Contains(ev.Net.DestIP)
	}

	// Otherwise a hostname glob, tried against every host the event carries.
	for _, host := range hostsOf(ev, cat) {
		if host != "" && ai.MatchGlob(entry, host) {
			return true
		}
	}
	return false
}

func matchesArgv(ev *runtimeevent.Event, want string) bool {
	if ev.Exec == nil || want == "" {
		return false
	}
	for _, arg := range ev.Exec.Argv {
		if strings.Contains(arg, want) {
			return true
		}
	}
	return strings.Contains(ev.Exec.Filename, want)
}

// hostsOf returns the hostnames an event carries, normalized the same way the
// catalog normalizes its patterns so a glob compares like with like.
func hostsOf(ev *runtimeevent.Event, _ *ai.Catalog) []string {
	hosts := make([]string, 0, 3)
	if ev.DNS != nil {
		hosts = append(hosts, ai.NormalizeHost(ev.DNS.QName))
	}
	if ev.TLS != nil {
		hosts = append(hosts, ai.NormalizeHost(ev.TLS.SNI))
	}
	if ev.HTTP != nil {
		hosts = append(hosts, ai.NormalizeHost(ev.HTTP.Host()))
	}
	return hosts
}

func destHost(ev *runtimeevent.Event) string {
	for _, h := range hostsOf(ev, nil) {
		if h != "" {
			return h
		}
	}
	return ""
}

func classAllowed(classes []string, class runtimeevent.AIClass) bool {
	if len(classes) == 0 {
		return true
	}
	for _, c := range classes {
		if strings.EqualFold(c, string(class)) {
			return true
		}
	}
	return false
}

func (e *Engine) tracked() []*trackedPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*trackedPolicy, 0, len(e.policies))
	for _, tp := range e.policies {
		out = append(out, tp)
	}
	return out
}

// snapshotRules copies the rule slice and its target slices. The managers mutate
// EvaluationResult in place on update, so the engine must not alias it.
func snapshotRules(rules []*compiler.AIRule) []*compiler.AIRule {
	out := make([]*compiler.AIRule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		cp := *r
		cp.Classes = append([]string(nil), r.Classes...)
		cp.Allow = append([]string(nil), r.Allow...)
		cp.Deny = append([]string(nil), r.Deny...)
		out = append(out, &cp)
	}
	return out
}

func selectorOf(res *compiler.EvaluationResult) labels.Selector {
	if res.Selector == nil {
		// A policy with no selector matches no pod, matching the managers'
		// treatment rather than silently applying cluster-wide.
		return labels.Nothing()
	}
	return res.Selector
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func argvString(ev *runtimeevent.Event) string {
	if ev.Exec == nil {
		return ""
	}
	if len(ev.Exec.Argv) == 0 {
		return ev.Exec.Filename
	}
	return strings.Join(ev.Exec.Argv, " ")
}

func boolPtr(b bool) *bool { return &b }
