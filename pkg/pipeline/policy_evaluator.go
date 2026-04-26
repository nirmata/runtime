package pipeline

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	baselinepkg "github.com/nirmata/kyverno-runtime/pkg/baseline"
	"github.com/nirmata/kyverno-runtime/pkg/observability"
	"github.com/nirmata/kyverno-runtime/pkg/policy"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// PolicyEvaluator wraps policy.Evaluator to implement Evaluator.
type PolicyEvaluator struct {
	evaluator        *policy.Evaluator
	client           client.Client
	baselineEnabled  bool
	signatureEnabled bool
	anomalyDetector  *policy.AnomalyDetector
	signatureEngine  *policy.SignatureEngine
}

type PolicyEvaluatorOptions struct {
	Client            client.Client
	BaselineEnabled   bool
	SignatureEnabled  bool
	MinConfidence     float64
	BehaviorNamespace string
}

// NewPolicyEvaluator creates a new PolicyEvaluator.
func NewPolicyEvaluator(evaluator *policy.Evaluator) *PolicyEvaluator {
	return NewPolicyEvaluatorWithOptions(evaluator, PolicyEvaluatorOptions{})
}

// NewPolicyEvaluatorWithOptions creates a policy evaluator with optional dual-engine support.
func NewPolicyEvaluatorWithOptions(evaluator *policy.Evaluator, opts PolicyEvaluatorOptions) *PolicyEvaluator {
	pe := &PolicyEvaluator{
		evaluator:        evaluator,
		client:           opts.Client,
		baselineEnabled:  opts.BaselineEnabled,
		signatureEnabled: opts.SignatureEnabled,
	}
	if pe.baselineEnabled {
		pe.anomalyDetector = policy.NewAnomalyDetector(opts.MinConfidence)
	}
	if pe.signatureEnabled {
		pe.signatureEngine = policy.NewSignatureEngine()
	}
	return pe
}

// Evaluate evaluates a policy against runtime events.
func (e *PolicyEvaluator) Evaluate(p *v1alpha1.RuntimePolicy, events []runtimeevents.Event) EvaluationResult {
	started := time.Now()
	defer func() {
		observability.ObserveEvaluatorLatency("cel", time.Since(started).Seconds())
	}()

	result := e.evaluator.EvaluateRuntime(p, events)
	return EvaluationResult{
		Findings: result.Findings,
		Actions:  result.Actions,
	}
}

// EnsureCompiled pre-compiles CEL expressions for a policy.
func (e *PolicyEvaluator) EnsureCompiled(p *v1alpha1.RuntimePolicy) error {
	if e == nil || e.evaluator == nil {
		return nil
	}
	return e.evaluator.EnsureCompiled(p)
}

// EvaluateForPod evaluates CEL policy and (optionally) signature/anomaly engines
// using pod context.
func (e *PolicyEvaluator) EvaluateForPod(p *v1alpha1.RuntimePolicy, pod *corev1.Pod, events []runtimeevents.Event) EvaluationResult {
	started := time.Now()
	defer func() {
		observability.ObserveEvaluatorLatency("combined", time.Since(started).Seconds())
	}()

	base := e.Evaluate(p, events)
	if (!e.baselineEnabled && !e.signatureEnabled) || pod == nil {
		return base
	}

	ctx := context.Background()
	var rb *v1alpha1.RuntimeBehavior
	if e.baselineEnabled {
		rb = e.findRuntimeBehaviorForPod(ctx, pod)
	}

	for _, ev := range events {
		if !policyHandlesEventType(p, ev.Type) {
			continue
		}
		if e.signatureEnabled {
			base.Findings = append(base.Findings, e.signatureFindings(ev)...)
		}
		if e.baselineEnabled {
			if rb != nil {
				base.Findings = append(base.Findings, e.anomalyFindings(ctx, rb, ev)...)
				e.updateRuntimeBehaviorObservation(ctx, rb, ev)
			}
		}
	}

	return base
}

func policyHandlesEventType(p *v1alpha1.RuntimePolicy, eventType string) bool {
	if p == nil {
		return false
	}
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	if eventType == "" {
		return false
	}
	if len(p.Spec.Validations) == 0 {
		return false
	}
	for _, v := range p.Spec.Validations {
		if strings.EqualFold(strings.TrimSpace(v.Event), eventType) {
			return true
		}
	}
	return false
}

func (e *PolicyEvaluator) signatureFindings(ev runtimeevents.Event) []v1alpha1.RuleFinding {
	if e.signatureEngine == nil {
		return nil
	}
	execVal := firstNonEmpty(ev.Field("process.name"), ev.Field("comm"), ev.Field("proc.comm"), ev.Field("args"), ev.Field("filename"))
	openVal := firstNonEmpty(ev.Field("fname"), ev.Field("file.path"), ev.Field("path"), ev.Field("fullPath"), ev.Field("filename"))
	networkVal := firstNonEmpty(ev.Field("destination.ip"), ev.Field("dst.addr"), ev.Field("destination"), ev.Field("remote.addr"))
	dnsVal := firstNonEmpty(ev.Field("query"), ev.Field("dns.query"), ev.Field("domain"))

	matches := e.signatureEngine.EvaluateSignatures(context.Background(), execVal, openVal, networkVal, dnsVal, nil)
	findings := make([]v1alpha1.RuleFinding, 0, len(matches))
	for _, m := range matches {
		findings = append(findings, v1alpha1.RuleFinding{
			RuleName:  m.RuleID,
			EventType: ev.Type,
			Severity:  strings.ToLower(string(m.Severity)),
			Message:   m.Description,
			Fields:    cloneFields(ev.Fields),
		})
	}
	return findings
}

func (e *PolicyEvaluator) anomalyFindings(ctx context.Context, rb *v1alpha1.RuntimeBehavior, ev runtimeevents.Event) []v1alpha1.RuleFinding {
	if e.anomalyDetector == nil || rb == nil {
		return nil
	}
	findings := []v1alpha1.RuleFinding{}

	addFinding := func(kind, observed string, res *policy.AnomalyDetectionResult) {
		if res == nil || !e.anomalyDetector.MeetsConfidenceThreshold(res) {
			return
		}
		severity := "warning"
		if rb.Spec.Mode == v1alpha1.ModeEnforce {
			severity = "error"
		}
		findings = append(findings, v1alpha1.RuleFinding{
			RuleName:  "anomaly-" + kind,
			EventType: ev.Type,
			Severity:  severity,
			Message:   "Behavior outside learned baseline: " + observed,
			Fields:    cloneFields(ev.Fields),
		})
	}

	switch strings.ToLower(strings.TrimSpace(ev.Type)) {
	case "exec":
		val := firstNonEmpty(ev.Field("process.name"), ev.Field("comm"), ev.Field("proc.comm"), ev.Field("args"))
		addFinding("exec", val, e.anomalyDetector.EvaluateExecBehavior(ctx, rb, val))
	case "open":
		val := firstNonEmpty(ev.Field("fname"), ev.Field("file.path"), ev.Field("path"), ev.Field("fullPath"), ev.Field("filename"))
		addFinding("open", val, e.anomalyDetector.EvaluateOpenBehavior(ctx, rb, val))
	case "connect", "tcpconnect", "network":
		val := firstNonEmpty(ev.Field("destination.ip"), ev.Field("dst.addr"), ev.Field("destination"))
		addFinding("network", val, e.anomalyDetector.EvaluateNetworkBehavior(ctx, rb, val))
	case "dns":
		val := firstNonEmpty(ev.Field("query"), ev.Field("dns.query"), ev.Field("domain"))
		addFinding("dns", val, e.anomalyDetector.EvaluateDNSBehavior(ctx, rb, val))
	}

	return findings
}

func (e *PolicyEvaluator) findRuntimeBehaviorForPod(ctx context.Context, pod *corev1.Pod) *v1alpha1.RuntimeBehavior {
	if e.client == nil || pod == nil {
		return nil
	}
	list := &v1alpha1.RuntimeBehaviorList{}
	if err := e.client.List(ctx, list, client.InNamespace(pod.Namespace)); err != nil {
		return nil
	}
	for i := range list.Items {
		rb := &list.Items[i]
		if rb.Spec.WorkloadSelector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(rb.Spec.WorkloadSelector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(pod.Labels)) {
			return rb
		}
	}
	return nil
}

func (e *PolicyEvaluator) updateRuntimeBehaviorObservation(ctx context.Context, rb *v1alpha1.RuntimeBehavior, ev runtimeevents.Event) {
	if e.client == nil || rb == nil {
		return
	}
	copyRB := &v1alpha1.RuntimeBehavior{}
	b, _ := json.Marshal(rb)
	_ = json.Unmarshal(b, copyRB)
	now := metav1.NewTime(time.Now().UTC())
	if copyRB.Status.Observed == nil {
		copyRB.Status.Observed = &v1alpha1.ObservedBehaviors{}
	}
	if copyRB.Status.Confidence == nil {
		copyRB.Status.Confidence = &v1alpha1.ConfidenceMetadata{}
	}
	if copyRB.Status.Confidence.ObservedFrom == nil {
		copyRB.Status.Confidence.ObservedFrom = &now
	}
	copyRB.Status.Confidence.ObservedTo = &now
	copyRB.Status.Confidence.SampleCount++

	addUnique := func(items []string, v string) []string {
		v = strings.TrimSpace(v)
		if v == "" {
			return items
		}
		for _, existing := range items {
			if existing == v {
				return items
			}
		}
		return append(items, v)
	}

	switch strings.ToLower(strings.TrimSpace(ev.Type)) {
	case "exec":
		copyRB.Status.Observed.Exec = addUnique(copyRB.Status.Observed.Exec, firstNonEmpty(ev.Field("process.name"), ev.Field("comm"), ev.Field("proc.comm"), ev.Field("args")))
	case "open":
		copyRB.Status.Observed.Open = addUnique(copyRB.Status.Observed.Open, firstNonEmpty(ev.Field("fname"), ev.Field("file.path"), ev.Field("path"), ev.Field("fullPath")))
	case "connect", "tcpconnect", "network":
		copyRB.Status.Observed.Network = addUnique(copyRB.Status.Observed.Network, firstNonEmpty(ev.Field("destination.ip"), ev.Field("dst.addr"), ev.Field("destination")))
	case "dns":
		copyRB.Status.Observed.DNS = addUnique(copyRB.Status.Observed.DNS, firstNonEmpty(ev.Field("query"), ev.Field("dns.query"), ev.Field("domain")))
	}

	compaction := baselinepkg.CompactObserved(copyRB.Status.Observed, baselinepkg.DefaultCompactionConfig())
	if compaction.ExecOverflow {
		observability.IncBaselineObservedOverflow("exec")
	}
	if compaction.OpenOverflow {
		observability.IncBaselineObservedOverflow("open")
	}
	if compaction.NetworkOverflow {
		observability.IncBaselineObservedOverflow("network")
	}
	if compaction.DNSOverflow {
		observability.IncBaselineObservedOverflow("dns")
	}

	copyRB.Status.Lifecycle = v1alpha1.LifecyclePartial
	if copyRB.Spec.Mode == v1alpha1.ModeLearning && copyRB.Spec.Learning != nil {
		samplesReached := copyRB.Status.Confidence.SampleCount >= int64(copyRB.Spec.Learning.MinSamples)
		durationReached := false
		if copyRB.Spec.Learning.Duration != nil && copyRB.Status.Confidence.ObservedFrom != nil {
			durationReached = copyRB.Status.Confidence.ObservedFrom.Add(copyRB.Spec.Learning.Duration.Duration).Before(time.Now().UTC())
		}
		if samplesReached && (durationReached || copyRB.Spec.Learning.Duration == nil) {
			copyRB.Status.Lifecycle = v1alpha1.LifecycleCompleted
			copyRB.Spec.Mode = v1alpha1.ModeMonitor
		}
	}
	copyRB.Status.LastTransitionTime = &now

	if err := e.client.Update(ctx, copyRB); err != nil {
		return
	}
	e.observeBaselineCompletionRatio(ctx, copyRB.Namespace)
}

func (e *PolicyEvaluator) observeBaselineCompletionRatio(ctx context.Context, namespace string) {
	if e.client == nil || strings.TrimSpace(namespace) == "" {
		return
	}
	list := &v1alpha1.RuntimeBehaviorList{}
	if err := e.client.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return
	}
	if len(list.Items) == 0 {
		observability.SetBaselineCompletionRatio(namespace, 0)
		return
	}
	completed := 0
	for i := range list.Items {
		if list.Items[i].Status.Lifecycle == v1alpha1.LifecycleCompleted {
			completed++
		}
	}
	ratio := float64(completed) / float64(len(list.Items))
	observability.SetBaselineCompletionRatio(namespace, ratio)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func cloneFields(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
