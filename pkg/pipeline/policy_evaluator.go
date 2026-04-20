package pipeline

import (
	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/policy"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// PolicyEvaluator wraps policy.Evaluator to implement Evaluator.
type PolicyEvaluator struct {
	evaluator *policy.Evaluator
}

// NewPolicyEvaluator creates a new PolicyEvaluator.
func NewPolicyEvaluator(evaluator *policy.Evaluator) *PolicyEvaluator {
	return &PolicyEvaluator{evaluator: evaluator}
}

// Evaluate evaluates a policy against runtime events.
func (e *PolicyEvaluator) Evaluate(p *v1alpha1.RuntimePolicy, events []runtimeevents.Event) EvaluationResult {
	result := e.evaluator.EvaluateRuntime(p, events)
	return EvaluationResult{
		Findings: result.Findings,
		Actions:  result.Actions,
	}
}
