package pipeline

import (
	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// EvaluationResult contains findings and actions from evaluating a policy
// against collected events.
type EvaluationResult struct {
	Findings []v1alpha1.RuleFinding
	Actions  []v1alpha1.ActionRecord
}

// Evaluator evaluates policies against collected runtime events.
type Evaluator interface {
	// Evaluate evaluates a policy against collected events.
	// Returns findings and actions if the policy conditions match.
	Evaluate(policy *v1alpha1.RuntimePolicy, events []runtimeevents.Event) EvaluationResult
}
