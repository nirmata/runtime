package pipeline

import (
	corev1 "k8s.io/api/core/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/policy"
)

// PolicyMatcher wraps policy.Evaluator to implement Matcher.
type PolicyMatcher struct {
	evaluator *policy.Evaluator
}

// NewPolicyMatcher creates a new PolicyMatcher.
func NewPolicyMatcher(evaluator *policy.Evaluator) *PolicyMatcher {
	return &PolicyMatcher{evaluator: evaluator}
}

// Matches uses the policy evaluator to check if a policy matches a pod.
func (m *PolicyMatcher) Matches(p *v1alpha1.RuntimePolicy, pod *corev1.Pod, nsLabels map[string]string) (bool, error) {
	return m.evaluator.MatchesPolicy(p, pod, nsLabels)
}
