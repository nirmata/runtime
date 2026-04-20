package pipeline

import (
	corev1 "k8s.io/api/core/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

// Matcher determines if a policy applies to a pod.
type Matcher interface {
	// Matches returns true if the policy's matchConstraints and selectors
	// apply to the given pod in the given namespace.
	Matches(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, namespaceLabels map[string]string) (bool, error)
}
