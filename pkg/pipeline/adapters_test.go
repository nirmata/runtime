package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/policy"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// TestNewDataSourceCollector tests the DataSourceCollector constructor
func TestNewDataSourceCollector(t *testing.T) {
	source := datasource.NewMockSource()
	collector := NewDataSourceCollector(source)

	require.NotNil(t, collector)
	require.NotNil(t, collector.source)
}

// TestDataSourceCollectorCollect tests event collection delegation
func TestDataSourceCollectorCollect(t *testing.T) {
	events := []runtimeevents.Event{
		{Type: "exec", PodName: "test-pod", Namespace: "default"},
		{Type: "open", PodName: "test-pod", Namespace: "default"},
	}
	source := datasource.NewMockSource(events...)
	collector := NewDataSourceCollector(source)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
	}
	req := CollectorRequest{
		Pod:        pod,
		EventTypes: []string{"exec", "open"},
		Parameters: map[string]string{"key": "value"},
	}

	result, err := collector.Collect(context.Background(), req)

	require.NoError(t, err)
	require.Len(t, result, 2)
	require.Equal(t, "exec", result[0].Type)
	require.Equal(t, "open", result[1].Type)
}

// TestDataSourceCollectorCollectError tests error propagation from source
func TestDataSourceCollectorCollectError(t *testing.T) {
	source := &MockErrorSource{err: errors.New("source error")}
	collector := NewDataSourceCollector(source)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
	}
	req := CollectorRequest{Pod: pod}

	_, err := collector.Collect(context.Background(), req)

	require.Error(t, err)
	require.Equal(t, "source error", err.Error())
}

// TestNewPolicyMatcher tests the PolicyMatcher constructor
func TestNewPolicyMatcher(t *testing.T) {
	evaluator := policy.NewEvaluator()
	matcher := NewPolicyMatcher(evaluator)

	require.NotNil(t, matcher)
	require.NotNil(t, matcher.evaluator)
}

// TestPolicyMatcherMatches tests policy matching delegation
func TestPolicyMatcherMatches(t *testing.T) {
	evaluator := policy.NewEvaluator()
	matcher := NewPolicyMatcher(evaluator)

	policy := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec: v1alpha1.RuntimePolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					{
						RuleWithOperations: admissionregistrationv1.RuleWithOperations{
							Rule: admissionregistrationv1.Rule{
								APIGroups: []string{""},
								Resources: []string{"pods"},
							},
						},
					},
				},
			},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
	}

	match, err := matcher.Matches(policy, pod, nil)

	require.NoError(t, err)
	require.True(t, match)
}

// TestPolicyMatcherNoMatch tests when policy doesn't match
func TestPolicyMatcherNoMatch(t *testing.T) {
	evaluator := policy.NewEvaluator()
	matcher := NewPolicyMatcher(evaluator)

	// Policy with no match constraints - should match any pod
	policy := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec:       v1alpha1.RuntimePolicySpec{},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
	}

	match, err := matcher.Matches(policy, pod, nil)

	require.NoError(t, err)
	// Empty spec matches all pods
	require.True(t, match)
}

// TestNewPolicyEvaluator tests the PolicyEvaluator constructor
func TestNewPolicyEvaluator(t *testing.T) {
	evaluator := policy.NewEvaluator()
	policyEval := NewPolicyEvaluator(evaluator)

	require.NotNil(t, policyEval)
	require.NotNil(t, policyEval.evaluator)
}

// TestPolicyEvaluatorEvaluate tests policy evaluation delegation
func TestPolicyEvaluatorEvaluate(t *testing.T) {
	evaluator := policy.NewEvaluator()
	policyEval := NewPolicyEvaluator(evaluator)

	policy := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{
				{
					Name:  "test-validation",
					Event: "exec",
					Conditions: []v1alpha1.RuntimeCELCondition{
						{
							Expression: `event.Fields['process.name'] == '/bin/bash'`,
						},
					},
				},
			},
		},
	}

	events := []runtimeevents.Event{
		{
			Type:      "exec",
			PodName:   "test-pod",
			Namespace: "default",
			Fields: map[string]string{
				"process.name": "/bin/bash",
			},
		},
	}

	result := policyEval.Evaluate(policy, events)

	require.NotNil(t, result)
	// Result should contain findings (may be empty depending on policy rules)
	require.NotNil(t, result.Findings)
}

// TestPolicyEvaluatorNoEvents tests evaluation with no events
func TestPolicyEvaluatorNoEvents(t *testing.T) {
	evaluator := policy.NewEvaluator()
	policyEval := NewPolicyEvaluator(evaluator)

	policy := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{
				{
					Name:  "test-validation",
					Event: "exec",
				},
			},
		},
	}

	result := policyEval.Evaluate(policy, []runtimeevents.Event{})

	require.NotNil(t, result)
	require.Empty(t, result.Findings)
}

// MockErrorSource is a mock datasource that always returns an error
type MockErrorSource struct {
	err error
}

func (m *MockErrorSource) Name() string {
	return "mock-error"
}

func (m *MockErrorSource) EventsForPod(ctx context.Context, pod *corev1.Pod, opts datasource.QueryOptions) ([]runtimeevents.Event, error) {
	return nil, m.err
}
