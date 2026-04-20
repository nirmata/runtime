package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

func TestManagerProcessPod_NoMatchingPolicies(t *testing.T) {
	matcher := &MockMatcher{
		MatchesFunc: func(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, nsLabels map[string]string) (bool, error) {
			return false, nil
		},
	}
	collector := &MockCollector{}
	evaluator := &MockEvaluator{}
	reporter := &MockReporter{}

	mgr := NewManager(matcher, collector, evaluator, reporter)

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}}
	policy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{
				{Name: "test", Event: "exec"},
			},
		},
	}

	err := mgr.ProcessPod(context.Background(), pod, []v1alpha1.RuntimePolicy{policy}, nil)
	require.NoError(t, err)
	require.Empty(t, reporter.Reports)
}

func TestManagerProcessPod_PolicyMatches(t *testing.T) {

	matcher := &MockMatcher{
		MatchesFunc: func(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, nsLabels map[string]string) (bool, error) {
			return true, nil
		},
	}

	events := []runtimeevents.Event{
		{Type: "exec", PodName: "test-pod", Namespace: "default"},
	}

	collector := &MockCollector{
		CollectFunc: func(ctx context.Context, req CollectorRequest) ([]runtimeevents.Event, error) {
			return events, nil
		},
	}

	findings := []v1alpha1.RuleFinding{
		{RuleName: "rule1", Message: "found", Severity: "high"},
	}

	evaluator := &MockEvaluator{
		EvaluateFunc: func(policy *v1alpha1.RuntimePolicy, events []runtimeevents.Event) EvaluationResult {
			return EvaluationResult{Findings: findings}
		},
	}

	reporter := &MockReporter{}

	mgr := NewManager(matcher, collector, evaluator, reporter)

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}}
	policy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{
				{Name: "test", Event: "exec"},
			},
		},
	}

	err := mgr.ProcessPod(context.Background(), pod, []v1alpha1.RuntimePolicy{policy}, nil)
	require.NoError(t, err)

	require.Len(t, reporter.Reports, 1)
	require.Equal(t, "test-pod", reporter.Reports[0].Pod.Name)
	require.Equal(t, "test-policy", reporter.Reports[0].Policy.Name)
	require.Len(t, reporter.Reports[0].Findings, 1)
	require.Equal(t, "rule1", reporter.Reports[0].Findings[0].RuleName)
}

func TestManagerProcessPod_MatcherError(t *testing.T) {

	matchErr := errors.New("match error")
	matcher := &MockMatcher{
		MatchesFunc: func(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, nsLabels map[string]string) (bool, error) {
			return false, matchErr
		},
	}

	mgr := NewManager(matcher, &MockCollector{}, &MockEvaluator{}, &MockReporter{})

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}}
	policy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec:       v1alpha1.RuntimePolicySpec{},
	}

	err := mgr.ProcessPod(context.Background(), pod, []v1alpha1.RuntimePolicy{policy}, nil)
	require.ErrorIs(t, err, matchErr)
}

func TestManagerProcessPod_CollectorError(t *testing.T) {

	matcher := &MockMatcher{
		MatchesFunc: func(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, nsLabels map[string]string) (bool, error) {
			return true, nil
		},
	}

	collectErr := errors.New("collect error")
	collector := &MockCollector{
		CollectFunc: func(ctx context.Context, req CollectorRequest) ([]runtimeevents.Event, error) {
			return nil, collectErr
		},
	}

	mgr := NewManager(matcher, collector, &MockEvaluator{}, &MockReporter{})

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}}
	policy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{
				{Name: "test", Event: "exec"},
			},
		},
	}

	err := mgr.ProcessPod(context.Background(), pod, []v1alpha1.RuntimePolicy{policy}, nil)
	require.ErrorIs(t, err, collectErr)
}

func TestManagerProcessPod_ReporterError(t *testing.T) {

	matcher := &MockMatcher{
		MatchesFunc: func(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, nsLabels map[string]string) (bool, error) {
			return true, nil
		},
	}

	collector := &MockCollector{
		CollectFunc: func(ctx context.Context, req CollectorRequest) ([]runtimeevents.Event, error) {
			return []runtimeevents.Event{{Type: "exec"}}, nil
		},
	}

	evaluator := &MockEvaluator{
		EvaluateFunc: func(policy *v1alpha1.RuntimePolicy, events []runtimeevents.Event) EvaluationResult {
			return EvaluationResult{
				Findings: []v1alpha1.RuleFinding{{RuleName: "test"}},
			}
		},
	}

	reportErr := errors.New("report error")
	reporter := &MockReporter{
		ReportFunc: func(ctx context.Context, req ReportRequest) error {
			return reportErr
		},
	}

	mgr := NewManager(matcher, collector, evaluator, reporter)

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}}
	policy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{
				{Name: "test", Event: "exec"},
			},
		},
	}

	err := mgr.ProcessPod(context.Background(), pod, []v1alpha1.RuntimePolicy{policy}, nil)
	require.ErrorIs(t, err, reportErr)
}

func TestManagerProcessPod_MultiplePolicies(t *testing.T) {

	matchCount := 0
	matcher := &MockMatcher{
		MatchesFunc: func(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, nsLabels map[string]string) (bool, error) {
			matchCount++
			return policy.Name == "policy-1", nil
		},
	}

	collector := &MockCollector{
		CollectFunc: func(ctx context.Context, req CollectorRequest) ([]runtimeevents.Event, error) {
			return []runtimeevents.Event{{Type: "exec"}}, nil
		},
	}

	evaluator := &MockEvaluator{
		EvaluateFunc: func(policy *v1alpha1.RuntimePolicy, events []runtimeevents.Event) EvaluationResult {
			return EvaluationResult{
				Findings: []v1alpha1.RuleFinding{{RuleName: "test"}},
			}
		},
	}

	reporter := &MockReporter{}

	mgr := NewManager(matcher, collector, evaluator, reporter)

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"}}
	policies := []v1alpha1.RuntimePolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-1"},
			Spec: v1alpha1.RuntimePolicySpec{
				Validations: []v1alpha1.RuntimeValidation{{Name: "test", Event: "exec"}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-2"},
			Spec: v1alpha1.RuntimePolicySpec{
				Validations: []v1alpha1.RuntimeValidation{{Name: "test", Event: "exec"}},
			},
		},
	}

	err := mgr.ProcessPod(context.Background(), pod, policies, nil)
	require.NoError(t, err)

	require.Equal(t, 2, matchCount)
	require.Len(t, reporter.Reports, 1)
	require.Equal(t, "policy-1", reporter.Reports[0].Policy.Name)
}

func TestEventTypesForPolicy(t *testing.T) {
	cases := []struct {
		name        string
		policy      *v1alpha1.RuntimePolicy
		expectedLen int
		expectedSet map[string]bool
	}{
		{
			name: "no validations",
			policy: &v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{Validations: []v1alpha1.RuntimeValidation{}},
			},
			expectedLen: 0,
		},
		{
			name: "single event type",
			policy: &v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Validations: []v1alpha1.RuntimeValidation{
						{Event: "exec"},
					},
				},
			},
			expectedLen: 1,
			expectedSet: map[string]bool{"exec": true},
		},
		{
			name: "multiple event types",
			policy: &v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Validations: []v1alpha1.RuntimeValidation{
						{Event: "exec"},
						{Event: "connect"},
						{Event: "exec"}, // duplicate
					},
				},
			},
			expectedLen: 2,
			expectedSet: map[string]bool{"exec": true, "connect": true},
		},
		{
			name: "empty event type",
			policy: &v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Validations: []v1alpha1.RuntimeValidation{
						{Event: "exec"},
						{Event: ""},
					},
				},
			},
			expectedLen: 1,
			expectedSet: map[string]bool{"exec": true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := eventTypesForPolicy(tc.policy)
			require.Len(t, result, tc.expectedLen)
			for _, et := range result {
				require.True(t, tc.expectedSet[et], "unexpected event type: %s", et)
			}
		})
	}
}
