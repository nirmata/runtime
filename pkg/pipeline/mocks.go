package pipeline

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// MockCollector is a mock implementation of Collector for testing.
type MockCollector struct {
	CollectFunc func(ctx context.Context, req CollectorRequest) ([]runtimeevents.Event, error)
}

func (m *MockCollector) Collect(ctx context.Context, req CollectorRequest) ([]runtimeevents.Event, error) {
	if m.CollectFunc != nil {
		return m.CollectFunc(ctx, req)
	}
	return []runtimeevents.Event{}, nil
}

// MockMatcher is a mock implementation of Matcher for testing.
type MockMatcher struct {
	MatchesFunc func(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, namespaceLabels map[string]string) (bool, error)
}

func (m *MockMatcher) Matches(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, namespaceLabels map[string]string) (bool, error) {
	if m.MatchesFunc != nil {
		return m.MatchesFunc(policy, pod, namespaceLabels)
	}
	return false, nil
}

// MockEvaluator is a mock implementation of Evaluator for testing.
type MockEvaluator struct {
	EvaluateFunc func(policy *v1alpha1.RuntimePolicy, events []runtimeevents.Event) EvaluationResult
}

func (m *MockEvaluator) Evaluate(policy *v1alpha1.RuntimePolicy, events []runtimeevents.Event) EvaluationResult {
	if m.EvaluateFunc != nil {
		return m.EvaluateFunc(policy, events)
	}
	return EvaluationResult{}
}

// MockReporter is a mock implementation of Reporter for testing.
type MockReporter struct {
	ReportFunc func(ctx context.Context, req ReportRequest) error
	Reports    []ReportRequest // Track all reports written
}

func (m *MockReporter) Report(ctx context.Context, req ReportRequest) error {
	m.Reports = append(m.Reports, req)
	if m.ReportFunc != nil {
		return m.ReportFunc(ctx, req)
	}
	return nil
}
