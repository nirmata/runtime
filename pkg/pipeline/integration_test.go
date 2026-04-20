package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/policy"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// TestEndToEnd_MockIG_OpenPolicy is a regression test for the original bug
// where zero eBPF events caused zero findings. It wires a mock IG collector
// into a real InspektorGadgetSource, feeds events through the real CEL
// evaluator, and verifies PolicyReport findings are produced.
func TestEndToEnd_MockIG_OpenPolicy(t *testing.T) {
	// 1. Set up a mock IG collector that returns open events with IG field names.
	mockCollector := &mockPipelineCollector{
		events: map[string][]runtimeevents.Event{
			"open": {
				{
					Type:      "open",
					Source:    "inspektorgadget",
					PodName:   "demo",
					Namespace: "runtime-demo",
					Timestamp: time.Now().UTC(),
					Fields: map[string]string{
						"fname":     "/etc/hosts",
						"proc.comm": "cat",
						"proc.pid":  "12345",
					},
				},
				{
					Type:      "open",
					Source:    "inspektorgadget",
					PodName:   "demo",
					Namespace: "runtime-demo",
					Timestamp: time.Now().UTC(),
					Fields: map[string]string{
						"fname":     "/tmp/safe.txt",
						"proc.comm": "vim",
					},
				},
			},
		},
	}

	igSource := datasource.NewInspektorGadgetSource(5*time.Second, 3*time.Second)
	igSource.Collector = mockCollector

	// 2. Build a real pipeline with the mock data source and real evaluator.
	policyEval := policy.NewEvaluator()
	collector := NewDataSourceCollector(igSource)
	evaluator := NewPolicyEvaluator(policyEval)
	matcher := NewPolicyMatcher(policyEval)
	reporter := &MockReporter{}

	mgr := NewManager(matcher, collector, evaluator, reporter)

	// 3. Define an open policy that detects /etc/hosts access.
	runtimePolicy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "detect-sensitive-open"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name:     "sensitive-file-open",
				Event:    "open",
				Severity: "high",
				Message:  "Sensitive file open detected",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["fname"].contains("/etc/hosts")`,
				}},
				Actions: []v1alpha1.RuntimeActionRef{{Type: "generate_report"}},
			}},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo",
			Namespace: "runtime-demo",
			Labels:    map[string]string{"app": "demo"},
		},
	}
	nsLabels := map[string]string{"runtime-monitor": "enabled"}

	// 4. Process the pod through the full pipeline.
	err := mgr.ProcessPod(context.Background(), pod, []v1alpha1.RuntimePolicy{runtimePolicy}, nsLabels)
	require.NoError(t, err)

	// 5. Verify exactly one report was generated with 1 finding (only /etc/hosts matches).
	require.Len(t, reporter.Reports, 1, "expected one report for the matching policy")
	report := reporter.Reports[0]
	require.Equal(t, "detect-sensitive-open", report.Policy.Name)
	require.Equal(t, "demo", report.Pod.Name)
	require.Len(t, report.Findings, 1, "only /etc/hosts event should match")
	require.Equal(t, "sensitive-file-open", report.Findings[0].RuleName)
	require.Equal(t, "high", report.Findings[0].Severity)
	require.Equal(t, "/etc/hosts", report.Findings[0].Fields["fname"])
}

// TestEndToEnd_MockIG_ExecPolicy verifies the exec detection pipeline works
// end-to-end with mock IG events.
func TestEndToEnd_MockIG_ExecPolicy(t *testing.T) {
	mockCollector := &mockPipelineCollector{
		events: map[string][]runtimeevents.Event{
			"exec": {
				{
					Type:      "exec",
					Source:    "inspektorgadget",
					PodName:   "app-pod",
					Namespace: "production",
					Timestamp: time.Now().UTC(),
					Fields: map[string]string{
						"proc.comm":        "cat",
						"proc.pid":         "9999",
						"args":             "/bin/cat /etc/hosts",
						"proc.parent.comm": "sh",
					},
				},
			},
		},
	}

	igSource := datasource.NewInspektorGadgetSource(5*time.Second, 3*time.Second)
	igSource.Collector = mockCollector

	policyEval := policy.NewEvaluator()
	collector := NewDataSourceCollector(igSource)
	evaluator := NewPolicyEvaluator(policyEval)
	matcher := NewPolicyMatcher(policyEval)
	reporter := &MockReporter{}

	mgr := NewManager(matcher, collector, evaluator, reporter)

	runtimePolicy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "detect-exec"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name:     "all-exec",
				Event:    "exec",
				Severity: "medium",
				Message:  "Exec detected",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `size(event) > 0`,
				}},
			}},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "production"},
	}

	err := mgr.ProcessPod(context.Background(), pod, []v1alpha1.RuntimePolicy{runtimePolicy}, nil)
	require.NoError(t, err)

	require.Len(t, reporter.Reports, 1)
	require.Len(t, reporter.Reports[0].Findings, 1)
	require.Equal(t, "all-exec", reporter.Reports[0].Findings[0].RuleName)
}

// TestEndToEnd_MockIG_ZeroEvents verifies that when the collector returns
// zero events, the pipeline still produces a report (with zero findings)
// rather than silently dropping the policy evaluation.
func TestEndToEnd_MockIG_ZeroEvents(t *testing.T) {
	mockCollector := &mockPipelineCollector{
		events: map[string][]runtimeevents.Event{
			"open": {},
		},
	}

	igSource := datasource.NewInspektorGadgetSource(5*time.Second, 3*time.Second)
	igSource.Collector = mockCollector

	policyEval := policy.NewEvaluator()
	collector := NewDataSourceCollector(igSource)
	evaluator := NewPolicyEvaluator(policyEval)
	matcher := NewPolicyMatcher(policyEval)
	reporter := &MockReporter{}

	mgr := NewManager(matcher, collector, evaluator, reporter)

	runtimePolicy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "detect-open"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name:  "test-open",
				Event: "open",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["fname"].contains("/etc/hosts")`,
				}},
			}},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
	}

	err := mgr.ProcessPod(context.Background(), pod, []v1alpha1.RuntimePolicy{runtimePolicy}, nil)
	require.NoError(t, err)

	// With zero events, a report is still written (with zero findings).
	require.Len(t, reporter.Reports, 1)
	require.Empty(t, reporter.Reports[0].Findings)
}

// TestEndToEnd_MockIG_FieldAliasing verifies that CEL expressions using
// different field names (fname, file.path, path) all resolve correctly
// through the full pipeline, preventing the "no such key" regression.
func TestEndToEnd_MockIG_FieldAliasing(t *testing.T) {
	// Event has only "path" but policy uses "fname"
	mockCollector := &mockPipelineCollector{
		events: map[string][]runtimeevents.Event{
			"open": {
				{
					Type:      "open",
					Source:    "inspektorgadget",
					PodName:   "demo",
					Namespace: "default",
					Timestamp: time.Now().UTC(),
					Fields:    map[string]string{"path": "/etc/hosts", "proc.comm": "cat"},
				},
			},
		},
	}

	igSource := datasource.NewInspektorGadgetSource(5*time.Second, 3*time.Second)
	igSource.Collector = mockCollector

	policyEval := policy.NewEvaluator()
	collector := NewDataSourceCollector(igSource)
	evaluator := NewPolicyEvaluator(policyEval)
	matcher := NewPolicyMatcher(policyEval)
	reporter := &MockReporter{}

	mgr := NewManager(matcher, collector, evaluator, reporter)

	// Policy uses "fname" but events only have "path" — aliases should bridge the gap.
	runtimePolicy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "alias-test"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name:    "detect-via-fname",
				Event:   "open",
				Message: "Detected via alias",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["fname"].contains("/etc/hosts")`,
				}},
			}},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
	}

	err := mgr.ProcessPod(context.Background(), pod, []v1alpha1.RuntimePolicy{runtimePolicy}, nil)
	require.NoError(t, err)

	require.Len(t, reporter.Reports, 1)
	require.Len(t, reporter.Reports[0].Findings, 1, "field aliasing should make path available as fname")
}

// TestEndToEnd_MockIG_MultiplePolices verifies that multiple policies are
// independently evaluated against the same pod and events.
func TestEndToEnd_MockIG_MultiplePolicies(t *testing.T) {
	mockCollector := &mockPipelineCollector{
		events: map[string][]runtimeevents.Event{
			"open": {
				{
					Type: "open", PodName: "demo", Namespace: "default",
					Source: "inspektorgadget", Timestamp: time.Now().UTC(),
					Fields: map[string]string{"fname": "/etc/hosts", "proc.comm": "cat"},
				},
			},
			"exec": {
				{
					Type: "exec", PodName: "demo", Namespace: "default",
					Source: "inspektorgadget", Timestamp: time.Now().UTC(),
					Fields: map[string]string{"proc.comm": "sh", "args": "/bin/sh"},
				},
			},
		},
	}

	igSource := datasource.NewInspektorGadgetSource(5*time.Second, 3*time.Second)
	igSource.Collector = mockCollector

	policyEval := policy.NewEvaluator()
	collector := NewDataSourceCollector(igSource)
	evaluator := NewPolicyEvaluator(policyEval)
	matcher := NewPolicyMatcher(policyEval)
	reporter := &MockReporter{}

	mgr := NewManager(matcher, collector, evaluator, reporter)

	openPolicy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "open-policy"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name: "open-check", Event: "open",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["fname"].contains("/etc/hosts")`,
				}},
			}},
		},
	}

	execPolicy := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "exec-policy"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name: "exec-check", Event: "exec",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `size(event) > 0`,
				}},
			}},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
	}

	err := mgr.ProcessPod(context.Background(), pod,
		[]v1alpha1.RuntimePolicy{openPolicy, execPolicy}, nil)
	require.NoError(t, err)

	require.Len(t, reporter.Reports, 2, "both policies should produce reports")
	require.Len(t, reporter.Reports[0].Findings, 1, "open policy should have 1 finding")
	require.Len(t, reporter.Reports[1].Findings, 1, "exec policy should have 1 finding")
}

// mockPipelineCollector implements datasource.GadgetCollector for integration tests.
// It maps event types to pre-defined events, simulating IG output.
type mockPipelineCollector struct {
	events map[string][]runtimeevents.Event
}

func (m *mockPipelineCollector) Collect(_ context.Context, req datasource.GadgetCollectRequest) ([]runtimeevents.Event, error) {
	if evts, ok := m.events[req.EventType]; ok {
		return append([]runtimeevents.Event{}, evts...), nil
	}
	return []runtimeevents.Event{}, nil
}
