package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/policy"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

func TestPolicyEvaluator_EvaluateForPod_DualEngines(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-demo", Namespace: "default"},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}},
			Mode:             v1alpha1.ModeMonitor,
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/usr/bin/python3"},
			},
			Learning: &v1alpha1.LearningConfig{MinSamples: 1, Duration: &metav1.Duration{Duration: time.Second}},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{
			Lifecycle: v1alpha1.LifecycleCompleted,
			Confidence: &v1alpha1.ConfidenceMetadata{
				SampleCount: 2000,
				DropRate:    0.0001,
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(rb).Build()
	e := NewPolicyEvaluatorWithOptions(policy.NewEvaluator(), PolicyEvaluatorOptions{
		Client:           c,
		BaselineEnabled:  true,
		SignatureEnabled: true,
		MinConfidence:    0.6,
	})

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default", Labels: map[string]string{"app": "demo"}}}
	rp := &v1alpha1.RuntimePolicy{ObjectMeta: metav1.ObjectMeta{Name: "p"}, Spec: v1alpha1.RuntimePolicySpec{Validations: []v1alpha1.RuntimeValidation{{Name: "exec-check", Event: "exec"}}}}
	events := []runtimeevents.Event{{
		Type:      "exec",
		PodName:   "demo",
		Namespace: "default",
		Fields: map[string]string{
			"comm": "/bin/bash",
		},
	}}

	result := e.EvaluateForPod(rp, pod, events)
	require.NotEmpty(t, result.Findings)

	hasSignature := false
	hasAnomaly := false
	for _, f := range result.Findings {
		if f.RuleName == "execution-shell" {
			hasSignature = true
		}
		if f.RuleName == "anomaly-exec" {
			hasAnomaly = true
		}
	}
	require.True(t, hasSignature, "expected signature finding")
	require.True(t, hasAnomaly, "expected anomaly finding")

	updated := &v1alpha1.RuntimeBehavior{}
	require.NoError(t, c.Get(context.Background(), clientKey("default", "rb-demo"), updated))
	require.NotNil(t, updated.Status.Confidence)
	require.Greater(t, updated.Status.Confidence.SampleCount, int64(2000))
	require.NotNil(t, updated.Status.Observed)
	require.Contains(t, updated.Status.Observed.Exec, "/bin/bash")
}

func TestPolicyEvaluator_EvaluateForPod_EnginesDisabled(t *testing.T) {
	e := NewPolicyEvaluatorWithOptions(policy.NewEvaluator(), PolicyEvaluatorOptions{
		BaselineEnabled:  false,
		SignatureEnabled: false,
	})

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default", Labels: map[string]string{"app": "demo"}}}
	rp := &v1alpha1.RuntimePolicy{ObjectMeta: metav1.ObjectMeta{Name: "p"}, Spec: v1alpha1.RuntimePolicySpec{}}
	events := []runtimeevents.Event{{
		Type:      "exec",
		PodName:   "demo",
		Namespace: "default",
		Fields: map[string]string{
			"comm": "/bin/bash",
		},
	}}

	result := e.EvaluateForPod(rp, pod, events)
	require.Empty(t, result.Findings)
	require.Empty(t, result.Actions)
}

func TestPolicyEvaluator_EvaluateForPod_SkipsNonMatchingPolicyEventType(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-demo", Namespace: "default"},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}},
			Mode:             v1alpha1.ModeMonitor,
			Allow:            &v1alpha1.AllowRules{Exec: []string{"/usr/bin/python3"}},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{Confidence: &v1alpha1.ConfidenceMetadata{SampleCount: 2000}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(rb).Build()
	e := NewPolicyEvaluatorWithOptions(policy.NewEvaluator(), PolicyEvaluatorOptions{
		Client:           c,
		BaselineEnabled:  true,
		SignatureEnabled: true,
		MinConfidence:    0.6,
	})

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default", Labels: map[string]string{"app": "demo"}}}
	rp := &v1alpha1.RuntimePolicy{ObjectMeta: metav1.ObjectMeta{Name: "p"}, Spec: v1alpha1.RuntimePolicySpec{Validations: []v1alpha1.RuntimeValidation{{Name: "open-check", Event: "open"}}}}
	events := []runtimeevents.Event{{Type: "exec", PodName: "demo", Namespace: "default", Fields: map[string]string{"comm": "/bin/bash"}}}

	result := e.EvaluateForPod(rp, pod, events)
	require.Empty(t, result.Findings)

	updated := &v1alpha1.RuntimeBehavior{}
	require.NoError(t, c.Get(context.Background(), clientKey("default", "rb-demo"), updated))
	// Observation should not be updated for policies that do not subscribe to this event type.
	require.Equal(t, int64(2000), updated.Status.Confidence.SampleCount)
}

func clientKey(ns, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: ns, Name: name}
}
