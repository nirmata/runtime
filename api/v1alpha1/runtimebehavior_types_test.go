package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRuntimeBehaviorDeepCopy(t *testing.T) {
	original := &RuntimeBehavior{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "runtime.kyverno.io/v1alpha1",
			Kind:       "RuntimeBehavior",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-behavior",
			Namespace: "default",
		},
		Spec: RuntimeBehaviorSpec{
			Mode: ModeMonitor,
			Learning: &LearningConfig{
				MinSamples: 100,
				StartAfter: StartAfterReady,
			},
			Allow: &AllowRules{
				Exec: []string{"/bin/sh", "/usr/bin/python"},
				Open: []string{"/etc/hosts"},
			},
		},
		Status: RuntimeBehaviorStatus{
			Lifecycle: LifecycleLearning,
			Confidence: &ConfidenceMetadata{
				SampleCount: 50,
				DropRate:    0.01,
			},
		},
	}

	copied := original.DeepCopyObject().(*RuntimeBehavior)

	if copied.Name != original.Name {
		t.Errorf("Name mismatch: %s vs %s", copied.Name, original.Name)
	}
	if copied.Spec.Mode != original.Spec.Mode {
		t.Errorf("Mode mismatch: %s vs %s", copied.Spec.Mode, original.Spec.Mode)
	}
	if len(copied.Spec.Allow.Exec) != len(original.Spec.Allow.Exec) {
		t.Errorf("Allow.Exec length mismatch: %d vs %d", len(copied.Spec.Allow.Exec), len(original.Spec.Allow.Exec))
	}
	if copied.Status.Lifecycle != original.Status.Lifecycle {
		t.Errorf("Lifecycle mismatch: %s vs %s", copied.Status.Lifecycle, original.Status.Lifecycle)
	}

	// Verify it's a deep copy by modifying the copy
	copied.Spec.Mode = ModeEnforce
	if original.Spec.Mode == ModeEnforce {
		t.Error("Original was modified when copy was changed")
	}
}

func TestRuntimeBehaviorListDeepCopy(t *testing.T) {
	original := &RuntimeBehaviorList{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "runtime.kyverno.io/v1alpha1",
			Kind:       "RuntimeBehaviorList",
		},
		Items: []RuntimeBehavior{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "rb1"},
				Spec:       RuntimeBehaviorSpec{Mode: ModeMonitor},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "rb2"},
				Spec:       RuntimeBehaviorSpec{Mode: ModeEnforce},
			},
		},
	}

	copied := original.DeepCopyObject().(*RuntimeBehaviorList)

	if len(copied.Items) != len(original.Items) {
		t.Errorf("Items length mismatch: %d vs %d", len(copied.Items), len(original.Items))
	}
	if copied.Items[0].Name != original.Items[0].Name {
		t.Errorf("Item 0 name mismatch: %s vs %s", copied.Items[0].Name, original.Items[0].Name)
	}

	// Verify it's a deep copy
	copied.Items[0].Spec.Mode = ModeEnforce
	if original.Items[0].Spec.Mode == ModeEnforce {
		t.Error("Original was modified when copy was changed")
	}
}

func TestRuntimeBehaviorMarshalJSON(t *testing.T) {
	rb := &RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: RuntimeBehaviorSpec{
			Mode: ModeMonitor,
			Allow: &AllowRules{
				Exec:    []string{"/bin/sh"},
				Open:    []string{"/etc/hosts"},
				Network: []string{"10.0.0.0/8"},
				DNS:     []string{"*.svc.cluster.local"},
			},
		},
		Status: RuntimeBehaviorStatus{
			Lifecycle: LifecycleLearning,
		},
	}

	data, err := json.Marshal(rb)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var unmarshaled RuntimeBehavior
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if unmarshaled.Name != rb.Name {
		t.Errorf("Name mismatch after round-trip: %s vs %s", unmarshaled.Name, rb.Name)
	}
	if unmarshaled.Spec.Mode != rb.Spec.Mode {
		t.Errorf("Mode mismatch after round-trip: %s vs %s", unmarshaled.Spec.Mode, rb.Spec.Mode)
	}
	if len(unmarshaled.Spec.Allow.Exec) != len(rb.Spec.Allow.Exec) {
		t.Error("Allow.Exec length mismatch after round-trip")
	}
}

func TestLifecycleConstants(t *testing.T) {
	tests := []struct {
		lifecycle RuntimeBehaviorLifecycle
		expected  string
	}{
		{LifecycleLearning, "learning"},
		{LifecyclePartial, "partial"},
		{LifecycleCompleted, "completed"},
		{LifecycleStale, "stale"},
		{LifecycleFailed, "failed"},
	}

	for _, test := range tests {
		if string(test.lifecycle) != test.expected {
			t.Errorf("Lifecycle %v != %s", test.lifecycle, test.expected)
		}
	}
}

func TestModeConstants(t *testing.T) {
	tests := []struct {
		mode     RuntimeBehaviorMode
		expected string
	}{
		{ModeLearning, "learning"},
		{ModeMonitor, "monitor"},
		{ModeEnforce, "enforce"},
	}

	for _, test := range tests {
		if string(test.mode) != test.expected {
			t.Errorf("Mode %v != %s", test.mode, test.expected)
		}
	}
}

func TestStartAfterConditionConstants(t *testing.T) {
	tests := []struct {
		condition StartAfterCondition
		expected  string
	}{
		{StartAfterImmediate, "immediate"},
		{StartAfterReady, "ready"},
	}

	for _, test := range tests {
		if string(test.condition) != test.expected {
			t.Errorf("StartAfter %v != %s", test.condition, test.expected)
		}
	}
}

func TestRuntimeBehaviorWithSharedDefaults(t *testing.T) {
	rb := &RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-with-defaults",
			Namespace: "default",
		},
		Spec: RuntimeBehaviorSpec{
			Mode: ModeMonitor,
			Allow: &AllowRules{
				Exec: []string{"/app/server"},
				Refs: []BehaviorReference{
					{
						Name:      "shared-defaults",
						Namespace: "kyverno-runtime",
					},
				},
				Deny: &DenyRules{
					Exec: []string{"/bin/sh"},
				},
			},
		},
	}

	if len(rb.Spec.Allow.Refs) != 1 {
		t.Errorf("Expected 1 ref, got %d", len(rb.Spec.Allow.Refs))
	}
	if rb.Spec.Allow.Refs[0].Name != "shared-defaults" {
		t.Errorf("Ref name mismatch: %s", rb.Spec.Allow.Refs[0].Name)
	}
	if rb.Spec.Allow.Deny == nil || len(rb.Spec.Allow.Deny.Exec) != 1 {
		t.Error("Deny rules not properly set")
	}
}

func TestRuntimeBehaviorWithoutWorkloadSelector(t *testing.T) {
	// SharedDefaults library behavior (no workloadSelector)
	rb := &RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enterprise-defaults",
			Namespace: "kyverno-runtime",
		},
		Spec: RuntimeBehaviorSpec{
			// No WorkloadSelector - this is a shared library
			Allow: &AllowRules{
				Network: []string{"proxy.corp.internal:3128"},
				DNS:     []string{"*.corp.internal"},
			},
		},
	}

	if rb.Spec.WorkloadSelector != nil {
		t.Error("WorkloadSelector should be nil for shared defaults")
	}
	if len(rb.Spec.Allow.Network) != 1 {
		t.Error("Network rules not set")
	}
}
