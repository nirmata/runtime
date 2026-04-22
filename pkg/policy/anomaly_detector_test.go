package policy

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

func TestAnomalyDetector_NewAnomalyDetector(t *testing.T) {
	tests := []struct {
		name            string
		inputConf       float64
		expectedMinConf float64
	}{
		{"negative threshold", -0.5, 0.0},
		{"above 1.0", 1.5, 1.0},
		{"zero threshold", 0.0, 0.0},
		{"valid threshold", 0.7, 0.7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewAnomalyDetector(tt.inputConf)
			if detector.minConfidence != tt.expectedMinConf {
				t.Errorf("expected minConfidence %f, got %f", tt.expectedMinConf, detector.minConfidence)
			}
		})
	}
}

func TestAnomalyDetector_EvaluateExecBehavior_NoBaseline(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	result := detector.EvaluateExecBehavior(ctx, nil, "/bin/bash")

	if result.IsAnomaly {
		t.Error("expected no anomaly when baseline is nil")
	}
	if result.BehaviorType != "exec" {
		t.Errorf("expected behavior type exec, got %s", result.BehaviorType)
	}
}

func TestAnomalyDetector_EvaluateExecBehavior_AllowedPattern(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rb",
			Namespace: "default",
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/bin/bash", "/usr/bin/python"},
			},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{
			Lifecycle: v1alpha1.LifecycleCompleted,
			Confidence: &v1alpha1.ConfidenceMetadata{
				SampleCount: 100,
				DropRate:    0.001,
			},
		},
	}

	result := detector.EvaluateExecBehavior(ctx, rb, "/bin/bash")

	if result.IsAnomaly {
		t.Error("expected allowed pattern to not be anomalous")
	}
	if result.Confidence != 0.0 {
		t.Errorf("expected confidence 0.0 for allowed pattern, got %f", result.Confidence)
	}
}

func TestAnomalyDetector_EvaluateExecBehavior_DisallowedPattern(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rb",
			Namespace: "default",
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/bin/bash"},
			},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{
			Lifecycle: v1alpha1.LifecycleCompleted,
			Confidence: &v1alpha1.ConfidenceMetadata{
				SampleCount: 100,
				DropRate:    0.001,
			},
		},
	}

	result := detector.EvaluateExecBehavior(ctx, rb, "/bin/perl")

	if !result.IsAnomaly {
		t.Error("expected disallowed pattern to be anomalous")
	}
	if result.Confidence <= 0.0 || result.Confidence >= 1.0 {
		t.Errorf("expected confidence between 0 and 1, got %f", result.Confidence)
	}
}

func TestAnomalyDetector_CalculateConfidence_HighQualityBaseline(t *testing.T) {
	detector := NewAnomalyDetector(0.5)

	rb := &v1alpha1.RuntimeBehavior{
		Status: v1alpha1.RuntimeBehaviorStatus{
			Lifecycle: v1alpha1.LifecycleCompleted,
			Confidence: &v1alpha1.ConfidenceMetadata{
				SampleCount: 1500,
				DropRate:    0.0001,
			},
		},
	}

	// Create a dummy anomaly to test confidence calculation
	detector.EvaluateExecBehavior(context.Background(), rb, "/usr/bin/perl")

	// Simulate confidence calculation by checking what it would be
	// High sample count (1500) + low drop rate (0.0001) + completed lifecycle
	// should give high confidence (capped at 1.0)

	result := detector.EvaluateExecBehavior(context.Background(), rb, "/usr/bin/perl")
	if result.Confidence < 0.9 { // Allow 10% tolerance
		t.Errorf("expected high confidence for high quality baseline, got %f", result.Confidence)
	}
}

func TestAnomalyDetector_CalculateConfidence_LowQualityBaseline(t *testing.T) {
	detector := NewAnomalyDetector(0.5)

	rb := &v1alpha1.RuntimeBehavior{
		Status: v1alpha1.RuntimeBehaviorStatus{
			Lifecycle: v1alpha1.LifecycleLearning,
			Confidence: &v1alpha1.ConfidenceMetadata{
				SampleCount: 5,
				DropRate:    0.1,
			},
		},
	}

	result := detector.EvaluateExecBehavior(context.Background(), rb, "/usr/bin/perl")

	// Low quality baseline should have lower confidence
	if result.Confidence > 0.7 {
		t.Errorf("expected lower confidence for low quality baseline, got %f", result.Confidence)
	}
}

func TestAnomalyDetector_EvaluateOpenBehavior_AllowedFile(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rb",
			Namespace: "default",
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Open: []string{"/etc/passwd", "/etc/group"},
			},
		},
	}

	result := detector.EvaluateOpenBehavior(ctx, rb, "/etc/passwd")

	if result.IsAnomaly {
		t.Error("expected allowed file open to not be anomalous")
	}
}

func TestAnomalyDetector_EvaluateOpenBehavior_DisallowedFile(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rb",
			Namespace: "default",
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Open: []string{"/etc/passwd"},
			},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{
			Lifecycle: v1alpha1.LifecycleCompleted,
			Confidence: &v1alpha1.ConfidenceMetadata{
				SampleCount: 100,
				DropRate:    0.001,
			},
		},
	}

	result := detector.EvaluateOpenBehavior(ctx, rb, "/etc/shadow")

	if !result.IsAnomaly {
		t.Error("expected disallowed file open to be anomalous")
	}
	if result.BehaviorType != "open" {
		t.Errorf("expected behavior type open, got %s", result.BehaviorType)
	}
}

func TestAnomalyDetector_EvaluateNetworkBehavior_AllowedDestination(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rb",
			Namespace: "default",
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Network: []string{"10.0.0.0/8", "172.16.0.0/12"},
			},
		},
	}

	result := detector.EvaluateNetworkBehavior(ctx, rb, "10.0.0.0/8")

	if result.IsAnomaly {
		t.Error("expected allowed network to not be anomalous")
	}
}

func TestAnomalyDetector_EvaluateNetworkBehavior_DisallowedDestination(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rb",
			Namespace: "default",
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Network: []string{"10.0.0.0/8"},
			},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{
			Lifecycle: v1alpha1.LifecycleCompleted,
			Confidence: &v1alpha1.ConfidenceMetadata{
				SampleCount: 500,
				DropRate:    0.0,
			},
		},
	}

	result := detector.EvaluateNetworkBehavior(ctx, rb, "8.8.8.8")

	if !result.IsAnomaly {
		t.Error("expected public network destination to be anomalous")
	}
}

func TestAnomalyDetector_EvaluateDNSBehavior_AllowedDomain(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rb",
			Namespace: "default",
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				DNS: []string{"api.example.com", "*.example.com"},
			},
		},
	}

	result := detector.EvaluateDNSBehavior(ctx, rb, "api.example.com")

	if result.IsAnomaly {
		t.Error("expected allowed DNS query to not be anomalous")
	}
}

func TestAnomalyDetector_EvaluateDNSBehavior_DisallowedDomain(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rb",
			Namespace: "default",
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				DNS: []string{"api.example.com"},
			},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{
			Lifecycle: v1alpha1.LifecycleCompleted,
			Confidence: &v1alpha1.ConfidenceMetadata{
				SampleCount: 200,
				DropRate:    0.01,
			},
		},
	}

	result := detector.EvaluateDNSBehavior(ctx, rb, "malicious.ngrok.io")

	if !result.IsAnomaly {
		t.Error("expected disallowed DNS query to be anomalous")
	}
}

func TestAnomalyDetector_MeetsConfidenceThreshold(t *testing.T) {
	detector := NewAnomalyDetector(0.6)

	tests := []struct {
		name     string
		result   *AnomalyDetectionResult
		expected bool
	}{
		{
			name: "anomaly above threshold",
			result: &AnomalyDetectionResult{
				IsAnomaly:  true,
				Confidence: 0.7,
			},
			expected: true,
		},
		{
			name: "anomaly below threshold",
			result: &AnomalyDetectionResult{
				IsAnomaly:  true,
				Confidence: 0.5,
			},
			expected: false,
		},
		{
			name: "not anomaly",
			result: &AnomalyDetectionResult{
				IsAnomaly:  false,
				Confidence: 0.8,
			},
			expected: false,
		},
		{
			name: "anomaly at threshold",
			result: &AnomalyDetectionResult{
				IsAnomaly:  true,
				Confidence: 0.6,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.MeetsConfidenceThreshold(tt.result)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAnomalyDetector_WithDenyRules(t *testing.T) {
	detector := NewAnomalyDetector(0.5)
	ctx := context.Background()

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rb",
			Namespace: "default",
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/bin/bash", "/bin/sh", "/usr/bin/python"},
				Deny: &v1alpha1.DenyRules{
					Exec: []string{"/bin/bash"}, // Explicitly deny bash even though it's in allow list
				},
			},
		},
	}

	result := detector.EvaluateExecBehavior(ctx, rb, "/bin/bash")

	if !result.IsAnomaly {
		t.Error("expected denied pattern to be anomalous even if in allow list")
	}
}
