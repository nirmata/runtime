package policy

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	baselinepkg "github.com/nirmata/kyverno-runtime/pkg/baseline"
)

// AnomalyDetectionResult represents a detected deviation from the baseline.
type AnomalyDetectionResult struct {
	// Baseline is the RuntimeBehavior profile being evaluated against.
	Baseline *v1alpha1.RuntimeBehavior
	// IsAnomaly indicates if the behavior deviates from the baseline.
	IsAnomaly bool
	// Confidence is a score (0.0-1.0) indicating confidence in the anomaly detection.
	Confidence float64
	// BehaviorType is the category of observed behavior (exec, open, network, dns).
	BehaviorType string
	// ObservedValue is the specific behavior that triggered the anomaly.
	ObservedValue string
}

// AnomalyDetector detects deviations from learned behavioral baselines.
type AnomalyDetector struct {
	minConfidence float64 // Minimum confidence threshold (default 0.5)
}

// NewAnomalyDetector creates a new anomaly detection engine.
func NewAnomalyDetector(minConfidence float64) *AnomalyDetector {
	// Clamp to valid range [0.0, 1.0]
	if minConfidence < 0.0 {
		minConfidence = 0.0
	}
	if minConfidence > 1.0 {
		minConfidence = 1.0
	}
	return &AnomalyDetector{
		minConfidence: minConfidence,
	}
}

// EvaluateExecBehavior checks if an exec behavior deviates from a baseline.
func (ad *AnomalyDetector) EvaluateExecBehavior(ctx context.Context, rb *v1alpha1.RuntimeBehavior, pattern string) *AnomalyDetectionResult {
	logger := log.FromContext(ctx)

	result := &AnomalyDetectionResult{
		Baseline:      rb,
		BehaviorType:  "exec",
		ObservedValue: pattern,
		IsAnomaly:     false,
		Confidence:    0.0,
	}

	if rb == nil {
		logger.V(2).Info("no baseline provided, skipping anomaly detection")
		return result
	}

	// Merge all allow sources with proper precedence
	merged, denied := baselinepkg.MergeBehaviors(rb, nil)

	// Check if the pattern is allowed
	if !baselinepkg.IsAllowed(pattern, merged.Exec, denied.Exec) {
		result.IsAnomaly = true
		result.Confidence = ad.calculateConfidence(rb)
	}

	return result
}

// EvaluateOpenBehavior checks if a file open behavior deviates from a baseline.
func (ad *AnomalyDetector) EvaluateOpenBehavior(ctx context.Context, rb *v1alpha1.RuntimeBehavior, pattern string) *AnomalyDetectionResult {
	result := &AnomalyDetectionResult{
		Baseline:      rb,
		BehaviorType:  "open",
		ObservedValue: pattern,
		IsAnomaly:     false,
		Confidence:    0.0,
	}

	if rb == nil {
		return result
	}

	merged, denied := baselinepkg.MergeBehaviors(rb, nil)
	if !baselinepkg.IsAllowed(pattern, merged.Open, denied.Open) {
		result.IsAnomaly = true
		result.Confidence = ad.calculateConfidence(rb)
	}

	return result
}

// EvaluateNetworkBehavior checks if a network behavior deviates from a baseline.
func (ad *AnomalyDetector) EvaluateNetworkBehavior(ctx context.Context, rb *v1alpha1.RuntimeBehavior, destination string) *AnomalyDetectionResult {
	result := &AnomalyDetectionResult{
		Baseline:      rb,
		BehaviorType:  "network",
		ObservedValue: destination,
		IsAnomaly:     false,
		Confidence:    0.0,
	}

	if rb == nil {
		return result
	}

	merged, denied := baselinepkg.MergeBehaviors(rb, nil)
	if !baselinepkg.IsAllowed(destination, merged.Network, denied.Network) {
		result.IsAnomaly = true
		result.Confidence = ad.calculateConfidence(rb)
	}

	return result
}

// EvaluateDNSBehavior checks if a DNS query deviates from a baseline.
func (ad *AnomalyDetector) EvaluateDNSBehavior(ctx context.Context, rb *v1alpha1.RuntimeBehavior, domain string) *AnomalyDetectionResult {
	result := &AnomalyDetectionResult{
		Baseline:      rb,
		BehaviorType:  "dns",
		ObservedValue: domain,
		IsAnomaly:     false,
		Confidence:    0.0,
	}

	if rb == nil {
		return result
	}

	merged, denied := baselinepkg.MergeBehaviors(rb, nil)
	if !baselinepkg.IsAllowed(domain, merged.DNS, denied.DNS) {
		result.IsAnomaly = true
		result.Confidence = ad.calculateConfidence(rb)
	}

	return result
}

// calculateConfidence computes confidence in anomaly detection based on baseline quality.
func (ad *AnomalyDetector) calculateConfidence(rb *v1alpha1.RuntimeBehavior) float64 {
	if rb.Status.Confidence == nil {
		return 0.5 // Default confidence if no confidence data
	}

	// Base confidence from sample count and drop rate
	confidence := 0.5

	// More samples = higher confidence
	if rb.Status.Confidence.SampleCount > 1000 {
		confidence += 0.3
	} else if rb.Status.Confidence.SampleCount > 100 {
		confidence += 0.2
	} else if rb.Status.Confidence.SampleCount > 10 {
		confidence += 0.1
	}

	// Lower drop rate = higher confidence
	dropRate := rb.Status.Confidence.DropRate
	if dropRate < 0.001 {
		confidence += 0.2
	} else if dropRate < 0.01 {
		confidence += 0.1
	}

	// Baseline lifecycle affects confidence
	if rb.Status.Lifecycle == v1alpha1.LifecycleCompleted {
		confidence += 0.1
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// MeetsConfidenceThreshold checks if the anomaly detection result meets the minimum confidence.
func (ad *AnomalyDetector) MeetsConfidenceThreshold(result *AnomalyDetectionResult) bool {
	return result.IsAnomaly && result.Confidence >= ad.minConfidence
}
