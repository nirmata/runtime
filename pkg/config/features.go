package config

// FeatureGates controls experimental and future capabilities.
type FeatureGates struct {
	// BaselineEngine enables learning and monitoring runtime baselines
	// via RuntimePolicy resources.
	BaselineEngine bool

	// SignatureEngine enables signature-based rule detection for known
	// attack patterns alongside anomaly detection.
	SignatureEngine bool

	// AlertSinks enables routing findings to external systems
	// (http, syslog, alertmanager, etc.).
	AlertSinks bool

	// AlertAggregation enables cross-rule aggregation and suppression
	// controls with cooldown and burst limits.
	AlertAggregation bool
}

// DefaultFeatures returns feature gates with recommended defaults for new installations.
// All core detection engines are enabled to provide comprehensive threat detection.
// Alert aggregation is enabled to prevent alert storms and resource exhaustion.
func DefaultFeatures() FeatureGates {
	return FeatureGates{
		BaselineEngine:   true,  // Learn and enforce workload behavioral baselines
		SignatureEngine:  true,  // Detect known attack patterns
		AlertSinks:       false, // Optional: advanced feature for external routing
		AlertAggregation: true,  // Prevent alert storms with cooldown/burst limits
	}
}
