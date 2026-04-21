package config

// FeatureGates controls experimental and future capabilities.
type FeatureGates struct {
	// BaselineEngine enables learning and monitoring runtime baselines
	// via RuntimeBehavior resources.
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

// DefaultFeatures returns feature gates with recommended defaults.
func DefaultFeatures() FeatureGates {
	return FeatureGates{
		BaselineEngine:   false,
		SignatureEngine:  false,
		AlertSinks:       false,
		AlertAggregation: false,
	}
}
