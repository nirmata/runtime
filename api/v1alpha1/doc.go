// Package v1alpha1 contains API Schema definitions for the runtime.nirmata.io API group.
// +kubebuilder:object:generate=true
// +groupName=runtime.nirmata.io
// +versionName=v1alpha1
package v1alpha1

// RuntimeSeverity represents the severity level of a runtime finding.
type RuntimeSeverity string

const (
	// SeverityError indicates a critical finding that should trigger enforcement.
	SeverityError RuntimeSeverity = "error"
	// SeverityWarning indicates a suspicious finding that warrants investigation.
	SeverityWarning RuntimeSeverity = "warning"
	// SeverityCritical indicates the most severe findings.
	SeverityCritical RuntimeSeverity = "critical"
)
