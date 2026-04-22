package v1alpha1

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RuntimeRuleBindingSpec specifies how detection rules are applied to workloads.
type RuntimeRuleBindingSpec struct {
	// WorkloadSelector identifies the pods this binding applies to.
	// If omitted, the binding applies to all pods in the namespace.
	//
	// +optional
	WorkloadSelector *metav1.LabelSelector `json:"workloadSelector,omitempty"`

	// Rules specifies which rules are enabled for matching workloads.
	// If omitted, all rules are enabled (default-allow).
	//
	// +optional
	Rules RuleSelection `json:"rules,omitempty"`

	// Severity overrides the default severity for matching rules.
	// +kubebuilder:validation:Enum=info;warning;error;critical
	// +optional
	Severity RuntimeSeverity `json:"severity,omitempty"`

	// AnomalyDetection controls anomaly detection behavior.
	// +optional
	AnomalyDetection *AnomalyDetectionConfig `json:"anomalyDetection,omitempty"`

	// SignatureDetection controls signature-based detection behavior.
	// +optional
	SignatureDetection *SignatureDetectionConfig `json:"signatureDetection,omitempty"`
}

// RuleSelection specifies which rules are enabled or disabled.
type RuleSelection struct {
	// Include lists rule names/patterns to enable.
	// If empty, all rules are included (unless Exclude is specified).
	// Supports wildcards: "*", "prefix-*", "*-suffix".
	//
	// +optional
	Include []string `json:"include,omitempty"`

	// Exclude lists rule names/patterns to disable.
	// Takes precedence over Include.
	//
	// +optional
	Exclude []string `json:"exclude,omitempty"`
}

// RuntimeSeverity represents the severity level of a detection finding.
// +kubebuilder:validation:Enum=info;warning;error;critical
type RuntimeSeverity string

const (
	SeverityInfo     RuntimeSeverity = "info"
	SeverityWarning  RuntimeSeverity = "warning"
	SeverityError    RuntimeSeverity = "error"
	SeverityCritical RuntimeSeverity = "critical"
)

// AnomalyDetectionConfig controls anomaly detection from baselines.
type AnomalyDetectionConfig struct {
	// Enabled toggles anomaly detection for matching workloads.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// MinConfidence is the minimum confidence level (0.0-1.0) for anomaly alerts.
	// Lower values = more alerts, higher values = fewer but higher-confidence alerts.
	// Default: 0.5
	//
	// +optional
	MinConfidence *float64 `json:"minConfidence,omitempty"`

	// Baseline selects which RuntimeBehavior resource to use for anomaly detection.
	// If omitted, uses the default RuntimeBehavior for the workload.
	//
	// +optional
	Baseline *BaselineReference `json:"baseline,omitempty"`
}

// BaselineReference identifies a RuntimeBehavior resource to use for anomaly detection.
type BaselineReference struct {
	// Name of the RuntimeBehavior resource.
	Name string `json:"name"`

	// Namespace of the RuntimeBehavior resource.
	// Defaults to the same namespace as the RuntimeRuleBinding.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// SignatureDetectionConfig controls signature-based detection behavior.
type SignatureDetectionConfig struct {
	// Enabled toggles signature detection for matching workloads.
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Rules lists explicit signature rule IDs to enable.
	// If empty, all signature rules are enabled (default behavior).
	//
	// +optional
	Rules []string `json:"rules,omitempty"`
}

// RuntimeRuleBindingStatus reflects the observed state of the binding.
type RuntimeRuleBindingStatus struct {
	// MatchedWorkloads is the number of pods matching the selector.
	// +optional
	MatchedWorkloads int32 `json:"matchedWorkloads,omitempty"`

	// EnabledRules is the number of rules enabled by this binding.
	// +optional
	EnabledRules int32 `json:"enabledRules,omitempty"`

	// LastUpdateTime tracks when this binding was last processed.
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`

	// Conditions reflect the current state (e.g., "RulesLoaded", "WorkloadsMatched").
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=rrb
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Workloads",type=integer,JSONPath=`.status.matchedWorkloads`
// +kubebuilder:printcolumn:name="EnabledRules",type=integer,JSONPath=`.status.enabledRules`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// RuntimeRuleBinding maps detection rules to workloads.
type RuntimeRuleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RuntimeRuleBindingSpec   `json:"spec,omitempty"`
	Status RuntimeRuleBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RuntimeRuleBindingList contains a list of RuntimeRuleBinding.
type RuntimeRuleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RuntimeRuleBinding `json:"items"`
}

func (in *RuntimeRuleBinding) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(RuntimeRuleBinding)
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, out)
	return out
}

func (in *RuntimeRuleBindingList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(RuntimeRuleBindingList)
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, out)
	return out
}
