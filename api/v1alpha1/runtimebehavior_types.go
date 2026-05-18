package v1alpha1

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RuntimeBehaviorSpec describes the known-good runtime profile for a workload.
type RuntimeBehaviorSpec struct {
	// WorkloadSelector identifies the pod(s) this behavior profile applies to.
	// If omitted, this RuntimeBehavior acts as a shared defaults library.
	//
	// +optional
	WorkloadSelector *metav1.LabelSelector `json:"workloadSelector,omitempty"`

	// Mode controls how deviations are handled: learning, monitor, or enforce.
	// +kubebuilder:validation:Enum=learning;monitor;enforce
	Mode RuntimeBehaviorMode `json:"mode,omitempty"`

	// Learning configuration for auto-discovery of allowed behaviors.
	// +optional
	Learning *LearningConfig `json:"learning,omitempty"`

	// Allow defines inline allow rules and references to shared defaults.
	// +optional
	Allow *AllowRules `json:"allow,omitempty"`
}

// RuntimeBehaviorMode represents the operational mode.
// +kubebuilder:validation:Enum=learning;monitor;enforce
type RuntimeBehaviorMode string

const (
	ModeLearning RuntimeBehaviorMode = "learning"
	ModeMonitor  RuntimeBehaviorMode = "monitor"
	ModeEnforce  RuntimeBehaviorMode = "enforce"
)

// LearningConfig controls auto-learning parameters.
type LearningConfig struct {
	// Duration is how long to observe behaviors before auto-promoting to monitor mode.
	// +optional
	Duration *metav1.Duration `json:"duration,omitempty"`

	// MinSamples is the minimum number of events to observe before auto-promotion.
	// +optional
	MinSamples int32 `json:"minSamples,omitempty"`

	// StartAfter controls when observation begins.
	// "immediate" starts right away; "ready" waits for pod readiness.
	// +kubebuilder:validation:Enum=immediate;ready
	// +optional
	StartAfter StartAfterCondition `json:"startAfter,omitempty"`
}

// StartAfterCondition defines when learning begins relative to pod lifecycle.
// +kubebuilder:validation:Enum=immediate;ready
type StartAfterCondition string

const (
	StartAfterImmediate StartAfterCondition = "immediate"
	StartAfterReady     StartAfterCondition = "ready"
)

// AllowRules defines allowed runtime behaviors.
type AllowRules struct {
	// Inline allow rules specific to this workload.
	// +optional
	Exec    []string `json:"exec,omitempty"`
	Open    []string `json:"open,omitempty"`
	Network []string `json:"network,omitempty"`
	DNS     []string `json:"dns,omitempty"`

	// Refs references other RuntimeBehavior resources that serve as shared defaults.
	// +optional
	Refs []BehaviorReference `json:"refs,omitempty"`

	// shouldnt deny rules exist at the same fucking level ?
	// Deny rules that always block behaviors, overriding allow rules.
	// +optional
	Deny *DenyRules `json:"deny,omitempty"`
}

// BehaviorReference references another RuntimeBehavior resource.
type BehaviorReference struct {
	// Name of the referenced RuntimeBehavior.
	Name string `json:"name"`

	// Namespace of the referenced RuntimeBehavior.
	// Defaults to the same namespace as the referrer.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// DenyRules explicitly forbids specific behaviors.
type DenyRules struct {
	// +optional
	Exec    []string `json:"exec,omitempty"`
	Open    []string `json:"open,omitempty"`
	Network []string `json:"network,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

// RuntimeBehaviorStatus reflects the observed state and learning progress.
type RuntimeBehaviorStatus struct {
	// Lifecycle state: learning, partial, completed, stale, failed.
	// +optional
	Lifecycle RuntimeBehaviorLifecycle `json:"lifecycle,omitempty"`

	// Confidence metadata about the observed behaviors.
	// +optional
	Confidence *ConfidenceMetadata `json:"confidence,omitempty"`

	// Observed behaviors collected during learning.
	// +optional
	Observed *ObservedBehaviors `json:"observed,omitempty"`

	// LastTransitionTime tracks when the lifecycle state last changed.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
}

// RuntimeBehaviorLifecycle represents the state of the RuntimeBehavior.
// +kubebuilder:validation:Enum=learning;partial;completed;stale;failed
type RuntimeBehaviorLifecycle string

const (
	LifecycleLearning  RuntimeBehaviorLifecycle = "learning"
	LifecyclePartial   RuntimeBehaviorLifecycle = "partial"
	LifecycleCompleted RuntimeBehaviorLifecycle = "completed"
	LifecycleStale     RuntimeBehaviorLifecycle = "stale"
	LifecycleFailed    RuntimeBehaviorLifecycle = "failed"
)

// ConfidenceMetadata tracks the quality of observed behavior data.
type ConfidenceMetadata struct {
	// ObservedFrom is when observation started.
	// +optional
	ObservedFrom *metav1.Time `json:"observedFrom,omitempty"`

	// ObservedTo is the last time a behavior was observed.
	// +optional
	ObservedTo *metav1.Time `json:"observedTo,omitempty"`

	// SampleCount is the number of events observed.
	// +optional
	SampleCount int64 `json:"sampleCount,omitempty"`

	// DropRate is the fraction of events that were dropped (0.0 to 1.0).
	// +optional
	DropRate float64 `json:"dropRate,omitempty"`
}

// ObservedBehaviors holds the behaviors learned during the learning phase.
type ObservedBehaviors struct {
	// +optional
	Exec    []string `json:"exec,omitempty"`
	Open    []string `json:"open,omitempty"`
	Network []string `json:"network,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=rbe
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Lifecycle",type=string,JSONPath=`.status.lifecycle`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// RuntimeBehavior describes the known-good runtime profile for a workload.
type RuntimeBehavior struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RuntimeBehaviorSpec   `json:"spec,omitempty"`
	Status RuntimeBehaviorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RuntimeBehaviorList contains a list of RuntimeBehavior.
type RuntimeBehaviorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RuntimeBehavior `json:"items"`
}

func (in *RuntimeBehavior) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(RuntimeBehavior)
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, out)
	return out
}

func (in *RuntimeBehaviorList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(RuntimeBehaviorList)
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, out)
	return out
}
