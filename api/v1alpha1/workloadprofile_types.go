package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// WorkloadProfileSpec defines the specification of a workload profile
type WorkloadProfileSpec struct {
	BehaviorsToLearn []string         `json:"behaviorsToLearn,omitempty"`
	Duration         *metav1.Duration `json:"duration,omitempty"`
}

// WorkloadProfileStatus reflects the observed state of a workload profile.
type WorkloadProfileStatus struct {
	// +optional
	Ready bool `json:"ready,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=wp,scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

type WorkloadProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WorkloadProfileSpec   `json:"spec,omitempty"`
	Status WorkloadProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type WorkloadProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WorkloadProfile `json:"items"`
}

func (in *WorkloadProfile) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(WorkloadProfile)
	deepCopyViaJSON(in, out)
	return out
}

func (in *WorkloadProfileList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(WorkloadProfileList)
	deepCopyViaJSON(in, out)
	return out
}
