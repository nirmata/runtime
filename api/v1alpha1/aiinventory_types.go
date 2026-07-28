package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=aiinv,scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Workloads",type=integer,JSONPath=`.status.summary.workloads`
// +kubebuilder:printcolumn:name="Providers",type=string,JSONPath=`.status.summary.providers`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AIInventory is a cluster-scoped singleton (named "cluster") holding the
// observed AI usage inventory. Any node's daemon creates it on demand; each
// daemon writes only its own shard in status.nodes.
type AIInventory struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AIInventorySpec   `json:"spec,omitempty"`
	Status AIInventoryStatus `json:"status,omitempty"`
}

// AIInventorySpec is reserved for future configuration.
type AIInventorySpec struct{}

// AIInventoryStatus is the observed AI usage, sharded per node.
type AIInventoryStatus struct {
	// +optional
	Summary AIInventorySummary `json:"summary,omitempty"`

	// Nodes holds one shard per node, written only by that node's daemon.
	// +optional
	// +listType=map
	// +listMapKey=nodeName
	Nodes []AINodeInventory `json:"nodes,omitempty"`
}

// AIInventorySummary is the cluster-wide rollup across all node shards.
type AIInventorySummary struct {
	// +optional
	Workloads int32 `json:"workloads,omitempty"`

	// Providers is a comma-separated, deduplicated provider list.
	// +optional
	Providers string `json:"providers,omitempty"`
}

// AINodeInventory is one node's shard of the AI inventory.
type AINodeInventory struct {
	NodeName string `json:"nodeName"`

	// +optional
	UpdatedAt metav1.Time `json:"updatedAt,omitempty"`

	// DroppedEvents surfaces collector drops: silence must never read as safety.
	// +optional
	DroppedEvents int64 `json:"droppedEvents,omitempty"`

	// +optional
	Workloads []AIWorkloadInventory `json:"workloads,omitempty"`
}

// AIWorkloadInventory is the observed AI usage of a single workload.
type AIWorkloadInventory struct {
	Namespace string `json:"namespace"`

	// Kind is the owner kind, or "Pod" for a bare pod.
	Kind string `json:"kind"`

	Name string `json:"name"`

	// +optional
	Classes []string `json:"classes,omitempty"`

	// +optional
	Providers []string `json:"providers,omitempty"`

	// +optional
	EndpointKinds []string `json:"endpointKinds,omitempty"`

	// +optional
	Models []string `json:"models,omitempty"`

	// +optional
	Transports []string `json:"transports,omitempty"`

	// +optional
	EventCount int64 `json:"eventCount,omitempty"`

	// UngovernedCount counts events whose destination bypassed the
	// governance proxy (governed == false).
	// +optional
	UngovernedCount int64 `json:"ungovernedCount,omitempty"`

	// +optional
	FirstSeen metav1.Time `json:"firstSeen,omitempty"`

	// +optional
	LastSeen metav1.Time `json:"lastSeen,omitempty"`
}

// +kubebuilder:object:root=true

type AIInventoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AIInventory `json:"items"`
}

func (in *AIInventory) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AIInventory)
	deepCopyViaJSON(in, out)
	return out
}

func (in *AIInventoryList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AIInventoryList)
	deepCopyViaJSON(in, out)
	return out
}
