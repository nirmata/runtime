package v1alpha1

import (
	"encoding/json"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RuntimePolicySpec defines a runtime policy for enforcing or monitoring behaviors.
type RuntimePolicySpec struct {
	// PodSelector identifies the pods this policy applies to.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// EvaluationInterval specifies how frequently the policy is re-evaluated.
	// +optional
	EvaluationInterval *metav1.Duration `json:"evaluationInterval,omitempty"`

	// Variables defines custom variables that can be used in behavior expressions.
	// +optional
	Variables []admissionregistrationv1.Variable `json:"variables,omitempty"`

	// Behaviors defines the allowed and denied runtime behaviors.
	// +optional
	Behaviors []PolicyBehavior `json:"behaviors,omitempty"`

	// Mode defines the operational mode of the policy.
	// +optional
	Mode *RuntimePolicyMode `json:"mode,omitempty"`
}

// RuntimePolicyMode represents the operational mode for policy enforcement.
// +kubebuilder:validation:Enum=monitor;enforce
type RuntimePolicyMode string

const (
	PolicyModeMonitor RuntimePolicyMode = "monitor"
	PolicyModeEnforce RuntimePolicyMode = "enforce"
)

// BehaviorRule defines allow/deny rules with values and/or expressions.
type BehaviorRule struct {
	// Values is a list of allowed or denied items (IPs, commands, files, etc.).
	// +optional
	Values []string `json:"values,omitempty"`

	// Expression is a CEL expression that evaluates to a list of items.
	// +optional
	Expression string `json:"expression,omitempty"`

	// ServiceRefs names in-cluster Services whose addresses are resolved from
	// the API server. Only valid on a network behavior.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	ServiceRefs []ServiceReference `json:"serviceRefs,omitempty"`
}

// ServiceReference names one in-cluster Service. RuntimePolicy is cluster
// scoped, so the namespace is not implied by the policy's own metadata.
type ServiceReference struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
}

// PolicyBehavior defines allow/deny rules for a specific behavior type.
// +kubebuilder:validation:XValidation:rule="(has(self.network) ? 1 : 0) + (has(self.exec) ? 1 : 0) + (has(self.open) ? 1 : 0) == 1",message="exactly one of network, exec, or open must be specified"
// One rule per allow/deny arm rather than a conjunction per behavior: the API
// server's CEL cost estimator budgets each rule separately, and the combined
// form is estimated at 1.7x the per-rule budget, which rejects the whole CRD.
// +kubebuilder:validation:XValidation:rule="!has(self.exec) || !has(self.exec.allow) || !has(self.exec.allow.serviceRefs)",message="serviceRefs is only supported on a network behavior"
// +kubebuilder:validation:XValidation:rule="!has(self.exec) || !has(self.exec.deny) || !has(self.exec.deny.serviceRefs)",message="serviceRefs is only supported on a network behavior"
// +kubebuilder:validation:XValidation:rule="!has(self.open) || !has(self.open.allow) || !has(self.open.allow.serviceRefs)",message="serviceRefs is only supported on a network behavior"
// +kubebuilder:validation:XValidation:rule="!has(self.open) || !has(self.open.deny) || !has(self.open.deny.serviceRefs)",message="serviceRefs is only supported on a network behavior"
type PolicyBehavior struct {
	// Network defines network behavior rules.
	// +optional
	Network *Behavior `json:"network,omitempty"`

	// Exec defines command execution behavior rules.
	// +optional
	Exec *Behavior `json:"exec,omitempty"`

	// Open defines file open behavior rules.
	// +optional
	Open *Behavior `json:"open,omitempty"`
}

// Behavoior defines the allowed and denied entries of a given type.
type Behavior struct {
	// Allow specifies allowed network access.
	// +optional
	Allow *BehaviorRule `json:"allow,omitempty"`

	// Deny specifies denied network access.
	// +optional
	Deny *BehaviorRule `json:"deny,omitempty"`
}

// RuntimePolicyStatus reflects the observed state of the policy.
type RuntimePolicyStatus struct {
	// LastEvaluatedTime is the last time the policy was evaluated.
	// +optional
	LastEvaluatedTime *metav1.Time `json:"lastEvaluatedTime,omitempty"`

	// Nodes holds one per-node shard, each written only by that node's daemon.
	// +optional
	// +listType=map
	// +listMapKey=nodeName
	Nodes []NodePolicyStatus `json:"nodes,omitempty"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// NodePolicyStatus is one node's shard of a RuntimePolicy's status, written
// only by that node's daemon.
type NodePolicyStatus struct {
	NodeName string `json:"nodeName"`

	// +optional
	LastEvaluatedTime *metav1.Time `json:"lastEvaluatedTime,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=rpol,scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Applied",type=string,JSONPath=`.status.conditions[?(@.type=="Applied")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Applied")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

type RuntimePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RuntimePolicySpec   `json:"spec,omitempty"`
	Status RuntimePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type RuntimePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RuntimePolicy `json:"items"`
}

func (in *RuntimePolicy) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(RuntimePolicy)
	deepCopyViaJSON(in, out)
	return out
}

func (in *RuntimePolicyList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(RuntimePolicyList)
	deepCopyViaJSON(in, out)
	return out
}

func deepCopyViaJSON(in any, out any) {
	b, _ := json.Marshal(in)
	_ = json.Unmarshal(b, out)
}
