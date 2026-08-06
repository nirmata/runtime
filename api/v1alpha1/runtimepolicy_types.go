package v1alpha1

import (
	"encoding/json"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RuntimePolicySpec defines a runtime policy for enforcing or monitoring behaviors.
//
// The dns rule is enforced here rather than only at compile time so the API
// server refuses the object outright: a policy that was accepted and then
// reported an unapplied condition is a policy an author has to go looking for.
//
// +kubebuilder:validation:XValidation:rule="!(has(self.mode) && self.mode == 'enforce' && has(self.behaviors) && self.behaviors.exists(b, has(b.dns)))",message="a dns behavior reports the names a workload resolves, it does not block them: set spec.mode to \"monitor\", or express the destinations you want blocked as a network behavior, which enforces domain values"
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
}

// PolicyBehavior defines allow/deny rules for a specific behavior type.
// +kubebuilder:validation:XValidation:rule="(has(self.network) ? 1 : 0) + (has(self.exec) ? 1 : 0) + (has(self.open) ? 1 : 0) + (has(self.dns) ? 1 : 0) == 1",message="exactly one of network, exec, open, or dns must be specified"
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

	// DNS declares the DNS names a selected workload is expected to resolve.
	// It is observation only: it reports, it never blocks, so a policy carrying
	// a dns behavior must use mode monitor and is rejected in mode enforce.
	//
	// Allow is the expected set. Deny names specific unwanted names, and the
	// "*" sentinel in deny means "report every name", which is how an operator
	// discovers what a workload resolves before writing an allow list.
	// +optional
	DNS *Behavior `json:"dns,omitempty"`
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

// Condition types and reasons the daemons write onto a RuntimePolicy's status.
const (
	// ConditionApplied reports that a node's daemon has the policy loaded,
	// with the reason naming the mode it is running in.
	ConditionApplied = "Applied"
	ReasonEnforcing  = "Enforcing"
	ReasonMonitoring = "Monitoring"
	// ReasonNoMode reports a policy that sets no spec.mode, so no manager
	// attached anything for it.
	ReasonNoMode = "NoMode"
	// ReasonCompileFailed reports a policy whose spec the compiler rejected,
	// so nothing at all was programmed for it.
	ReasonCompileFailed = "CompileFailed"

	ConditionTargetsValid     = "TargetsValid"
	ReasonUnsupportedTargets  = "UnsupportedTargets"
	ReasonAllTargetsSupported = "AllTargetsSupported"
	ReasonNoTargets           = "NoTargets"
	// ReasonUnresolvedServices reports cluster DNS values whose Service or
	// endpoint is absent from cache, so no address could be programmed.
	ReasonUnresolvedServices = "UnresolvedServices"

	// Exec and open get a condition each because conditions are keyed by type
	// and last-write-wins: one shared type would report whichever behavior was
	// recorded last.
	ConditionExecRulesValid = "ExecRulesValid"
	ConditionOpenRulesValid = "OpenRulesValid"
	ReasonUnsupportedPaths  = "UnsupportedPaths"
	ReasonAllPathsSupported = "AllPathsSupported"
	ReasonNoPaths           = "NoPaths"

	ConditionObservationAvailable = "ObservationAvailable"
	ReasonObservationUnavailable  = "ObservationUnavailable"
)

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
