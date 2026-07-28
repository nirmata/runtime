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
// +kubebuilder:validation:Enum=monitor;enforce;discover
type RuntimePolicyMode string

const (
	PolicyModeMonitor RuntimePolicyMode = "monitor"
	PolicyModeEnforce RuntimePolicyMode = "enforce"
	// PolicyModeDiscover observes and populates the AIInventory only: no
	// findings, no enforcement.
	PolicyModeDiscover RuntimePolicyMode = "discover"
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
// +kubebuilder:validation:XValidation:rule="(has(self.network) ? 1 : 0) + (has(self.exec) ? 1 : 0) + (has(self.open) ? 1 : 0) + (has(self.ai) ? 1 : 0) == 1",message="exactly one of network, exec, open, or ai must be specified"
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

	// AI defines AI traffic detection rules (LLM, MCP, A2A).
	// +optional
	AI *AIBehavior `json:"ai,omitempty"`
}

// AITrafficClass identifies a class of AI traffic.
// +kubebuilder:validation:Enum=llm;mcp;a2a
type AITrafficClass string

const (
	AIClassLLM AITrafficClass = "llm"
	AIClassMCP AITrafficClass = "mcp"
	AIClassA2A AITrafficClass = "a2a"
)

// AIBehavior defines detection rules for AI traffic classes.
//
// NOTE on modes: an AI behavior is honored in `discover` mode (inventory only)
// and `monitor` mode (findings only). `enforce` is NOT implemented for AI
// behaviors -- compelled routing is a later phase -- and the detection engine
// treats an `enforce` policy carrying an AI behavior as `monitor`, setting the
// policy condition `AIEnforcementImplemented=False`. Nothing is blocked.
type AIBehavior struct {
	// Classes restricts which traffic classes this rule considers.
	// Empty means all classes.
	// +optional
	Classes []AITrafficClass `json:"classes,omitempty"`

	// Allow and Deny use destination identities: hostname globs,
	// IPv4/CIDR, "provider:<name>" tokens resolved from the provider
	// catalog, or "mcp-server:<package>" for stdio servers. Values and
	// expression are unioned, same semantics as other behaviors.
	// +optional
	Allow *BehaviorRule `json:"allow,omitempty"`
	// +optional
	Deny *BehaviorRule `json:"deny,omitempty"`

	// Match is a CEL expression over the per-event `event` variable that
	// must evaluate to bool. Evaluated per detected AI event.
	// +optional
	Match string `json:"match,omitempty"`

	// MinConfidence gates findings by classifier confidence (0-100).
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	MinConfidence *int32 `json:"minConfidence,omitempty"`

	// Severity for emitted findings.
	// +kubebuilder:validation:Enum=info;low;medium;high;critical
	// +optional
	Severity string `json:"severity,omitempty"`
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
