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
// +kubebuilder:validation:XValidation:rule="!(has(self.mode) && self.mode == 'enforce' && has(self.monitorFilter))",message="a monitorFilter narrows what a monitor-mode policy reports; an enforce-mode policy reports only operations the kernel actually denied, and those are never suppressed"
// +kubebuilder:validation:XValidation:rule="!(has(self.mode) && self.mode == 'enforce') || has(self.podSelector) || has(self.namespaceSelector)",message="an enforce-mode policy must state the pods it applies to: set spec.podSelector or spec.namespaceSelector, or set spec.podSelector to {} to enforce on every pod on the node"
type RuntimePolicySpec struct {
	// PodSelector identifies the pods this policy applies to. An empty selector
	// and an omitted field both match every pod on the node.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// NamespaceSelector narrows PodSelector to pods whose namespace carries
	// these labels. An empty selector and an omitted field both match every
	// namespace.
	//
	// Target namespaces by name through kubernetes.io/metadata.name, which the
	// API server sets on every namespace.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// EvaluationInterval specifies how frequently the policy is re-evaluated.
	// +optional
	EvaluationInterval *metav1.Duration `json:"evaluationInterval,omitempty"`

	// Variables defines custom variables that can be used in behavior expressions.
	// +optional
	Variables []admissionregistrationv1.Variable `json:"variables,omitempty"`

	// Behaviors defines the allowed and denied runtime behaviors.
	//
	// The bound is what keeps the per-item XValidation rule inside the CEL cost
	// budget: an unbounded list makes the API server multiply that rule's cost by
	// the largest number of items a request could carry, and the estimate then
	// exceeds the budget and the CRD is refused at apply time.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	Behaviors []PolicyBehavior `json:"behaviors,omitempty"`

	// Mode defines the operational mode of the policy.
	// +optional
	Mode *RuntimePolicyMode `json:"mode,omitempty"`

	// MonitorFilter narrows which findings a monitor-mode policy reports. It
	// selects what is observed into a finding, never what the kernel blocks.
	// +optional
	MonitorFilter *MonitorFilter `json:"monitorFilter,omitempty"`
}

// MonitorFilter selects which findings are reported. Expressions are ANDed and
// evaluated in order, short-circuiting on the first false. Each must evaluate
// to bool over the event variable.
type MonitorFilter struct {
	// Expressions each state a condition a finding must satisfy to be reported.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	Expressions []MonitorFilterExpression `json:"expressions"`
}

// MonitorFilterExpression is one named condition on a candidate finding.
type MonitorFilterExpression struct {
	// Name identifies this expression in compile errors, status conditions and
	// the eval-error metric. It is never emitted to a Report.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Expression is a CEL expression over the event variable that must evaluate
	// to bool. event.kind selects the arm that is populated: event.open.path,
	// event.exec.filename and .argv, event.net.destIP and .domain,
	// event.dns.qname, event.protocol.protocol and .alpn. Every event also
	// carries time, comm, pid, count, kernelDenied, wouldDeny, and pod.
	// +kubebuilder:validation:MinLength=1
	Expression string `json:"expression"`
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
// +kubebuilder:validation:XValidation:rule="(has(self.network) ? 1 : 0) + (has(self.exec) ? 1 : 0) + (has(self.open) ? 1 : 0) + (has(self.protocol) ? 1 : 0) + (has(self.dns) ? 1 : 0) == 1",message="exactly one of network, exec, open, protocol, or dns must be specified"
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

	// Protocol defines application protocol behavior rules, evaluated
	// against the first data segment of a connection.
	// +optional
	Protocol *Behavior `json:"protocol,omitempty"`

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

	// ConditionEnforcementAvailable reports a kernel map the runtime could not
	// program, so the policy's workloads run unenforced.
	ConditionEnforcementAvailable = "EnforcementAvailable"
	ReasonEnforcementUnavailable  = "EnforcementUnavailable"
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
