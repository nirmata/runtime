package v1alpha1

import (
	"encoding/json"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type RuntimePolicySpec struct {
	// MatchConstraints specifies which resources this policy targets. Mirrors
	// the K8s ValidatingAdmissionPolicy matchConstraints field. The policy cares
	// about a resource only if it matches _all_ constraints.
	//
	// +optional
	MatchConstraints *admissionregistrationv1.MatchResources `json:"matchConstraints,omitempty"`

	// NamespaceSelector restricts which namespaces this policy applies to.
	// Deprecated in favour of matchConstraints.namespaceSelector.
	//
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	Monitor     MonitorSpec         `json:"monitor,omitempty"`
	Validations []RuntimeValidation `json:"validations,omitempty"`
}

// Validate returns an error if the spec is misconfigured.
// RuntimePolicy only supports targeting Pod resources; any matchConstraints
// resourceRules that reference other resource types are rejected.
func (s *RuntimePolicySpec) Validate() error {
	if s.MatchConstraints == nil {
		return nil
	}
	for i, rule := range s.MatchConstraints.ResourceRules {
		for _, group := range rule.APIGroups {
			if group != "" {
				return fmt.Errorf("matchConstraints.resourceRules[%d]: only the core API group (\"\") is supported, got %q", i, group)
			}
		}
		for _, resource := range rule.Resources {
			if resource != "pods" {
				return fmt.Errorf("matchConstraints.resourceRules[%d]: only \"pods\" is supported as a resource, got %q", i, resource)
			}
		}
	}
	return nil
}

type MonitorSpec struct {
	Parameters map[string]string `json:"parameters,omitempty"`
	SampleRate int               `json:"sampleRate,omitempty"`
}

// RuntimeValidation models a Kyverno ValidatingPolicy-like runtime check backed by CEL expressions.
type RuntimeValidation struct {
	Name            string                `json:"name"`
	Event           string                `json:"event,omitempty"`
	Message         string                `json:"message,omitempty"`
	Severity        string                `json:"severity,omitempty"`
	MatchConditions []RuntimeCELCondition `json:"matchConditions,omitempty"`
	Conditions      []RuntimeCELCondition `json:"conditions,omitempty"`
	Actions         []RuntimeActionRef    `json:"actions,omitempty"`
}

type RuntimeCELCondition struct {
	Name       string `json:"name,omitempty"`
	Expression string `json:"expression"`
}

type RuntimeActionRef struct {
	// Type specifies the action to take on policy violation.
	// +kubebuilder:validation:Enum=audit
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
}

type RuleFinding struct {
	RuleName  string            `json:"ruleName"`
	EventType string            `json:"eventType,omitempty"`
	Severity  string            `json:"severity,omitempty"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type ActionRecord struct {
	Type      string      `json:"type"`
	Message   string      `json:"message,omitempty"`
	Timestamp metav1.Time `json:"timestamp"`
}

type RuntimePolicyStatus struct {
	ObservedPods      int32        `json:"observedPods,omitempty"`
	ViolatingPods     int32        `json:"violatingPods,omitempty"`
	LastEvaluatedTime *metav1.Time `json:"lastEvaluatedTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=rpol,scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="ObservedPods",type=integer,JSONPath=`.status.observedPods`
// +kubebuilder:printcolumn:name="ViolatingPods",type=integer,JSONPath=`.status.violatingPods`
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
