package compiler

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// PodTarget is a policy's compiled answer to "does this policy apply to this
// pod": the namespace selector and the pod selector must both match.
//
// The zero value matches nothing. A selector that could not be built must
// never widen a policy's scope, so Matches treats a nil half as no match
// rather than as "unset, so everything".
type PodTarget struct {
	Pod       labels.Selector
	Namespace labels.Selector
}

func (t PodTarget) Matches(nsLabels, podLabels map[string]string) bool {
	if t.Pod == nil || t.Namespace == nil {
		return false
	}
	return t.Namespace.Matches(labels.Set(nsLabels)) && t.Pod.Matches(labels.Set(podLabels))
}

// compileTarget builds the target from the two spec selectors. An absent
// selector matches everything on either half, so neither goes through
// LabelSelectorAsSelector's nil-means-nothing conversion.
//
// Because absent is now the widest target rather than the narrowest, enforce
// mode requires one of the two to be named. RuntimePolicySpec carries the same
// rule so the API server refuses the object outright; this is the backstop for
// an object already stored when the CRD gained it, which no admission rule
// re-examines, and the two messages are meant to read identically.
func compileTarget(podSel, nsSel *metav1.LabelSelector, mode string) (PodTarget, error) {
	path := field.NewPath("spec")

	if mode == ModeEnforce && podSel == nil && nsSel == nil {
		return PodTarget{}, field.Required(path.Child("podSelector"), "an enforce-mode policy must state the pods it applies to: set spec.podSelector or spec.namespaceSelector, or set spec.podSelector to {} to enforce on every pod on the node")
	}

	pod, err := selectorOrEverything(podSel)
	if err != nil {
		return PodTarget{}, field.Invalid(path.Child("podSelector"), podSel, err.Error())
	}
	ns, err := selectorOrEverything(nsSel)
	if err != nil {
		return PodTarget{}, field.Invalid(path.Child("namespaceSelector"), nsSel, err.Error())
	}
	return PodTarget{Pod: pod, Namespace: ns}, nil
}

func selectorOrEverything(sel *metav1.LabelSelector) (labels.Selector, error) {
	if sel == nil {
		return labels.Everything(), nil
	}
	return metav1.LabelSelectorAsSelector(sel)
}
