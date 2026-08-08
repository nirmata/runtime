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
// podSelector selects no pods, while an absent namespaceSelector selects every
// namespace, so only the pod half goes through LabelSelectorAsSelector's
// nil-means-nothing conversion.
func compileTarget(podSel, nsSel *metav1.LabelSelector) (PodTarget, error) {
	path := field.NewPath("spec")

	pod, err := metav1.LabelSelectorAsSelector(podSel)
	if err != nil {
		return PodTarget{}, field.Invalid(path.Child("podSelector"), podSel, err.Error())
	}
	ns := labels.Everything()
	if nsSel != nil {
		ns, err = metav1.LabelSelectorAsSelector(nsSel)
		if err != nil {
			return PodTarget{}, field.Invalid(path.Child("namespaceSelector"), nsSel, err.Error())
		}
	}
	return PodTarget{Pod: pod, Namespace: ns}, nil
}
