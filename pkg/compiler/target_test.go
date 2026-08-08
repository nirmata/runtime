package compiler

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCompileTarget_AbsentSelectorsDifferByHalf(t *testing.T) {
	matchProd := &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}}
	matchApp := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}}

	prodNs := map[string]string{"tier": "prod"}
	devNs := map[string]string{"tier": "dev"}
	agentPod := map[string]string{"app": "agent"}
	otherPod := map[string]string{"app": "other"}

	tests := []struct {
		name     string
		podSel   *metav1.LabelSelector
		nsSel    *metav1.LabelSelector
		nsLabels map[string]string
		podLabel map[string]string
		want     bool
	}{
		// An omitted podSelector selects no pods, so nothing else can rescue it.
		{"no pod selector, no namespace selector", nil, nil, prodNs, agentPod, false},
		{"no pod selector, matching namespace selector", nil, matchProd, prodNs, agentPod, false},

		// An omitted namespaceSelector selects every namespace, which is what
		// keeps a policy written before the field existed working unchanged.
		{"pod selector only, matching pod", matchApp, nil, devNs, agentPod, true},
		{"pod selector only, non-matching pod", matchApp, nil, devNs, otherPod, false},
		{"pod selector only, no namespace labels at all", matchApp, nil, nil, agentPod, true},

		// An empty namespaceSelector is the same "every namespace" as an
		// omitted one, following LabelSelectorAsSelector.
		{"empty namespace selector", matchApp, &metav1.LabelSelector{}, devNs, agentPod, true},

		// Both halves are ANDed, and each half reads its own label set: a swap
		// of the two arguments flips one of these two rows.
		{"both match", matchApp, matchProd, prodNs, agentPod, true},
		{"namespace matches, pod does not", matchApp, matchProd, prodNs, otherPod, false},
		{"pod matches, namespace does not", matchApp, matchProd, devNs, agentPod, false},
		{"neither matches", matchApp, matchProd, devNs, otherPod, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := compileTarget(tt.podSel, tt.nsSel)
			if err != nil {
				t.Fatalf("compileTarget() unexpected error = %v", err)
			}
			if got := target.Matches(tt.nsLabels, tt.podLabel); got != tt.want {
				t.Errorf("Matches(%v, %v) = %v, want %v", tt.nsLabels, tt.podLabel, got, tt.want)
			}
		})
	}
}

// The zero value reaches a match loop when a delete event carries only a uid,
// and it must not be read as the "unset, so everything" that an absent
// namespaceSelector means.
func TestPodTarget_ZeroValueMatchesNothing(t *testing.T) {
	var zero PodTarget
	if zero.Matches(map[string]string{"tier": "prod"}, map[string]string{"app": "agent"}) {
		t.Error("the zero PodTarget must match nothing")
	}
	if zero.Matches(nil, nil) {
		t.Error("the zero PodTarget must match nothing, including empty label sets")
	}
}

// Namespaces are targeted by name through the label the API server sets on
// every namespace, which is why there is no separate name field.
func TestCompileTarget_NamespaceByWellKnownNameLabel(t *testing.T) {
	target, err := compileTarget(
		&metav1.LabelSelector{},
		&metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "kubernetes.io/metadata.name",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"payments", "checkout"},
			}},
		},
	)
	if err != nil {
		t.Fatalf("compileTarget() unexpected error = %v", err)
	}

	for _, ns := range []string{"payments", "checkout"} {
		if !target.Matches(map[string]string{"kubernetes.io/metadata.name": ns}, nil) {
			t.Errorf("namespace %q should be selected", ns)
		}
	}
	if target.Matches(map[string]string{"kubernetes.io/metadata.name": "default"}, nil) {
		t.Error("namespace \"default\" should not be selected")
	}
}
