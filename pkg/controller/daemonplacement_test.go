package controller

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestDaemonPlacementIncludesPendingTargets keeps a new node visible before its
// daemon can report, without duplicating the scheduler's placement rules.
func TestDaemonPlacementIncludesPendingTargets(t *testing.T) {
	controller := true
	owned := func(node string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{
				Kind: "DaemonSet", Name: "runtime", UID: "runtime-uid", Controller: &controller,
			}}},
			Spec: corev1.PodSpec{NodeName: node},
		}
	}
	pending := owned("")
	pending.Spec.Affinity = targetNodeAffinity("node-b")
	unrelated := owned("node-c")
	unrelated.OwnerReferences[0].UID = "other-release"
	terminating := owned("node-c")
	now := metav1.NewTime(time.Unix(1, 0))
	terminating.DeletionTimestamp = &now
	failed := owned("node-c")
	failed.Status.Phase = corev1.PodFailed
	cases := []struct {
		name       string
		pods       []*corev1.Pod
		desired    int32
		observed   int64
		deleted    bool
		absentNode string
		want       ExpectedSourceNodes
	}{
		{name: "pending target", pods: []*corev1.Pod{pending, owned("node-a")}, desired: 2, observed: 2,
			want: ExpectedSourceNodes{Names: []string{"node-a", "node-b"}, Desired: 2, Synced: true}},
		{name: "controller has not created new pod", pods: []*corev1.Pod{owned("node-a")}, desired: 2, observed: 2,
			want: ExpectedSourceNodes{Names: []string{"node-a"}, Desired: 2, Synced: true}},
		{name: "generation unobserved", pods: []*corev1.Pod{owned("node-a")}, desired: 1, observed: 1,
			want: ExpectedSourceNodes{Names: []string{"node-a"}, Desired: 1}},
		{name: "rollout deduplicates", pods: []*corev1.Pod{owned("node-a"), owned("node-a"), unrelated, terminating, failed}, desired: 1, observed: 2,
			want: ExpectedSourceNodes{Names: []string{"node-a"}, Desired: 1, Synced: true}},
		{name: "deleted node", pods: []*corev1.Pod{owned("node-a"), pending}, absentNode: "node-b", desired: 1, observed: 2,
			want: ExpectedSourceNodes{Names: []string{"node-a"}, Desired: 1, Synced: true}},
		{name: "daemonset deleting", pods: []*corev1.Pod{owned("node-a")}, desired: 1, observed: 2, deleted: true,
			want: ExpectedSourceNodes{Names: []string{"node-a"}, Desired: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ds := &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{UID: "runtime-uid", Generation: 2},
				Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: tc.desired, ObservedGeneration: tc.observed},
			}
			if tc.deleted {
				ds.DeletionTimestamp = &now
			}
			got := daemonPlacementNodes(ds, tc.pods, func(name string) bool { return name != tc.absentNode })
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("placement mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDaemonPodTargetRejectsAmbiguousAffinity refuses to turn a general affinity
// expression into evidence that a particular node should have a daemon.
func TestDaemonPodTargetRejectsAmbiguousAffinity(t *testing.T) {
	ambiguous := targetNodeAffinity("node-a")
	ambiguous.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = append(
		ambiguous.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms,
		targetNodeAffinity("node-b").NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms...)
	cases := []struct {
		name string
		spec corev1.PodSpec
		want string
	}{
		{name: "bound node", spec: corev1.PodSpec{NodeName: "node-a", Affinity: ambiguous}, want: "node-a"},
		{name: "pending target", spec: corev1.PodSpec{Affinity: targetNodeAffinity("node-b")}, want: "node-b"},
		{name: "no affinity"},
		{name: "ambiguous target", spec: corev1.PodSpec{Affinity: ambiguous}},
		{name: "empty terms", spec: corev1.PodSpec{Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{},
		}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := daemonPodNodeName(&corev1.Pod{Spec: tc.spec}); got != tc.want {
				t.Fatalf("target = %q, want %q", got, tc.want)
			}
		})
	}
}

func targetNodeAffinity(name string) *corev1.Affinity {
	return &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{
				Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{name},
			}}}},
		},
	}}
}
