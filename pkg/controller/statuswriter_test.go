package controller

import (
	"context"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	fakeversioned "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned/fake"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
)

var fixedNow = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

func newTestStatusWriter(t *testing.T, nodeName string, objs ...runtime.Object) (*StatusWriter, *fakeversioned.Clientset) {
	t.Helper()
	client := fakeversioned.NewSimpleClientset(objs...)
	sw := NewStatusWriter(client, nodeName, time.Hour, logr.Discard())
	sw.clock = func() time.Time { return fixedNow }
	return sw, client
}

func policyObj(name, uid string) *v1alpha1.RuntimePolicy {
	return &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)},
	}
}

func evalResult(uid, name, mode string, sel labels.Selector) *compiler.EvaluationResult {
	return &compiler.EvaluationResult{UID: uid, Name: name, Mode: mode, Selector: sel}
}

func selectorFor(t *testing.T, kv map[string]string) labels.Selector {
	t.Helper()
	sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: kv})
	if err != nil {
		t.Fatal(err)
	}
	return sel
}

func labeledPod(ns, name, uid string, podLabels map[string]string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID(uid), Labels: podLabels,
		},
	}
}

func getPolicy(t *testing.T, c *fakeversioned.Clientset, name string) *v1alpha1.RuntimePolicy {
	t.Helper()
	got, err := c.RuntimeV1alpha1().RuntimePolicies().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting policy %s: %v", name, err)
	}
	return got
}

// TestStatusWriterImplementsBothInterfaces documents the two seams the daemon
// wires the StatusWriter into: the event fan-out and the recorder handed to the
// managers and sinks.
func TestStatusWriterImplementsBothInterfaces(t *testing.T) {
	sel := selectorFor(t, map[string]string{"app": "web"})
	sw, client := newTestStatusWriter(t, "node-1", policyObj("p", "uid-p"))

	// Exercise the StatusWriter through each seam rather than nil-checking it:
	// the assignments below are the compile-time proof, and the calls prove the
	// daemon's entry points reach the same instance.
	var podHandler events.PodEventHandler = sw
	var rpHandler events.RuntimePolicyEventHandler = sw
	var recorder runtimeevent.PolicyStatusRecorder = sw

	if err := rpHandler.RuntimePolicyEvent(evalResult("uid-p", "p", compiler.ModeMonitor, sel), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent via events.RuntimePolicyEventHandler: %v", err)
	}
	if err := podHandler.PodEvent(labeledPod("ns", "a", "pod-a", map[string]string{"app": "web"}), nil, events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent via events.PodEventHandler: %v", err)
	}
	recorder.RecordViolation("uid-p", "pod-a")

	if err := sw.Flush(t.Context()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := getPolicy(t, client, "p").Status.ViolatingPods; got != 1 {
		t.Errorf("violation recorded through the recorder seam did not reach status: got %d, want 1", got)
	}
}

func TestStatusWriterWritesOwnNodeShardAndSums(t *testing.T) {
	sel := selectorFor(t, map[string]string{"app": "web"})
	sw, client := newTestStatusWriter(t, "node-b", policyObj("p", "uid-1"))

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, sel), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	// two matching pods, one that does not match
	for _, p := range []corev1.Pod{
		labeledPod("ns", "a", "pod-a", map[string]string{"app": "web"}),
		labeledPod("ns", "b", "pod-b", map[string]string{"app": "web"}),
		labeledPod("ns", "c", "pod-c", map[string]string{"app": "other"}),
	} {
		if err := sw.PodEvent(p, nil, events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
	}
	sw.RecordViolation("uid-1", "pod-a")

	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := getPolicy(t, client, "p")
	wantNodes := []v1alpha1.NodePolicyStatus{{
		NodeName:          "node-b",
		ObservedPods:      2,
		ViolatingPods:     1,
		LastEvaluatedTime: ptrTime(fixedNow),
	}}
	if diff := cmp.Diff(wantNodes, got.Status.Nodes); diff != "" {
		t.Errorf("status.nodes mismatch (-want +got):\n%s", diff)
	}
	if got.Status.ObservedPods != 2 || got.Status.ViolatingPods != 1 {
		t.Errorf("scalars = (%d, %d), want (2, 1)", got.Status.ObservedPods, got.Status.ViolatingPods)
	}
	if got.Status.LastEvaluatedTime == nil || !got.Status.LastEvaluatedTime.Time.Equal(fixedNow) {
		t.Errorf("lastEvaluatedTime = %v, want %v", got.Status.LastEvaluatedTime, fixedNow)
	}
}

// TestStatusWriterReplacesOnlyOwnNodeShard is the DaemonSet-contention case:
// every node writes the same cluster-scoped object, so a flush must leave the
// other nodes' entries alone and recompute the scalars from the whole list.
func TestStatusWriterReplacesOnlyOwnNodeShard(t *testing.T) {
	other := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	existing := policyObj("p", "uid-1")
	existing.Status = v1alpha1.RuntimePolicyStatus{
		ObservedPods:      7,
		ViolatingPods:     3,
		LastEvaluatedTime: ptrTime(other),
		Nodes: []v1alpha1.NodePolicyStatus{
			{NodeName: "node-a", ObservedPods: 4, ViolatingPods: 1, LastEvaluatedTime: ptrTime(other)},
			{NodeName: "node-b", ObservedPods: 3, ViolatingPods: 2, LastEvaluatedTime: ptrTime(other)},
			{NodeName: "node-c", ObservedPods: 0, ViolatingPods: 0, LastEvaluatedTime: ptrTime(other)},
		},
	}

	sel := selectorFor(t, map[string]string{"app": "web"})
	sw, client := newTestStatusWriter(t, "node-b", existing)

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, sel), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.PodEvent(labeledPod("ns", "x", "pod-x", map[string]string{"app": "web"}), nil, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := getPolicy(t, client, "p")
	want := []v1alpha1.NodePolicyStatus{
		{NodeName: "node-a", ObservedPods: 4, ViolatingPods: 1, LastEvaluatedTime: ptrTime(other)},
		{NodeName: "node-b", ObservedPods: 1, ViolatingPods: 0, LastEvaluatedTime: ptrTime(fixedNow)},
		{NodeName: "node-c", ObservedPods: 0, ViolatingPods: 0, LastEvaluatedTime: ptrTime(other)},
	}
	if diff := cmp.Diff(want, got.Status.Nodes); diff != "" {
		t.Errorf("status.nodes mismatch (-want +got):\n%s", diff)
	}
	// 4 + 1 + 0 observed, 1 + 0 + 0 violating
	if got.Status.ObservedPods != 5 {
		t.Errorf("observedPods = %d, want 5 (recomputed across all shards)", got.Status.ObservedPods)
	}
	if got.Status.ViolatingPods != 1 {
		t.Errorf("violatingPods = %d, want 1 (recomputed across all shards)", got.Status.ViolatingPods)
	}
	if got.Status.LastEvaluatedTime == nil || !got.Status.LastEvaluatedTime.Time.Equal(fixedNow) {
		t.Errorf("lastEvaluatedTime = %v, want the newest shard time %v", got.Status.LastEvaluatedTime, fixedNow)
	}
}

// TestStatusWriterInsertsNodeShardInSortedOrder keeps the list stable so
// concurrent writers do not reorder each other's entries.
func TestStatusWriterInsertsNodeShardInSortedOrder(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		nodeName string
		want     []string
	}{
		{name: "empty", existing: nil, nodeName: "node-b", want: []string{"node-b"}},
		{name: "before all", existing: []string{"node-b", "node-c"}, nodeName: "node-a", want: []string{"node-a", "node-b", "node-c"}},
		{name: "middle", existing: []string{"node-a", "node-c"}, nodeName: "node-b", want: []string{"node-a", "node-b", "node-c"}},
		{name: "after all", existing: []string{"node-a", "node-b"}, nodeName: "node-c", want: []string{"node-a", "node-b", "node-c"}},
		{name: "replace existing", existing: []string{"node-a", "node-b"}, nodeName: "node-b", want: []string{"node-a", "node-b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := &v1alpha1.RuntimePolicyStatus{}
			for _, n := range tc.existing {
				status.Nodes = append(status.Nodes, v1alpha1.NodePolicyStatus{NodeName: n})
			}
			setNodeShard(status, v1alpha1.NodePolicyStatus{NodeName: tc.nodeName, ObservedPods: 9})

			var got []string
			for _, n := range status.Nodes {
				got = append(got, n.NodeName)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("node order mismatch (-want +got):\n%s", diff)
			}
			for _, n := range status.Nodes {
				if n.NodeName == tc.nodeName && n.ObservedPods != 9 {
					t.Errorf("the shard for %s was not written: %+v", tc.nodeName, n)
				}
			}
		})
	}
}

func TestStatusWriterMergesConditions(t *testing.T) {
	existing := policyObj("p", "uid-1")
	existing.Status.Conditions = []metav1.Condition{{
		Type:               "SomeOtherControllerSaysSo",
		Status:             metav1.ConditionTrue,
		Reason:             "Whatever",
		LastTransitionTime: metav1.NewTime(fixedNow.Add(-time.Hour)),
	}}
	sw, client := newTestStatusWriter(t, "node-a", existing)

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeMonitor, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	sw.RecordCondition("uid-1", metav1.Condition{
		Type:    "TargetsValid",
		Status:  metav1.ConditionFalse,
		Reason:  "UnsupportedTargets",
		Message: "1 target cannot be programmed",
	})
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := getPolicy(t, client, "p")
	byType := map[string]metav1.Condition{}
	for _, c := range got.Status.Conditions {
		byType[c.Type] = c
	}
	if len(byType) != 3 {
		t.Fatalf("conditions = %+v, want the pre-existing one plus Applied and TargetsValid", got.Status.Conditions)
	}
	if _, ok := byType["SomeOtherControllerSaysSo"]; !ok {
		t.Error("the pre-existing condition was dropped instead of merged")
	}
	applied := byType[ConditionApplied]
	if applied.Status != metav1.ConditionTrue || applied.Reason != ReasonMonitoring {
		t.Errorf("Applied condition = (%s, %s), want (True, %s)", applied.Status, applied.Reason, ReasonMonitoring)
	}
	tv := byType["TargetsValid"]
	if tv.Status != metav1.ConditionFalse || tv.Reason != "UnsupportedTargets" {
		t.Errorf("TargetsValid condition = (%s, %s), want (False, UnsupportedTargets)", tv.Status, tv.Reason)
	}
	if tv.LastTransitionTime.IsZero() {
		t.Error("TargetsValid has no lastTransitionTime, which the API rejects")
	}
}

func TestStatusWriterAppliedReasonPerMode(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{mode: compiler.ModeEnforce, want: ReasonEnforcing},
		{mode: compiler.ModeMonitor, want: ReasonMonitoring},
		{mode: "", want: ReasonEnforcing},
		{mode: "something-new", want: ReasonEnforcing},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
			if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", tc.mode, labels.Everything()), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			if err := sw.Flush(context.Background()); err != nil {
				t.Fatalf("flush: %v", err)
			}
			got := getPolicy(t, client, "p")
			var reason string
			for _, c := range got.Status.Conditions {
				if c.Type == ConditionApplied {
					reason = c.Reason
				}
			}
			if reason != tc.want {
				t.Errorf("Applied reason for mode %q = %q, want %q", tc.mode, reason, tc.want)
			}
		})
	}
}

// TestStatusWriterRetriesOnConflict injects a conflict on the first update, the
// way another node's concurrent write would.
func TestStatusWriterRetriesOnConflict(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))

	var updates int
	client.PrependReactor("update", "runtimepolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		if updates == 1 {
			return true, nil, apierrors.NewConflict(
				action.GetResource().GroupResource(), "p", context.DeadlineExceeded)
		}
		return false, nil, nil
	})

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush should have retried the conflict: %v", err)
	}
	if updates < 2 {
		t.Fatalf("update was attempted %d times, want a retry after the conflict", updates)
	}
	got := getPolicy(t, client, "p")
	if len(got.Status.Nodes) != 1 {
		t.Errorf("status.nodes = %+v, want this node's shard written after the retry", got.Status.Nodes)
	}
}

// TestStatusWriterSkipsNoOpUpdates keeps every daemon in the DaemonSet from
// rewriting an identical status on every tick.
func TestStatusWriterSkipsNoOpUpdates(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))

	var updates int
	client.PrependReactor("update", "runtimepolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		return false, nil, nil
	})

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if updates != 1 {
		t.Fatalf("first flush issued %d updates, want 1", updates)
	}

	// nothing changed, and the item is clean, so no snapshot is even taken
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if updates != 1 {
		t.Errorf("second flush issued %d updates in total, want the no-op skipped", updates)
	}

	// force a re-flush of unchanged content: the diff check must still skip it
	sw.mu.Lock()
	sw.policies["uid-1"].dirty = true
	sw.mu.Unlock()
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if updates != 1 {
		t.Errorf("re-flushing identical content issued %d updates in total, want 1", updates)
	}
}

func TestStatusWriterRecordViolationIsIdempotent(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeMonitor, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		sw.RecordViolation("uid-1", "pod-a")
	}
	sw.RecordViolation("uid-1", "pod-b")
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := getPolicy(t, client, "p")
	if got.Status.ViolatingPods != 2 {
		t.Errorf("violatingPods = %d, want 2 distinct pods", got.Status.ViolatingPods)
	}
}

// TestStatusWriterRecordersToleratePolicyEventOrdering covers the concurrent
// fan-out: a manager can record a condition before the StatusWriter itself has
// seen the policy event, so the entry has to wait for its name rather than be
// dropped.
func TestStatusWriterRecordersToleratePolicyEventOrdering(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))

	sw.RecordCondition("uid-1", metav1.Condition{
		Type: "TargetsValid", Status: metav1.ConditionFalse, Reason: "UnsupportedTargets",
	})
	sw.RecordViolation("uid-1", "pod-a")

	// nothing can be written yet: the policy name is unknown
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := getPolicy(t, client, "p"); len(got.Status.Nodes) != 0 {
		t.Fatalf("status was written before the policy name was known: %+v", got.Status)
	}
	sw.mu.Lock()
	dirty := sw.policies["uid-1"].dirty
	sw.mu.Unlock()
	if !dirty {
		t.Fatal("the pending entry was marked clean, so its condition would be lost")
	}

	// the policy event arrives and the next flush writes everything
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeMonitor, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := getPolicy(t, client, "p")
	if got.Status.ViolatingPods != 1 {
		t.Errorf("violatingPods = %d, want the violation recorded before the policy event", got.Status.ViolatingPods)
	}
	var types []string
	for _, c := range got.Status.Conditions {
		types = append(types, c.Type)
	}
	if diff := cmp.Diff([]string{ConditionApplied, "TargetsValid"}, types, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Errorf("condition types mismatch (-want +got):\n%s", diff)
	}
}

func TestStatusWriterPodMatching(t *testing.T) {
	sel := selectorFor(t, map[string]string{"app": "web"})
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, sel), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	// a pod that does not match yet
	pod := labeledPod("ns", "a", "pod-a", map[string]string{"app": "batch"})
	if err := sw.PodEvent(pod, nil, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if got := sw.observedPods("uid-1"); got != 0 {
		t.Fatalf("observed = %d, want 0 for a non-matching pod", got)
	}

	// it gains the label
	pod.Labels = map[string]string{"app": "web"}
	if err := sw.PodEvent(pod, nil, events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	if got := sw.observedPods("uid-1"); got != 1 {
		t.Fatalf("observed = %d, want 1 after the label change", got)
	}
	sw.RecordViolation("uid-1", "pod-a")

	// and loses it again: the violation goes with it
	pod.Labels = map[string]string{"app": "batch"}
	if err := sw.PodEvent(pod, nil, events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	if got := sw.observedPods("uid-1"); got != 0 {
		t.Errorf("observed = %d, want 0 after the pod stopped matching", got)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := getPolicy(t, client, "p"); got.Status.ViolatingPods != 0 {
		t.Errorf("violatingPods = %d, want 0 once the pod no longer matches", got.Status.ViolatingPods)
	}
}

func TestStatusWriterPodDeleteRemovesFromEveryPolicy(t *testing.T) {
	sel := selectorFor(t, map[string]string{"app": "web"})
	sw, _ := newTestStatusWriter(t, "node-a", policyObj("p1", "uid-1"), policyObj("p2", "uid-2"))
	for _, res := range []*compiler.EvaluationResult{
		evalResult("uid-1", "p1", compiler.ModeEnforce, sel),
		evalResult("uid-2", "p2", compiler.ModeMonitor, sel),
	} {
		if err := sw.RuntimePolicyEvent(res, events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
	}
	pod := labeledPod("ns", "a", "pod-a", map[string]string{"app": "web"})
	if err := sw.PodEvent(pod, nil, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	sw.RecordViolation("uid-2", "pod-a")

	if err := sw.PodDeleted(string(pod.UID)); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"uid-1", "uid-2"} {
		if got := sw.observedPods(uid); got != 0 {
			t.Errorf("policy %s observed = %d, want 0 after the pod was deleted", uid, got)
		}
	}
}

// TestStatusWriterSelectorChangeRematchesCachedPods covers a policy update that
// narrows the selector: the matched set is recomputed from the pods this node
// already knows about, not just from future pod events.
func TestStatusWriterSelectorChangeRematchesCachedPods(t *testing.T) {
	sw, _ := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	for _, p := range []corev1.Pod{
		labeledPod("ns", "a", "pod-a", map[string]string{"app": "web"}),
		labeledPod("ns", "b", "pod-b", map[string]string{"app": "batch"}),
	} {
		if err := sw.PodEvent(p, nil, events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
	}
	if got := sw.observedPods("uid-1"); got != 2 {
		t.Fatalf("observed = %d, want 2 with an empty selector", got)
	}

	narrowed := selectorFor(t, map[string]string{"app": "web"})
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, narrowed), events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	if got := sw.observedPods("uid-1"); got != 1 {
		t.Errorf("observed = %d, want 1 after the selector narrowed", got)
	}
}

// TestStatusWriterNilSelectorMatchesNothing pins the safe default: a policy with
// no podSelector must never inflate observedPods.
func TestStatusWriterNilSelectorMatchesNothing(t *testing.T) {
	sw, _ := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.PodEvent(labeledPod("ns", "a", "pod-a", map[string]string{"app": "web"}), nil, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if got := sw.observedPods("uid-1"); got != 0 {
		t.Errorf("observed = %d, want 0 for a policy with no selector", got)
	}
}

func TestStatusWriterPolicyDeleteDropsState(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.RuntimePolicyEvent(&compiler.EvaluationResult{UID: "uid-1"}, events.EventTypeDelete); err != nil {
		t.Fatal(err)
	}

	sw.mu.Lock()
	_, tracked := sw.policies["uid-1"]
	sw.mu.Unlock()
	if tracked {
		t.Error("the deleted policy is still tracked")
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := getPolicy(t, client, "p"); len(got.Status.Nodes) != 0 {
		t.Errorf("status was written for a deleted policy: %+v", got.Status)
	}
}

// TestStatusWriterForgetsPoliciesThatNoLongerExist keeps a deleted policy from
// being retried forever.
func TestStatusWriterForgetsPoliciesThatNoLongerExist(t *testing.T) {
	sw, _ := newTestStatusWriter(t, "node-a")
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "gone", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("a missing policy must not be an error: %v", err)
	}
	sw.mu.Lock()
	_, tracked := sw.policies["uid-1"]
	sw.mu.Unlock()
	if tracked {
		t.Error("state was kept for a policy that no longer exists")
	}
}

// TestStatusWriterIgnoresRecreatedPolicyWithSameName guards the shard against
// being written onto a different object that happens to reuse the name.
func TestStatusWriterIgnoresRecreatedPolicyWithSameName(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-NEW"))
	if err := sw.RuntimePolicyEvent(evalResult("uid-OLD", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := getPolicy(t, client, "p"); len(got.Status.Nodes) != 0 {
		t.Errorf("a stale shard was written onto the recreated policy: %+v", got.Status)
	}
	sw.mu.Lock()
	_, tracked := sw.policies["uid-OLD"]
	sw.mu.Unlock()
	if tracked {
		t.Error("the stale policy state was not dropped")
	}
}

// TestStatusWriterFlushFailureKeepsItemDirty makes sure a failed write is
// retried on the next tick instead of being silently lost.
func TestStatusWriterFlushFailureKeepsItemDirty(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	client.PrependReactor("update", "runtimepolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewInternalError(context.Canceled)
	})

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.Flush(context.Background()); err == nil {
		t.Fatal("a failed status write must be reported")
	}
	sw.mu.Lock()
	dirty := sw.policies["uid-1"].dirty
	sw.mu.Unlock()
	if !dirty {
		t.Error("the policy was marked clean despite the write failing")
	}
}

// TestStatusWriterRunFlushesOnIntervalAndOnCancel covers the Run loop, both the
// ticker path and the final flush after cancellation.
func TestStatusWriterRunFlushesOnIntervalAndOnCancel(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	sw.interval = 5 * time.Millisecond

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sw.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for len(getPolicy(t, client, "p").Status.Nodes) != 1 {

		select {
		case <-deadline:
			t.Fatal("Run never flushed on the interval")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	// a change made just before cancellation must still land
	sw.RecordViolation("uid-1", "pod-a")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if got := getPolicy(t, client, "p"); got.Status.ViolatingPods != 1 {
		t.Errorf("violatingPods = %d, want the final flush to have written 1", got.Status.ViolatingPods)
	}
}

func TestRecomputeStatusSums(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	status := &v1alpha1.RuntimePolicyStatus{
		Nodes: []v1alpha1.NodePolicyStatus{
			{NodeName: "a", ObservedPods: 2, ViolatingPods: 1, LastEvaluatedTime: ptrTime(late)},
			{NodeName: "b", ObservedPods: 3, ViolatingPods: 0, LastEvaluatedTime: ptrTime(early)},
			{NodeName: "c", ObservedPods: 1, ViolatingPods: 4},
		},
	}
	recomputeStatusSums(status)
	if status.ObservedPods != 6 {
		t.Errorf("observedPods = %d, want 6", status.ObservedPods)
	}
	if status.ViolatingPods != 5 {
		t.Errorf("violatingPods = %d, want 5", status.ViolatingPods)
	}
	if status.LastEvaluatedTime == nil || !status.LastEvaluatedTime.Time.Equal(late) {
		t.Errorf("lastEvaluatedTime = %v, want the newest shard time %v", status.LastEvaluatedTime, late)
	}
}

func TestNewStatusWriterDefaultsInterval(t *testing.T) {
	sw := NewStatusWriter(fakeversioned.NewSimpleClientset(), "node-a", 0, logr.Discard())
	if sw.interval != DefaultStatusFlushInterval {
		t.Errorf("interval = %v, want the %v default", sw.interval, DefaultStatusFlushInterval)
	}
}

// observedPods is a test helper reading the tracked matched-pod count.
func (s *StatusWriter) observedPods(uid string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.policies[uid]
	if !ok {
		return 0
	}
	return len(st.matched)
}

func ptrTime(t time.Time) *metav1.Time {
	mt := metav1.NewTime(t)
	return &mt
}
