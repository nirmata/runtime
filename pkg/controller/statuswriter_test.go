package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/runtime/api/v1alpha1"
	fakeversioned "github.com/nirmata/runtime/pkg/client/clientset/versioned/fake"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	sw := NewStatusWriter(client, nodeName, time.Hour, logr.Discard(), nil, nil)
	sw.clock = func() time.Time { return fixedNow }
	return sw, client
}

func policyObj(name, uid string) *v1alpha1.RuntimePolicy {
	return &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)},
	}
}

func evalResult(uid, name, mode string, sel labels.Selector) *compiler.EvaluationResult {
	return &compiler.EvaluationResult{
		UID:       uid,
		Name:      name,
		Mode:      mode,
		AppliesTo: compiler.PodTarget{Pod: sel, Namespace: labels.Everything()},
	}
}

func selectorFor(t *testing.T, kv map[string]string) labels.Selector {
	t.Helper()
	sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: kv})
	if err != nil {
		t.Fatal(err)
	}
	return sel
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
func TestStatusWriterWritesOwnNodeShard(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-b", policyObj("p", "uid-1"))

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := getPolicy(t, client, "p")
	if len(got.Status.Nodes) != 1 {
		t.Fatalf("nodes = %+v, want exactly this node's shard", got.Status.Nodes)
	}
	if got.Status.Nodes[0].NodeName != "node-b" {
		t.Errorf("nodes[0].nodeName = %q, want node-b", got.Status.Nodes[0].NodeName)
	}
	if got.Status.Nodes[0].LastEvaluatedTime == nil {
		t.Error("nodes[0].lastEvaluatedTime is nil, want the flush timestamp")
	}
	if got.Status.LastEvaluatedTime == nil {
		t.Error("status.lastEvaluatedTime is nil, want it lifted from the shard")
	}
}

func TestStatusWriterReplacesOnlyOwnNodeShard(t *testing.T) {
	other := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	existing := policyObj("p", "uid-1")
	existing.Status = v1alpha1.RuntimePolicyStatus{
		LastEvaluatedTime: ptrTime(other),
		Nodes: []v1alpha1.NodePolicyStatus{
			{NodeName: "node-a", LastEvaluatedTime: ptrTime(other)},
			{NodeName: "node-b", LastEvaluatedTime: ptrTime(other)},
			{NodeName: "node-c", LastEvaluatedTime: ptrTime(other)},
		},
	}

	sel := selectorFor(t, map[string]string{"app": "web"})
	sw, client := newTestStatusWriter(t, "node-b", existing)

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, sel), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := getPolicy(t, client, "p")
	want := []v1alpha1.NodePolicyStatus{
		{NodeName: "node-a", LastEvaluatedTime: ptrTime(other)},
		{NodeName: "node-b", LastEvaluatedTime: ptrTime(fixedNow)},
		{NodeName: "node-c", LastEvaluatedTime: ptrTime(other)},
	}
	if diff := cmp.Diff(want, got.Status.Nodes); diff != "" {
		t.Errorf("status.nodes mismatch (-want +got):\n%s", diff)
	}
	// 4 + 1 + 0 observed, 1 + 0 + 0 violating
	if got.Status.LastEvaluatedTime == nil || !got.Status.LastEvaluatedTime.Time.Equal(fixedNow) {
		t.Errorf("lastEvaluatedTime = %v, want the newest shard time %v", got.Status.LastEvaluatedTime, fixedNow)
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
			setNodeShard(status, v1alpha1.NodePolicyStatus{NodeName: tc.nodeName, LastEvaluatedTime: ptrTime(fixedNow)})

			var got []string
			for _, n := range status.Nodes {
				got = append(got, n.NodeName)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("node order mismatch (-want +got):\n%s", diff)
			}
			for _, n := range status.Nodes {
				if n.NodeName == tc.nodeName && n.LastEvaluatedTime == nil {
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
	sw.RecordCondition("uid-1", "p", metav1.Condition{
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
	applied := byType[v1alpha1.ConditionApplied]
	if applied.Status != metav1.ConditionTrue || applied.Reason != v1alpha1.ReasonMonitoring {
		t.Errorf("Applied condition = (%s, %s), want (True, %s)", applied.Status, applied.Reason, v1alpha1.ReasonMonitoring)
	}
	tv := byType["TargetsValid"]
	if tv.Status != metav1.ConditionFalse || tv.Reason != "UnsupportedTargets" {
		t.Errorf("TargetsValid condition = (%s, %s), want (False, UnsupportedTargets)", tv.Status, tv.Reason)
	}
	if tv.LastTransitionTime.IsZero() {
		t.Error("TargetsValid has no lastTransitionTime, which the API rejects")
	}
}

// TestFlushNotifiesOnDerivedAppliedTransition pins the fix for the callback
// missing the far more common way Applied actually goes False: nothing ever
// calls RecordCondition with Type=Applied for an attachment failure, only with
// the EnforcementAvailable/ObservationAvailable gate that setClusterConditions
// derives Applied from during flush. The callback must still fire, carrying
// the derived Applied condition that was actually written.
func TestFlushNotifiesOnDerivedAppliedTransition(t *testing.T) {
	client := fakeversioned.NewSimpleClientset(policyObj("p", "uid-1"))
	var calls []metav1.Condition
	sw := NewStatusWriter(client, "node-a", time.Hour, logr.Discard(), nil,
		func(policyUID, policyName string, cond metav1.Condition) { calls = append(calls, cond) })
	sw.clock = func() time.Time { return fixedNow }

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	sw.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionEnforcementAvailable, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonEnforcementUnavailable,
		Message: "BPF-LSM is not active on this node",
	})
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var applied *metav1.Condition
	for i := range calls {
		if calls[i].Type == v1alpha1.ConditionApplied {
			applied = &calls[i]
		}
	}
	if applied == nil {
		t.Fatalf("callback calls = %+v, want a derived Applied condition among them", calls)
	}
	if applied.Status != metav1.ConditionFalse || applied.Reason != v1alpha1.ReasonEnforcementUnavailable {
		t.Errorf("Applied = (%s, %s), want (False, %s)", applied.Status, applied.Reason, v1alpha1.ReasonEnforcementUnavailable)
	}
}

// TestFlushDoesNotNotifyOnNoOpReflush covers the identical-status case a
// derived condition can hit that RecordCondition's own dedup never sees:
// flushing the same inputs twice must fire the callback only on the flush
// that actually changes what is persisted.
func TestFlushDoesNotNotifyOnNoOpReflush(t *testing.T) {
	client := fakeversioned.NewSimpleClientset(policyObj("p", "uid-1"))
	var calls int
	sw := NewStatusWriter(client, "node-a", time.Hour, logr.Discard(), nil,
		func(policyUID, policyName string, cond metav1.Condition) { calls++ })
	sw.clock = func() time.Time { return fixedNow }

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	sw.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionEnforcementAvailable, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonEnforcementUnavailable,
		Message: "BPF-LSM is not active on this node",
	})
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	firstFlushCalls := calls
	if firstFlushCalls == 0 {
		t.Fatal("first flush notified nothing; the rest of this test is vacuous")
	}

	// force a re-flush of the identical, already-persisted content
	sw.mu.Lock()
	sw.policies["uid-1"].dirty = true
	sw.mu.Unlock()
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if calls != firstFlushCalls {
		t.Errorf("re-flushing identical content notified %d more times, want 0 more", calls-firstFlushCalls)
	}
}

// TestFlushDoesNotNotifyAfterRestart guards the false-positive a hook on
// RecordCondition would manufacture: a fresh process starts with an empty
// in-memory condition cache, so re-deriving and re-recording a condition that
// is already persisted must not read as a change. Comparing against the
// object's actual persisted state (read fresh from the API every flush) is
// what makes this safe.
func TestFlushDoesNotNotifyAfterRestart(t *testing.T) {
	client := fakeversioned.NewSimpleClientset(policyObj("p", "uid-1"))
	warm := NewStatusWriter(client, "node-a", time.Hour, logr.Discard(), nil, nil)
	warm.clock = func() time.Time { return fixedNow }
	if err := warm.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	warm.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionEnforcementAvailable, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonEnforcementUnavailable,
		Message: "BPF-LSM is not active on this node",
	})
	if err := warm.Flush(context.Background()); err != nil {
		t.Fatalf("warm flush: %v", err)
	}

	// simulate a restart: a new StatusWriter, empty in-memory state, pointed
	// at the same already-persisted RuntimePolicy, re-deriving the identical
	// signals a manager would report again on startup.
	var calls int
	cold := NewStatusWriter(client, "node-a", time.Hour, logr.Discard(), nil,
		func(policyUID, policyName string, cond metav1.Condition) { calls++ })
	cold.clock = func() time.Time { return fixedNow }
	if err := cold.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	cold.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionEnforcementAvailable, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonEnforcementUnavailable,
		Message: "BPF-LSM is not active on this node",
	})
	if err := cold.Flush(context.Background()); err != nil {
		t.Fatalf("post-restart flush: %v", err)
	}
	if calls != 0 {
		t.Errorf("post-restart flush of already-persisted state notified %d times, want 0", calls)
	}
}

// TestFlushNotifiesOnExplicitTargetsValid covers the always-explicit
// condition type: TargetsValid never goes through cluster derivation, so this
// pins that the flush-path hook still catches it.
func TestFlushNotifiesOnExplicitTargetsValid(t *testing.T) {
	client := fakeversioned.NewSimpleClientset(policyObj("p", "uid-1"))
	var calls []metav1.Condition
	sw := NewStatusWriter(client, "node-a", time.Hour, logr.Discard(), nil,
		func(policyUID, policyName string, cond metav1.Condition) { calls = append(calls, cond) })
	sw.clock = func() time.Time { return fixedNow }

	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeMonitor, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	sw.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionTargetsValid, Status: metav1.ConditionFalse, Reason: "UnsupportedTargets",
		Message: "1 target cannot be programmed",
	})
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var found bool
	for _, c := range calls {
		if c.Type == v1alpha1.ConditionTargetsValid && c.Status == metav1.ConditionFalse {
			found = true
		}
	}
	if !found {
		t.Errorf("callback calls = %+v, want a False TargetsValid condition among them", calls)
	}
}

// TestRecordConditionWithNilCallback covers the default-off path: a
// StatusWriter built with no onConditionChanged must not panic through either
// RecordCondition or the flush it feeds.
func TestRecordConditionWithNilCallback(t *testing.T) {
	sw, _ := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	sw.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionEnforcementAvailable, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonEnforcementUnavailable,
	})
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// A policy with no spec.mode neither enforces nor reports, so Applied must not
// claim otherwise.
func TestStatusWriterAppliedReasonPerMode(t *testing.T) {
	tests := []struct {
		mode       string
		wantReason string
		wantStatus metav1.ConditionStatus
	}{
		{mode: compiler.ModeEnforce, wantReason: v1alpha1.ReasonEnforcing, wantStatus: metav1.ConditionTrue},
		{mode: compiler.ModeMonitor, wantReason: v1alpha1.ReasonMonitoring, wantStatus: metav1.ConditionTrue},
		{mode: "", wantReason: v1alpha1.ReasonNoMode, wantStatus: metav1.ConditionFalse},
		{mode: "something-new", wantReason: v1alpha1.ReasonEnforcing, wantStatus: metav1.ConditionTrue},
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
			var applied *metav1.Condition
			for i := range got.Status.Conditions {
				if got.Status.Conditions[i].Type == v1alpha1.ConditionApplied {
					applied = &got.Status.Conditions[i]
				}
			}
			if applied == nil {
				t.Fatalf("conditions = %+v, want Applied", got.Status.Conditions)
			}
			if applied.Reason != tc.wantReason || applied.Status != tc.wantStatus {
				t.Errorf("Applied for mode %q = (%s, %s), want (%s, %s)",
					tc.mode, applied.Status, applied.Reason, tc.wantStatus, tc.wantReason)
			}
			if applied.Message == "" {
				t.Error("Applied has no message")
			}
		})
	}
}

// TestStatusWriterAppliedDerivedFromAttachmentOutcome pins the fix for Applied
// being written from spec.mode alone: a manager (lsmmgr, egressmgr) reporting
// that attachment for the policy's mode actually failed on this node must
// downgrade Applied instead of leaving it at whatever the mode alone implies,
// and a later recovery must be reflected too.
func TestStatusWriterAppliedDerivedFromAttachmentOutcome(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		gateType   string
		gateReason string
	}{
		{name: "enforce mode gated by EnforcementAvailable", mode: compiler.ModeEnforce,
			gateType: v1alpha1.ConditionEnforcementAvailable, gateReason: v1alpha1.ReasonEnforcementUnavailable},
		{name: "monitor mode gated by ObservationAvailable", mode: compiler.ModeMonitor,
			gateType: v1alpha1.ConditionObservationAvailable, gateReason: v1alpha1.ReasonObservationUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
			if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", tc.mode, labels.Everything()), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			sw.RecordCondition("uid-1", "p", metav1.Condition{
				Type: tc.gateType, Status: metav1.ConditionFalse, Reason: tc.gateReason,
				Message: "attach failed: BPF-LSM is not active on this node",
			})
			if err := sw.Flush(context.Background()); err != nil {
				t.Fatalf("flush: %v", err)
			}

			got := getPolicy(t, client, "p")
			applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
			if applied.Status != metav1.ConditionFalse || applied.Reason != tc.gateReason {
				t.Errorf("Applied = (%s, %s), want (False, %s)", applied.Status, applied.Reason, tc.gateReason)
			}
			if applied.Message == "" {
				t.Error("Applied carries no message explaining the failure")
			}

			// the underlying cause clears and the manager reasserts success
			sw.RecordCondition("uid-1", "p", metav1.Condition{
				Type: tc.gateType, Status: metav1.ConditionTrue, Reason: "Recovered",
				Message: "attached",
			})
			if err := sw.Flush(context.Background()); err != nil {
				t.Fatalf("flush after recovery: %v", err)
			}
			got = getPolicy(t, client, "p")
			applied = conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
			if applied.Status != metav1.ConditionTrue {
				t.Errorf("Applied after recovery = %s, want True", applied.Status)
			}
		})
	}
}

// TestStatusWriterAppliedGatedByPodsMatched: a policy whose
// podSelector/namespaceSelector matches zero pods on this node must not read
// the same as one that is enforcing/observing something, even though its
// attachment itself succeeded.
func TestStatusWriterAppliedGatedByPodsMatched(t *testing.T) {
	tests := []struct {
		mode string
	}{
		{mode: compiler.ModeEnforce},
		{mode: compiler.ModeMonitor},
	}

	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
			if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", tc.mode, labels.Everything()), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			sw.RecordCondition("uid-1", "p", metav1.Condition{
				Type: v1alpha1.ConditionPodsMatched, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonNoMatchingPods,
				Message: "no pod on this node matches the policy's podSelector/namespaceSelector",
			})
			if err := sw.Flush(context.Background()); err != nil {
				t.Fatalf("flush: %v", err)
			}

			got := getPolicy(t, client, "p")
			applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
			if applied.Status != metav1.ConditionFalse || applied.Reason != v1alpha1.ReasonNoMatchingPods {
				t.Errorf("Applied = (%s, %s), want (False, %s)", applied.Status, applied.Reason, v1alpha1.ReasonNoMatchingPods)
			}
			if applied.Message == "" {
				t.Error("Applied carries no message explaining why nothing matched")
			}

			// a pod now matches and the manager reasserts it
			sw.RecordCondition("uid-1", "p", metav1.Condition{
				Type: v1alpha1.ConditionPodsMatched, Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonPodsMatched,
				Message: "1 pod(s) on this node match the policy",
			})
			if err := sw.Flush(context.Background()); err != nil {
				t.Fatalf("flush after a pod matches: %v", err)
			}
			got = getPolicy(t, client, "p")
			applied = conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
			if applied.Status != metav1.ConditionTrue {
				t.Errorf("Applied once a pod matches = %s, want True", applied.Status)
			}
		})
	}
}

// TestStatusWriterAppliedPrefersAttachmentFailureOverPodsMatched: when both
// gates are False at once, the attachment failure — the more actionable of
// the two — is what Applied's reason/message must carry, not PodsMatched.
func TestStatusWriterAppliedPrefersAttachmentFailureOverPodsMatched(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	sw.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionPodsMatched, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonNoMatchingPods,
	})
	sw.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionEnforcementAvailable, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonEnforcementUnavailable,
		Message: "BPF-LSM is not active on this node",
	})
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := getPolicy(t, client, "p")
	applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
	if applied.Status != metav1.ConditionFalse || applied.Reason != v1alpha1.ReasonEnforcementUnavailable {
		t.Errorf("Applied = (%s, %s), want (False, %s): the attachment failure must win over PodsMatched",
			applied.Status, applied.Reason, v1alpha1.ReasonEnforcementUnavailable)
	}
}

// TestStatusWriterAppliedIgnoresUnrelatedGate makes sure the derivation only
// looks at the condition that gates the policy's own mode: an enforce-mode
// policy must not be downgraded by an ObservationAvailable=False left over
// from, say, a monitor-mode policy that shares nothing but a uid collision in
// the test setup.
func TestStatusWriterAppliedIgnoresUnrelatedGate(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", compiler.ModeEnforce, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	sw.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionObservationAvailable, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonObservationUnavailable,
	})
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	got := getPolicy(t, client, "p")
	applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
	if applied.Status != metav1.ConditionTrue || applied.Reason != v1alpha1.ReasonEnforcing {
		t.Errorf("Applied = (%s, %s), want (True, %s): an enforce-mode policy is not gated by ObservationAvailable",
			applied.Status, applied.Reason, v1alpha1.ReasonEnforcing)
	}
}

func conditionOfType(t *testing.T, conds []metav1.Condition, condType string) metav1.Condition {
	t.Helper()
	for _, c := range conds {
		if c.Type == condType {
			return c
		}
	}
	t.Fatalf("no %s condition found (have %+v)", condType, conds)
	return metav1.Condition{}
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

// TestStatusWriterRecordersToleratePolicyEventOrdering covers the concurrent
// fan-out: a manager that knows only the uid can record a condition before the
// StatusWriter has seen the policy event, so the entry has to wait for its name
// rather than be dropped.
func TestStatusWriterRecordersToleratePolicyEventOrdering(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))

	sw.RecordCondition("uid-1", "", metav1.Condition{
		Type: "TargetsValid", Status: metav1.ConditionFalse, Reason: "UnsupportedTargets",
	})
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
	var types []string
	for _, c := range got.Status.Conditions {
		types = append(types, c.Type)
	}
	if diff := cmp.Diff([]string{v1alpha1.ConditionApplied, "TargetsValid"}, types, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Errorf("condition types mismatch (-want +got):\n%s", diff)
	}
}

// A supplied name makes the entry addressable straight away, which is what a
// policy that never compiles depends on: it produces no policy event at all.
func TestStatusWriterRecordedNameMakesConditionFlushable(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))

	sw.RecordCondition("uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionApplied, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonCompileFailed,
		Message: "spec.behaviors[0].network: Invalid value",
	})
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := getPolicy(t, client, "p")
	if !hasCondition(got.Status.Conditions, v1alpha1.ConditionApplied) {
		t.Fatalf("conditions = %+v, want Applied written without any policy event", got.Status.Conditions)
	}
	sw.mu.Lock()
	dirty := sw.policies["uid-1"].dirty
	sw.mu.Unlock()
	if dirty {
		t.Error("the entry is still dirty after a successful flush")
	}
}

// TestStatusWriterExplicitAppliedWinsOverDerivation guards the interaction
// between reportCompileFailure, which records Applied directly (it is the
// only place the offending field path and value reach the operator), and
// snapshot's own derivation of Applied: the two must never both land in the
// flushed condition list for the same event, with the explicit one kept.
// Repeated because snapshot iterates a map, whose order is randomized per
// run, so a single pass could miss a regression that only shows up under a
// particular iteration order.
func TestStatusWriterExplicitAppliedWinsOverDerivation(t *testing.T) {
	for i := range 30 {
		sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
		sw.RecordCondition("uid-1", "p", metav1.Condition{
			Type: v1alpha1.ConditionApplied, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonCompileFailed,
			Message: "spec.behaviors[0].network: Invalid value",
		})
		if err := sw.Flush(context.Background()); err != nil {
			t.Fatalf("iteration %d: flush: %v", i, err)
		}

		got := getPolicy(t, client, "p")
		var count int
		var applied metav1.Condition
		for _, c := range got.Status.Conditions {
			if c.Type == v1alpha1.ConditionApplied {
				count++
				applied = c
			}
		}
		if count != 1 {
			t.Fatalf("iteration %d: %d Applied conditions, want exactly 1 (have %+v)", i, count, got.Status.Conditions)
		}
		if applied.Reason != v1alpha1.ReasonCompileFailed || applied.Message == "" {
			t.Fatalf("iteration %d: Applied = %+v, want reason %s with its message intact", i, applied, v1alpha1.ReasonCompileFailed)
		}
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
	sw.RecordCondition("uid-1", "p", metav1.Condition{
		Type: "TargetsValid", Status: metav1.ConditionFalse, Reason: "UnsupportedTargets",
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	got := getPolicy(t, client, "p")
	if !hasCondition(got.Status.Conditions, "TargetsValid") {
		t.Errorf("conditions = %+v, want the final flush to have written TargetsValid", got.Status.Conditions)
	}
}

// recordAndFlush drives one node's daemon: a policy event, its conditions, and
// a flush, against the shared fake API the other writers also use.
func recordAndFlush(t *testing.T, sw *StatusWriter, mode string, conds ...metav1.Condition) {
	t.Helper()
	if err := sw.RuntimePolicyEvent(evalResult("uid-1", "p", mode, labels.Everything()), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	for _, c := range conds {
		sw.RecordCondition("uid-1", "p", c)
	}
	if err := sw.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func availabilityCondition(condType string, status metav1.ConditionStatus, message string) metav1.Condition {
	reason := v1alpha1.ReasonEnforcementAvailable
	switch {
	case condType == v1alpha1.ConditionEnforcementAvailable && status == metav1.ConditionFalse:
		reason = v1alpha1.ReasonEnforcementUnavailable
	case condType == v1alpha1.ConditionObservationAvailable && status == metav1.ConditionTrue:
		reason = v1alpha1.ReasonObservationAvailable
	case condType == v1alpha1.ConditionObservationAvailable && status == metav1.ConditionFalse:
		reason = v1alpha1.ReasonObservationUnavailable
	}
	return metav1.Condition{Type: condType, Status: status, Reason: reason, Message: message}
}

func podsMatchedCondition(status metav1.ConditionStatus) metav1.Condition {
	if status == metav1.ConditionTrue {
		return metav1.Condition{Type: v1alpha1.ConditionPodsMatched, Status: status,
			Reason: v1alpha1.ReasonPodsMatched, Message: "1 pod(s) on this node match the policy"}
	}
	return metav1.Condition{Type: v1alpha1.ConditionPodsMatched, Status: status,
		Reason: v1alpha1.ReasonNoMatchingPods, Message: "no pod on this node matches the policy's podSelector/namespaceSelector"}
}

func TestClusterConditionsUniformHealthyCluster(t *testing.T) {
	tests := []struct {
		mode          string
		gateType      string
		wantAppliedAs string
	}{
		{mode: compiler.ModeEnforce, gateType: v1alpha1.ConditionEnforcementAvailable, wantAppliedAs: v1alpha1.ReasonEnforcing},
		{mode: compiler.ModeMonitor, gateType: v1alpha1.ConditionObservationAvailable, wantAppliedAs: v1alpha1.ReasonMonitoring},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			swA, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
			swB := NewStatusWriter(client, "node-b", time.Hour, logr.Discard(), nil, nil)
			swB.clock = func() time.Time { return fixedNow }

			for _, sw := range []*StatusWriter{swA, swB} {
				recordAndFlush(t, sw, tc.mode,
					availabilityCondition(tc.gateType, metav1.ConditionTrue, "attached"),
					podsMatchedCondition(metav1.ConditionTrue))
			}

			got := getPolicy(t, client, "p")
			for _, condType := range []string{tc.gateType, v1alpha1.ConditionPodsMatched, v1alpha1.ConditionApplied} {
				c := conditionOfType(t, got.Status.Conditions, condType)
				if c.Status != metav1.ConditionTrue {
					t.Errorf("%s = (%s, %s), want True", condType, c.Status, c.Reason)
				}
			}
			applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
			if applied.Reason != tc.wantAppliedAs {
				t.Errorf("Applied reason = %s, want %s", applied.Reason, tc.wantAppliedAs)
			}
		})
	}
}

// TestClusterAvailabilityFalseWhenAnyNodeLacksIt: one incapable node leaves its
// workloads uncovered, so the cluster-scoped condition must say so no matter
// how many capable nodes also report.
func TestClusterAvailabilityFalseWhenAnyNodeLacksIt(t *testing.T) {
	tests := []struct {
		mode     string
		gateType string
		gateWhy  string
	}{
		{mode: compiler.ModeEnforce, gateType: v1alpha1.ConditionEnforcementAvailable, gateWhy: v1alpha1.ReasonEnforcementUnavailable},
		{mode: compiler.ModeMonitor, gateType: v1alpha1.ConditionObservationAvailable, gateWhy: v1alpha1.ReasonObservationUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			swA, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
			swB := NewStatusWriter(client, "node-b", time.Hour, logr.Discard(), nil, nil)
			swB.clock = func() time.Time { return fixedNow }

			recordAndFlush(t, swA, tc.mode,
				availabilityCondition(tc.gateType, metav1.ConditionTrue, "attached"),
				podsMatchedCondition(metav1.ConditionTrue))
			recordAndFlush(t, swB, tc.mode,
				availabilityCondition(tc.gateType, metav1.ConditionFalse, "BPF-LSM is not active on this node"))

			got := getPolicy(t, client, "p")
			gate := conditionOfType(t, got.Status.Conditions, tc.gateType)
			if gate.Status != metav1.ConditionFalse || gate.Reason != tc.gateWhy {
				t.Errorf("%s = (%s, %s), want (False, %s)", tc.gateType, gate.Status, gate.Reason, tc.gateWhy)
			}
			if !strings.Contains(gate.Message, "node-b: BPF-LSM is not active on this node") {
				t.Errorf("%s message = %q, want it to name node-b and its failure", tc.gateType, gate.Message)
			}
			applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
			if applied.Status != metav1.ConditionFalse || applied.Reason != tc.gateWhy {
				t.Errorf("Applied = (%s, %s), want (False, %s)", applied.Status, applied.Reason, tc.gateWhy)
			}
			// the healthy node still counts toward PodsMatched
			pods := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionPodsMatched)
			if pods.Status != metav1.ConditionTrue {
				t.Errorf("PodsMatched = %s, want True from node-a", pods.Status)
			}
		})
	}
}

// TestClusterConditionsSurviveHealthyNodeFlushingLast pins the fix for the
// last-write-wins flap: a healthy node's later flush recomputes the aggregate
// from every shard instead of overwriting the incapable node's answer.
func TestClusterConditionsSurviveHealthyNodeFlushingLast(t *testing.T) {
	swA, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	swB := NewStatusWriter(client, "node-b", time.Hour, logr.Discard(), nil, nil)
	swB.clock = func() time.Time { return fixedNow }

	recordAndFlush(t, swB, compiler.ModeEnforce,
		availabilityCondition(v1alpha1.ConditionEnforcementAvailable, metav1.ConditionFalse, "BPF-LSM is not active on this node"))
	recordAndFlush(t, swA, compiler.ModeEnforce,
		availabilityCondition(v1alpha1.ConditionEnforcementAvailable, metav1.ConditionTrue, "attached"),
		podsMatchedCondition(metav1.ConditionTrue))

	got := getPolicy(t, client, "p")
	gate := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionEnforcementAvailable)
	if gate.Status != metav1.ConditionFalse {
		t.Errorf("EnforcementAvailable after the healthy node flushed last = %s, want False", gate.Status)
	}
	applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
	if applied.Status != metav1.ConditionFalse || applied.Reason != v1alpha1.ReasonEnforcementUnavailable {
		t.Errorf("Applied = (%s, %s), want (False, %s)", applied.Status, applied.Reason, v1alpha1.ReasonEnforcementUnavailable)
	}
}

// TestClusterAppliedTrueDespiteUnmatchedNode: a node where the selector matches
// nothing reports its own PodsMatched=False, and that must not read as a broken
// policy at cluster scope while another node's matching pods are covered.
func TestClusterAppliedTrueDespiteUnmatchedNode(t *testing.T) {
	swA, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	swB := NewStatusWriter(client, "node-b", time.Hour, logr.Discard(), nil, nil)
	swB.clock = func() time.Time { return fixedNow }

	recordAndFlush(t, swA, compiler.ModeEnforce,
		availabilityCondition(v1alpha1.ConditionEnforcementAvailable, metav1.ConditionTrue, "attached"),
		podsMatchedCondition(metav1.ConditionTrue))
	recordAndFlush(t, swB, compiler.ModeEnforce,
		availabilityCondition(v1alpha1.ConditionEnforcementAvailable, metav1.ConditionTrue, "attached"),
		podsMatchedCondition(metav1.ConditionFalse))

	got := getPolicy(t, client, "p")
	pods := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionPodsMatched)
	if pods.Status != metav1.ConditionTrue {
		t.Errorf("PodsMatched = (%s, %s), want True while any node matches", pods.Status, pods.Reason)
	}
	applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
	if applied.Status != metav1.ConditionTrue || applied.Reason != v1alpha1.ReasonEnforcing {
		t.Errorf("Applied = (%s, %s), want (True, %s)", applied.Status, applied.Reason, v1alpha1.ReasonEnforcing)
	}
}

func TestClusterPodsMatchedFalseOnlyWhenNoNodeMatches(t *testing.T) {
	swA, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	swB := NewStatusWriter(client, "node-b", time.Hour, logr.Discard(), nil, nil)
	swB.clock = func() time.Time { return fixedNow }

	for _, sw := range []*StatusWriter{swA, swB} {
		recordAndFlush(t, sw, compiler.ModeEnforce,
			availabilityCondition(v1alpha1.ConditionEnforcementAvailable, metav1.ConditionTrue, "attached"),
			podsMatchedCondition(metav1.ConditionFalse))
	}

	got := getPolicy(t, client, "p")
	pods := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionPodsMatched)
	if pods.Status != metav1.ConditionFalse || pods.Reason != v1alpha1.ReasonNoMatchingPods {
		t.Errorf("PodsMatched = (%s, %s), want (False, %s)", pods.Status, pods.Reason, v1alpha1.ReasonNoMatchingPods)
	}
	applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
	if applied.Status != metav1.ConditionFalse || applied.Reason != v1alpha1.ReasonNoMatchingPods {
		t.Errorf("Applied = (%s, %s), want (False, %s)", applied.Status, applied.Reason, v1alpha1.ReasonNoMatchingPods)
	}
}

// TestNodeShardCarriesRecordedSignals checks the compact per-node fields the
// aggregation reads are actually written into this node's shard.
func TestNodeShardCarriesRecordedSignals(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	recordAndFlush(t, sw, compiler.ModeEnforce,
		availabilityCondition(v1alpha1.ConditionEnforcementAvailable, metav1.ConditionFalse, "BPF-LSM is not active on this node"),
		podsMatchedCondition(metav1.ConditionTrue))

	got := getPolicy(t, client, "p")
	if len(got.Status.Nodes) != 1 {
		t.Fatalf("nodes = %+v, want exactly this node's shard", got.Status.Nodes)
	}
	shard := got.Status.Nodes[0]
	if shard.EnforcementAvailable == nil || *shard.EnforcementAvailable {
		t.Errorf("shard.enforcementAvailable = %v, want false", shard.EnforcementAvailable)
	}
	if shard.ObservationAvailable != nil {
		t.Errorf("shard.observationAvailable = %v, want unset: nothing reported it", *shard.ObservationAvailable)
	}
	if shard.PodsMatched == nil || !*shard.PodsMatched {
		t.Errorf("shard.podsMatched = %v, want true", shard.PodsMatched)
	}
	if shard.Message != "BPF-LSM is not active on this node" {
		t.Errorf("shard.message = %q, want the unavailability message", shard.Message)
	}
}

func TestAggregateAvailability(t *testing.T) {
	value := func(n *v1alpha1.NodePolicyStatus) *bool { return n.EnforcementAvailable }
	now := metav1.NewTime(fixedNow)
	tests := []struct {
		name        string
		nodes       []v1alpha1.NodePolicyStatus
		wantOK      bool
		wantStatus  metav1.ConditionStatus
		wantMessage string
	}{
		{name: "no node reports", nodes: []v1alpha1.NodePolicyStatus{{NodeName: "a"}}, wantOK: false},
		{name: "all reporting nodes true",
			nodes: []v1alpha1.NodePolicyStatus{
				{NodeName: "a", EnforcementAvailable: ptrBool(true)},
				{NodeName: "b"},
			},
			wantOK: true, wantStatus: metav1.ConditionTrue,
			wantMessage: "available on all 1 reporting node(s)"},
		{name: "one node false",
			nodes: []v1alpha1.NodePolicyStatus{
				{NodeName: "a", EnforcementAvailable: ptrBool(true)},
				{NodeName: "b", EnforcementAvailable: ptrBool(false), Message: "BPF-LSM is not active on this node"},
			},
			wantOK: true, wantStatus: metav1.ConditionFalse,
			wantMessage: "unavailable on 1 of 2 reporting node(s): b: BPF-LSM is not active on this node"},
		{name: "failing node without a message",
			nodes: []v1alpha1.NodePolicyStatus{
				{NodeName: "b", EnforcementAvailable: ptrBool(false)},
			},
			wantOK: true, wantStatus: metav1.ConditionFalse,
			wantMessage: "unavailable on 1 of 1 reporting node(s): b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := aggregateAvailability(tc.nodes, now, v1alpha1.ConditionEnforcementAvailable,
				v1alpha1.ReasonEnforcementAvailable, v1alpha1.ReasonEnforcementUnavailable, value)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.Status != tc.wantStatus || got.Message != tc.wantMessage {
				t.Errorf("condition = (%s, %q), want (%s, %q)", got.Status, got.Message, tc.wantStatus, tc.wantMessage)
			}
		})
	}
}

// TestAggregateAvailabilityCapsNamedNodes keeps the condition message bounded
// on a large cluster where many nodes fail the same way.
func TestAggregateAvailabilityCapsNamedNodes(t *testing.T) {
	var nodes []v1alpha1.NodePolicyStatus
	for i := range 8 {
		nodes = append(nodes, v1alpha1.NodePolicyStatus{
			NodeName:             fmt.Sprintf("node-%d", i),
			EnforcementAvailable: ptrBool(false),
		})
	}
	got, ok := aggregateAvailability(nodes, metav1.NewTime(fixedNow), v1alpha1.ConditionEnforcementAvailable,
		v1alpha1.ReasonEnforcementAvailable, v1alpha1.ReasonEnforcementUnavailable,
		func(n *v1alpha1.NodePolicyStatus) *bool { return n.EnforcementAvailable })
	if !ok {
		t.Fatal("no condition produced")
	}
	if !strings.Contains(got.Message, "and 3 more") || strings.Contains(got.Message, "node-5") {
		t.Errorf("message = %q, want the node list capped at %d with a remainder count", got.Message, maxReportedNodes)
	}
}

func TestAggregatePodsMatched(t *testing.T) {
	now := metav1.NewTime(fixedNow)
	tests := []struct {
		name       string
		nodes      []v1alpha1.NodePolicyStatus
		wantOK     bool
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{name: "no node reports", nodes: []v1alpha1.NodePolicyStatus{{NodeName: "a"}}, wantOK: false},
		{name: "one node matches",
			nodes: []v1alpha1.NodePolicyStatus{
				{NodeName: "a", PodsMatched: ptrBool(true)},
				{NodeName: "b", PodsMatched: ptrBool(false)},
			},
			wantOK: true, wantStatus: metav1.ConditionTrue, wantReason: v1alpha1.ReasonPodsMatched},
		{name: "no node matches",
			nodes: []v1alpha1.NodePolicyStatus{
				{NodeName: "a", PodsMatched: ptrBool(false)},
				{NodeName: "b", PodsMatched: ptrBool(false)},
			},
			wantOK: true, wantStatus: metav1.ConditionFalse, wantReason: v1alpha1.ReasonNoMatchingPods},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := aggregatePodsMatched(tc.nodes, now)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.Status != tc.wantStatus || got.Reason != tc.wantReason {
				t.Errorf("condition = (%s, %s), want (%s, %s)", got.Status, got.Reason, tc.wantStatus, tc.wantReason)
			}
		})
	}
}

func ptrBool(v bool) *bool { return &v }

// TestFlushPrunesShardsOfDeletedNodes: a node that leaves the cluster must
// stop feeding the aggregate, or its last-known false would pin the
// cluster-scoped condition forever.
func TestFlushPrunesShardsOfDeletedNodes(t *testing.T) {
	existing := policyObj("p", "uid-1")
	existing.Status.Nodes = []v1alpha1.NodePolicyStatus{
		{NodeName: "node-b", EnforcementAvailable: ptrBool(true), PodsMatched: ptrBool(true)},
		{NodeName: "node-gone", EnforcementAvailable: ptrBool(false), Message: "BPF-LSM is not active on this node"},
	}
	sw, client := newTestStatusWriter(t, "node-a", existing)
	sw.nodeGone = func(name string) bool { return name == "node-gone" }

	recordAndFlush(t, sw, compiler.ModeEnforce,
		availabilityCondition(v1alpha1.ConditionEnforcementAvailable, metav1.ConditionTrue, "attached"),
		podsMatchedCondition(metav1.ConditionTrue))

	got := getPolicy(t, client, "p")
	var names []string
	for _, n := range got.Status.Nodes {
		names = append(names, n.NodeName)
	}
	if diff := cmp.Diff([]string{"node-a", "node-b"}, names); diff != "" {
		t.Errorf("shard node names mismatch (-want +got):\n%s", diff)
	}
	gate := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionEnforcementAvailable)
	if gate.Status != metav1.ConditionTrue {
		t.Errorf("EnforcementAvailable = (%s, %q), want True once the deleted node's shard is gone", gate.Status, gate.Message)
	}
}

// TestFlushNeverPrunesOwnShard: the flush rewriting this node's shard is proof
// the node is alive, whatever the node watch currently claims.
func TestFlushNeverPrunesOwnShard(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	sw.nodeGone = func(string) bool { return true }

	recordAndFlush(t, sw, compiler.ModeEnforce,
		podsMatchedCondition(metav1.ConditionTrue))

	got := getPolicy(t, client, "p")
	if len(got.Status.Nodes) != 1 || got.Status.Nodes[0].NodeName != "node-a" {
		t.Errorf("nodes = %+v, want exactly this node's shard kept", got.Status.Nodes)
	}
}

// TestClusterConditionsRemovedWhenNoShardReports: a condition no shard backs
// is removed instead of left at whatever an older writer put there.
func TestClusterConditionsRemovedWhenNoShardReports(t *testing.T) {
	existing := policyObj("p", "uid-1")
	existing.Status.Conditions = []metav1.Condition{
		{Type: v1alpha1.ConditionEnforcementAvailable, Status: metav1.ConditionFalse,
			Reason: v1alpha1.ReasonEnforcementUnavailable, LastTransitionTime: metav1.NewTime(fixedNow.Add(-time.Hour))},
		{Type: v1alpha1.ConditionObservationAvailable, Status: metav1.ConditionTrue,
			Reason: v1alpha1.ReasonObservationAvailable, LastTransitionTime: metav1.NewTime(fixedNow.Add(-time.Hour))},
		{Type: v1alpha1.ConditionPodsMatched, Status: metav1.ConditionTrue,
			Reason: v1alpha1.ReasonPodsMatched, LastTransitionTime: metav1.NewTime(fixedNow.Add(-time.Hour))},
	}
	sw, client := newTestStatusWriter(t, "node-a", existing)

	recordAndFlush(t, sw, compiler.ModeEnforce)

	got := getPolicy(t, client, "p")
	for _, condType := range []string{v1alpha1.ConditionEnforcementAvailable,
		v1alpha1.ConditionObservationAvailable, v1alpha1.ConditionPodsMatched} {
		if hasCondition(got.Status.Conditions, condType) {
			t.Errorf("%s survived although no shard reports it", condType)
		}
	}
	applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
	if applied.Status != metav1.ConditionTrue || applied.Reason != v1alpha1.ReasonEnforcing {
		t.Errorf("Applied = (%s, %s), want (True, %s)", applied.Status, applied.Reason, v1alpha1.ReasonEnforcing)
	}
}

// TestModeChangeClearsStaleAvailabilitySignal: an availability condition
// recorded under the previous mode has no writer left to correct it, so a
// mode change must drop it, or the shard's message would name the wrong
// cause and the aggregate would keep reporting a mode nothing runs in.
func TestModeChangeClearsStaleAvailabilitySignal(t *testing.T) {
	sw, client := newTestStatusWriter(t, "node-a", policyObj("p", "uid-1"))
	recordAndFlush(t, sw, compiler.ModeMonitor,
		availabilityCondition(v1alpha1.ConditionObservationAvailable, metav1.ConditionFalse, "the LSM program has no observation maps"),
		podsMatchedCondition(metav1.ConditionTrue))

	recordAndFlush(t, sw, compiler.ModeEnforce,
		availabilityCondition(v1alpha1.ConditionEnforcementAvailable, metav1.ConditionFalse, "BPF-LSM is not active on this node"))

	got := getPolicy(t, client, "p")
	shard := got.Status.Nodes[0]
	if shard.ObservationAvailable != nil {
		t.Errorf("shard.observationAvailable = %v, want it cleared on the mode change", *shard.ObservationAvailable)
	}
	if shard.Message != "BPF-LSM is not active on this node" {
		t.Errorf("shard.message = %q, want the enforce-mode cause", shard.Message)
	}
	if hasCondition(got.Status.Conditions, v1alpha1.ConditionObservationAvailable) {
		t.Error("ObservationAvailable survived the switch to enforce mode")
	}
	applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied)
	if applied.Reason != v1alpha1.ReasonEnforcementUnavailable || !strings.Contains(applied.Message, "BPF-LSM is not active on this node") {
		t.Errorf("Applied = (%s, %q), want %s carrying the enforce-mode cause",
			applied.Reason, applied.Message, v1alpha1.ReasonEnforcementUnavailable)
	}
}

func TestRecomputeLastEvaluated(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	status := &v1alpha1.RuntimePolicyStatus{
		Nodes: []v1alpha1.NodePolicyStatus{
			{NodeName: "a", LastEvaluatedTime: ptrTime(late)},
			{NodeName: "b", LastEvaluatedTime: ptrTime(early)},
			{NodeName: "c"},
		},
	}
	recomputeLastEvaluated(status)
	if status.LastEvaluatedTime == nil || !status.LastEvaluatedTime.Time.Equal(late) {
		t.Errorf("lastEvaluatedTime = %v, want the newest shard time %v", status.LastEvaluatedTime, late)
	}
}

func TestNewStatusWriterDefaultsInterval(t *testing.T) {
	sw := NewStatusWriter(fakeversioned.NewSimpleClientset(), "node-a", 0, logr.Discard(), nil, nil)
	if sw.interval != DefaultStatusFlushInterval {
		t.Errorf("interval = %v, want the %v default", sw.interval, DefaultStatusFlushInterval)
	}
}

func ptrTime(t time.Time) *metav1.Time {
	mt := metav1.NewTime(t)
	return &mt
}

func hasCondition(conds []metav1.Condition, condType string) bool {
	for _, c := range conds {
		if c.Type == condType {
			return true
		}
	}
	return false
}
