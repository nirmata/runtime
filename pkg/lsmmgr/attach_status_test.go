package lsmmgr

import (
	"errors"
	"testing"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// TestAttachFailureReportsUnavailableAndClearsOnRetry pins the fix for a node
// that can never honor an open/exec rule (no BPF-LSM, or any other attach
// failure): the failure must land on the policy's status instead of being
// swallowed into the event queue's retry-and-forget path, and it must not get
// stuck once a retry actually succeeds.
func TestAttachFailureReportsUnavailableAndClearsOnRetry(t *testing.T) {
	tests := []struct {
		name          string
		mode          string
		wantCondition string
	}{
		{name: "enforce mode reports EnforcementAvailable", mode: compiler.ModeEnforce, wantCondition: v1alpha1.ConditionEnforcementAvailable},
		{name: "monitor mode reports ObservationAvailable", mode: compiler.ModeMonitor, wantCondition: v1alpha1.ConditionObservationAvailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			attachErr := errors.New("attach: operation not permitted")
			h.failCreate(open, attachErr)

			rp := result("rp1", tt.mode, labels.Everything(), pair(nil, []string{"/etc/shadow"}), nil)
			if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err == nil {
				t.Fatal("expected the attach failure to propagate so the event gets requeued")
			}

			got := condOfType(t, h.status, "rp1", tt.wantCondition)
			if got.Status != metav1.ConditionFalse {
				t.Errorf("%s status = %v, want False", tt.wantCondition, got.Status)
			}
			if got.Message == "" {
				t.Error("expected a message naming the attach failure")
			}

			// the requeue path in runtimepolicy_informer.go retries the same
			// event; once the underlying cause clears, the condition must too
			h.failCreate(open, nil)
			if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
				t.Fatalf("retry: unexpected error: %v", err)
			}
			got = condOfType(t, h.status, "rp1", tt.wantCondition)
			if got.Status != metav1.ConditionTrue {
				t.Errorf("%s status after a successful retry = %v, want True", tt.wantCondition, got.Status)
			}
		})
	}
}

// TestAttachFailureAggregateNotMaskedByADifferentProgType pins a masking bug:
// EnforcementAvailable/ObservationAvailable is shared across a policy's open
// and exec program types, so clearing it from one program type's successful
// attach must not erase a different program type's still-active failure.
func TestAttachFailureAggregateNotMaskedByADifferentProgType(t *testing.T) {
	h := newHarness(t)
	// a cgid-map failure specific to open, independent of whether exec attaches
	h.failMethod(open, "AddCgids", errors.New("cgid map full"))

	if err := h.l.PodEvent(testPod("pod-1", map[string]string{"app": "web"}), nil, cgs(1), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: unexpected error: %v", err)
	}

	sel := labels.SelectorFromSet(map[string]string{"app": "web"})
	rp := result("rp1", compiler.ModeEnforce, sel, pair(nil, []string{"/etc/shadow"}), nil)
	if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("create: unexpected error: %v", err)
	}

	got := condOfType(t, h.status, "rp1", v1alpha1.ConditionEnforcementAvailable)
	if got.Status != metav1.ConditionFalse {
		t.Fatalf("open's cgid failure: EnforcementAvailable = %v, want False", got.Status)
	}

	// the policy gains an exec rule whose attach succeeds cleanly; open's cgid
	// failure was never addressed and must still hold the condition False
	rp2 := result("rp1", compiler.ModeEnforce, sel, pair(nil, []string{"/etc/shadow"}), pair([]string{"/bin/ls"}, nil))
	if err := h.l.RuntimePolicyEvent(rp2, events.EventTypeUpdate); err != nil {
		t.Fatalf("update: unexpected error: %v", err)
	}

	got = condOfType(t, h.status, "rp1", v1alpha1.ConditionEnforcementAvailable)
	if got.Status != metav1.ConditionFalse {
		t.Errorf("exec's successful attach masked open's still-failing cgid state: EnforcementAvailable = %v, want False", got.Status)
	}
}

// TestPodsMatchedCondition pins the second reported gap: a podSelector that
// currently selects nothing on this node must not read the same as a policy
// that is doing something.
func TestPodsMatchedCondition(t *testing.T) {
	h := newHarness(t)
	rp := result("rp1", compiler.ModeEnforce, labels.SelectorFromSet(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), nil)

	if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := condOfType(t, h.status, "rp1", v1alpha1.ConditionPodsMatched)
	if got.Status != metav1.ConditionFalse || got.Reason != v1alpha1.ReasonNoMatchingPods {
		t.Errorf("with no matching pod: status=%v reason=%v, want False/%s", got.Status, got.Reason, v1alpha1.ReasonNoMatchingPods)
	}

	if err := h.l.PodEvent(testPod("pod-1", map[string]string{"app": "web"}), nil, cgs(1), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: unexpected error: %v", err)
	}
	// the policy itself is unchanged, but re-evaluating it is what the
	// periodic re-evaluation thread and the informer's resync both do
	if err := h.l.RuntimePolicyEvent(rp, events.EventTypeUpdate); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got = condOfType(t, h.status, "rp1", v1alpha1.ConditionPodsMatched)
	if got.Status != metav1.ConditionTrue || got.Reason != v1alpha1.ReasonPodsMatched {
		t.Errorf("with a matching pod: status=%v reason=%v, want True/%s", got.Status, got.Reason, v1alpha1.ReasonPodsMatched)
	}
}

// TestPodsMatchedUpdatesOnPodEventsAlone pins a bug Copilot's review caught: a
// policy re-evaluated on RuntimePolicyEvent recomputes PodsMatched, but pod
// create/update/delete previously never did, so a policy created with zero
// matches stayed PodsMatched=False (and, since Applied now derives from it,
// Applied=False) forever after a matching pod later showed up, until the
// policy itself happened to be re-evaluated. No RuntimePolicyEvent update is
// sent anywhere in this test — every transition below has to come from the
// pod events alone.
func TestPodsMatchedUpdatesOnPodEventsAlone(t *testing.T) {
	h := newHarness(t)
	rp := result("rp1", compiler.ModeEnforce, labels.SelectorFromSet(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), nil)
	if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("create: unexpected error: %v", err)
	}
	got := condOfType(t, h.status, "rp1", v1alpha1.ConditionPodsMatched)
	if got.Status != metav1.ConditionFalse {
		t.Fatalf("before any pod: PodsMatched = %v, want False", got.Status)
	}

	// a matching pod is created: PodsMatched must flip on this event alone
	if err := h.l.PodEvent(testPod("pod-1", map[string]string{"app": "web"}), nil, cgs(1), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent create: unexpected error: %v", err)
	}
	got = condOfType(t, h.status, "rp1", v1alpha1.ConditionPodsMatched)
	if got.Status != metav1.ConditionTrue {
		t.Fatalf("after a matching pod is created: PodsMatched = %v, want True", got.Status)
	}

	// the pod is relabelled out of the selector: PodsMatched must flip back
	if err := h.l.PodEvent(testPod("pod-1", map[string]string{"app": "other"}), nil, cgs(1), events.EventTypeUpdate); err != nil {
		t.Fatalf("PodEvent update: unexpected error: %v", err)
	}
	got = condOfType(t, h.status, "rp1", v1alpha1.ConditionPodsMatched)
	if got.Status != metav1.ConditionFalse {
		t.Fatalf("after the pod relabels out: PodsMatched = %v, want False", got.Status)
	}

	// relabel it back in, then delete it outright: PodsMatched must flip back
	// to False on the delete, not stay stuck True
	if err := h.l.PodEvent(testPod("pod-1", map[string]string{"app": "web"}), nil, cgs(1), events.EventTypeUpdate); err != nil {
		t.Fatalf("PodEvent re-label: unexpected error: %v", err)
	}
	got = condOfType(t, h.status, "rp1", v1alpha1.ConditionPodsMatched)
	if got.Status != metav1.ConditionTrue {
		t.Fatalf("after the pod relabels back in: PodsMatched = %v, want True", got.Status)
	}
	if err := h.l.PodDeleted("pod-1"); err != nil {
		t.Fatalf("PodDeleted: unexpected error: %v", err)
	}
	got = condOfType(t, h.status, "rp1", v1alpha1.ConditionPodsMatched)
	if got.Status != metav1.ConditionFalse {
		t.Errorf("after the last matching pod is deleted: PodsMatched = %v, want False", got.Status)
	}
}
