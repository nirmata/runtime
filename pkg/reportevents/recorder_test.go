package reportevents

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/reporter"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var fixedTime = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

func testFinding(enforced bool, target string) reporter.Finding {
	return reporter.Finding{
		PolicyName: "block-egress",
		PolicyUID:  "policy-uid-1",
		Behavior:   "network",
		Target:     target,
		Result:     reporter.ResultFail,
		Enforced:   enforced,
		Message:    "egress to " + target + " was denied by policy block-egress",
		Pod: runtimeevent.PodIdentity{
			UID:       "pod-uid-1",
			Namespace: "default",
			Name:      "pod-1",
		},
	}
}

func newTestRecorder(t *testing.T) (*Recorder, *k8sfake.Clientset) {
	t.Helper()
	client := k8sfake.NewSimpleClientset()
	r := New(client.EventsV1(), logr.Discard())
	r.clock = func() time.Time { return fixedTime }
	return r, client
}

func listEvents(t *testing.T, client *k8sfake.Clientset, namespace string) []eventsv1.Event {
	t.Helper()
	list, err := client.EventsV1().Events(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing events: %v", err)
	}
	sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
	return list.Items
}

func TestFindingFlushedMapsEnforcementToReasonAndType(t *testing.T) {
	tests := []struct {
		name       string
		enforced   bool
		wantType   string
		wantReason string
	}{
		{name: "enforced violation", enforced: true, wantType: corev1.EventTypeWarning, wantReason: ReasonPolicyViolation},
		{name: "monitor mode counterfactual", enforced: false, wantType: corev1.EventTypeNormal, wantReason: ReasonPolicyWouldViolate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, client := newTestRecorder(t)

			r.FindingFlushed(testFinding(tc.enforced, "1.2.3.4"), 1)

			events := listEvents(t, client, "default")
			if len(events) != 1 {
				t.Fatalf("events = %d, want 1", len(events))
			}
			if events[0].Type != tc.wantType || events[0].Reason != tc.wantReason {
				t.Errorf("event = (%s, %s), want (%s, %s)", events[0].Type, events[0].Reason, tc.wantType, tc.wantReason)
			}
		})
	}
}

// TestFindingFlushedGivesDistinctFingerprintsDistinctEvents is the regression
// test for the correlator bug: client-go's events.EventRecorder keys its
// correlation cache on (type, action, reason, controller, instance,
// regarding, related) and never looks at the note, so two distinct findings
// for the same pod, policy, and enforcement mode — differing only in target —
// would collapse into a single Event series with only the first message
// surviving. Naming each Event from the finding's fingerprint instead must
// keep them as two distinct objects, each with its own correct message.
func TestFindingFlushedGivesDistinctFingerprintsDistinctEvents(t *testing.T) {
	r, client := newTestRecorder(t)

	r.FindingFlushed(testFinding(true, "1.2.3.4"), 1)
	r.FindingFlushed(testFinding(true, "5.6.7.8"), 1)

	got := listEvents(t, client, "default")
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2 distinct objects for 2 distinct fingerprints", len(got))
	}
	if got[0].Name == got[1].Name {
		t.Fatalf("both findings produced the same event name %q", got[0].Name)
	}
	notes := map[string]bool{got[0].Note: true, got[1].Note: true}
	if !notes[testFinding(true, "1.2.3.4").Message] || !notes[testFinding(true, "5.6.7.8").Message] {
		t.Errorf("notes = %v, want both distinct target messages present", notes)
	}
}

// TestFindingFlushedCoalescesTheSameFingerprintAcrossFlushes covers the other
// half of the fix: a genuine repeat of the identical finding across separate
// flush calls must patch the same Event object (refreshing its series count
// and note) rather than creating a new one every time.
func TestFindingFlushedCoalescesTheSameFingerprintAcrossFlushes(t *testing.T) {
	r, client := newTestRecorder(t)

	r.FindingFlushed(testFinding(true, "1.2.3.4"), 2)
	r.FindingFlushed(testFinding(true, "1.2.3.4"), 5)

	got := listEvents(t, client, "default")
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1 object for 2 flushes of the identical fingerprint", len(got))
	}
	if got[0].Series == nil || got[0].Series.Count != 5 {
		t.Errorf("series = %+v, want the latest flush's count (5)", got[0].Series)
	}
	if !strings.Contains(got[0].Note, "(5 occurrences this interval)") {
		t.Errorf("note = %q, want it refreshed to the latest flush's occurrence count", got[0].Note)
	}
}

func TestFindingFlushedOmitsOccurrenceCountForOne(t *testing.T) {
	r, client := newTestRecorder(t)

	r.FindingFlushed(testFinding(true, "1.2.3.4"), 1)

	got := listEvents(t, client, "default")
	if strings.Contains(got[0].Note, "occurrences") {
		t.Errorf("note = %q, want no occurrence note for a single occurrence", got[0].Note)
	}
}

// TestFindingFlushedRedactsTheNote guards the redaction boundary: a finding
// message carrying a credential-shaped substring must not reach the Event.
func TestFindingFlushedRedactsTheNote(t *testing.T) {
	secret := "sk-ant-api03-CANARYaaaabbbbccccddddeeeeffff"
	f := testFinding(true, "1.2.3.4")
	f.Message = "egress denied, request carried " + secret

	r, client := newTestRecorder(t)
	r.FindingFlushed(f, 1)

	got := listEvents(t, client, "default")
	if strings.Contains(got[0].Note, secret) || strings.Contains(got[0].Note, "CANARY") {
		t.Errorf("planted secret survived into the event: %q", got[0].Note)
	}
	if !strings.Contains(got[0].Note, reporter.Redacted) {
		t.Errorf("note = %q, want the redaction marker present", got[0].Note)
	}
}

func TestConditionChangedEmitsOnlyForAppliedAndTargetsValidFalse(t *testing.T) {
	tests := []struct {
		name       string
		policyName string
		cond       metav1.Condition
		wantEvent  bool
	}{
		{
			name:       "Applied False",
			policyName: "p",
			cond:       metav1.Condition{Type: v1alpha1.ConditionApplied, Status: metav1.ConditionFalse, Reason: "CompileFailed", Message: "bad policy"},
			wantEvent:  true,
		},
		{
			name:       "TargetsValid False",
			policyName: "p",
			cond:       metav1.Condition{Type: v1alpha1.ConditionTargetsValid, Status: metav1.ConditionFalse, Reason: "UnsupportedTargets", Message: "1 target cannot be programmed"},
			wantEvent:  true,
		},
		{
			name:       "Applied True",
			policyName: "p",
			cond:       metav1.Condition{Type: v1alpha1.ConditionApplied, Status: metav1.ConditionTrue, Reason: "Enforcing"},
			wantEvent:  false,
		},
		{
			name:       "unrelated condition type",
			policyName: "p",
			cond:       metav1.Condition{Type: v1alpha1.ConditionPodsMatched, Status: metav1.ConditionFalse, Reason: "NoMatchingPods"},
			wantEvent:  false,
		},
		{
			name:       "empty policy name",
			policyName: "",
			cond:       metav1.Condition{Type: v1alpha1.ConditionApplied, Status: metav1.ConditionFalse, Reason: "CompileFailed"},
			wantEvent:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, client := newTestRecorder(t)

			r.ConditionChanged("policy-uid-1", tc.policyName, tc.cond)

			got := listEvents(t, client, corev1.NamespaceDefault)
			if tc.wantEvent {
				if len(got) != 1 {
					t.Fatalf("events = %d, want 1", len(got))
				}
				if got[0].Type != corev1.EventTypeWarning || got[0].Reason != ReasonPolicyError {
					t.Errorf("event = (%s, %s), want (%s, %s)", got[0].Type, got[0].Reason, corev1.EventTypeWarning, ReasonPolicyError)
				}
			} else if len(got) != 0 {
				t.Fatalf("events = %d, want 0", len(got))
			}
		})
	}
}

// TestConditionChangedGivesDistinctConditionTypesDistinctEvents is the
// regression test for the same correlator bug applied to policy errors: an
// Applied failure followed by a TargetsValid failure on the same policy must
// not collapse into one Event.
func TestConditionChangedGivesDistinctConditionTypesDistinctEvents(t *testing.T) {
	r, client := newTestRecorder(t)

	r.ConditionChanged("policy-uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionApplied, Status: metav1.ConditionFalse, Reason: "CompileFailed", Message: "bad policy",
	})
	r.ConditionChanged("policy-uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionTargetsValid, Status: metav1.ConditionFalse, Reason: "UnsupportedTargets", Message: "1 target cannot be programmed",
	})

	got := listEvents(t, client, corev1.NamespaceDefault)
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2 distinct objects for 2 distinct condition types", len(got))
	}
}

// TestConditionChangedReplacesTheNoteOnANewReason covers a changed
// reason/message under the same condition type: it must update the same
// object's note in place rather than being silently discarded by the old
// note-blind correlator.
func TestConditionChangedReplacesTheNoteOnANewReason(t *testing.T) {
	r, client := newTestRecorder(t)

	r.ConditionChanged("policy-uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionApplied, Status: metav1.ConditionFalse, Reason: "CompileFailed", Message: "first failure",
	})
	r.ConditionChanged("policy-uid-1", "p", metav1.Condition{
		Type: v1alpha1.ConditionApplied, Status: metav1.ConditionFalse, Reason: "EnforcementUnavailable", Message: "second failure",
	})

	got := listEvents(t, client, corev1.NamespaceDefault)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1 object updated in place", len(got))
	}
	if !strings.Contains(got[0].Note, "second failure") || strings.Contains(got[0].Note, "first failure") {
		t.Errorf("note = %q, want only the latest reason/message", got[0].Note)
	}
}

// TestConditionChangedRedactsReasonAndMessage guards the redaction boundary
// for PolicyError events: Reason/Message can carry compiler error text
// quoting user policy content.
func TestConditionChangedRedactsReasonAndMessage(t *testing.T) {
	secret := "Bearer sk-live-CANARY-9f8e7d6c5b4a3210"
	r, client := newTestRecorder(t)

	r.ConditionChanged("policy-uid-1", "p", metav1.Condition{
		Type:    v1alpha1.ConditionApplied,
		Status:  metav1.ConditionFalse,
		Reason:  "CompileFailed",
		Message: "rejected value " + secret,
	})

	got := listEvents(t, client, corev1.NamespaceDefault)
	if strings.Contains(got[0].Note, secret) || strings.Contains(got[0].Note, "CANARY") {
		t.Errorf("planted secret survived into the event: %q", got[0].Note)
	}
	if !strings.Contains(got[0].Note, reporter.Redacted) {
		t.Errorf("note = %q, want the redaction marker present", got[0].Note)
	}
}
