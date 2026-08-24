package reportevents

import (
	"strings"
	"testing"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/reporter"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
)

func testFinding(enforced bool) reporter.Finding {
	return reporter.Finding{
		PolicyName: "block-egress",
		PolicyUID:  "policy-uid-1",
		Behavior:   "network",
		Target:     "1.2.3.4",
		Result:     reporter.ResultFail,
		Enforced:   enforced,
		Message:    "egress to 1.2.3.4 was denied by policy block-egress",
		Pod: runtimeevent.PodIdentity{
			UID:       "pod-uid-1",
			Namespace: "default",
			Name:      "pod-1",
		},
	}
}

func recvEvent(t *testing.T, rec *events.FakeRecorder) string {
	t.Helper()
	select {
	case got := <-rec.Events:
		return got
	default:
		t.Fatal("no event was recorded")
		return ""
	}
}

func assertNoEvent(t *testing.T, rec *events.FakeRecorder) {
	t.Helper()
	select {
	case got := <-rec.Events:
		t.Fatalf("unexpected event recorded: %q", got)
	default:
	}
}

func TestFindingFlushedMapsEnforcementToReasonAndType(t *testing.T) {
	tests := []struct {
		name       string
		enforced   bool
		wantType   string
		wantReason string
	}{
		{name: "enforced violation", enforced: true, wantType: "Warning", wantReason: ReasonPolicyViolation},
		{name: "monitor mode counterfactual", enforced: false, wantType: "Normal", wantReason: ReasonPolicyWouldViolate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := events.NewFakeRecorder(1)
			r := New(fake, logr.Discard())

			r.FindingFlushed(testFinding(tc.enforced), 1)

			got := recvEvent(t, fake)
			if !strings.HasPrefix(got, tc.wantType+" "+tc.wantReason+" ") {
				t.Errorf("event = %q, want it to start with %q", got, tc.wantType+" "+tc.wantReason+" ")
			}
		})
	}
}

func TestFindingFlushedNotesOccurrenceCount(t *testing.T) {
	fake := events.NewFakeRecorder(1)
	r := New(fake, logr.Discard())

	r.FindingFlushed(testFinding(true), 5)

	got := recvEvent(t, fake)
	if !strings.Contains(got, "(5 occurrences this interval)") {
		t.Errorf("event = %q, want it to note the occurrence count", got)
	}
}

func TestFindingFlushedOmitsOccurrenceCountForOne(t *testing.T) {
	fake := events.NewFakeRecorder(1)
	r := New(fake, logr.Discard())

	r.FindingFlushed(testFinding(true), 1)

	got := recvEvent(t, fake)
	if strings.Contains(got, "occurrences") {
		t.Errorf("event = %q, want no occurrence note for a single occurrence", got)
	}
}

// TestFindingFlushedRedactsTheNote guards the redaction boundary: a finding
// message carrying a credential-shaped substring must not reach the Event.
func TestFindingFlushedRedactsTheNote(t *testing.T) {
	secret := "sk-ant-api03-CANARYaaaabbbbccccddddeeeeffff"
	f := testFinding(true)
	f.Message = "egress denied, request carried " + secret

	fake := events.NewFakeRecorder(1)
	r := New(fake, logr.Discard())
	r.FindingFlushed(f, 1)

	got := recvEvent(t, fake)
	if strings.Contains(got, secret) || strings.Contains(got, "CANARY") {
		t.Errorf("planted secret survived into the event: %q", got)
	}
	if !strings.Contains(got, reporter.Redacted) {
		t.Errorf("event = %q, want the redaction marker present", got)
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
			fake := events.NewFakeRecorder(1)
			r := New(fake, logr.Discard())

			r.ConditionChanged("policy-uid-1", tc.policyName, tc.cond)

			if tc.wantEvent {
				got := recvEvent(t, fake)
				if !strings.HasPrefix(got, "Warning "+ReasonPolicyError+" ") {
					t.Errorf("event = %q, want it to start with %q", got, "Warning "+ReasonPolicyError+" ")
				}
			} else {
				assertNoEvent(t, fake)
			}
		})
	}
}

// TestConditionChangedRedactsReasonAndMessage guards the redaction boundary
// for PolicyError events: Reason/Message can carry compiler error text
// quoting user policy content.
func TestConditionChangedRedactsReasonAndMessage(t *testing.T) {
	secret := "Bearer sk-live-CANARY-9f8e7d6c5b4a3210"
	fake := events.NewFakeRecorder(1)
	r := New(fake, logr.Discard())

	r.ConditionChanged("policy-uid-1", "p", metav1.Condition{
		Type:    v1alpha1.ConditionApplied,
		Status:  metav1.ConditionFalse,
		Reason:  "CompileFailed",
		Message: "rejected value " + secret,
	})

	got := recvEvent(t, fake)
	if strings.Contains(got, secret) || strings.Contains(got, "CANARY") {
		t.Errorf("planted secret survived into the event: %q", got)
	}
	if !strings.Contains(got, reporter.Redacted) {
		t.Errorf("event = %q, want the redaction marker present", got)
	}
}
