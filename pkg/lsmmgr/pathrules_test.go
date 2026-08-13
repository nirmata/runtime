package lsmmgr

import (
	"slices"
	"strings"
	"testing"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// condOfType returns the last condition of a type, which is what a
// last-write-wins status holds.
func condOfType(t *testing.T, s *fakeStatus, policyUID, condType string) metav1.Condition {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var got metav1.Condition
	found := false
	for _, c := range s.conditions[policyUID] {
		if c.Type == condType {
			got, found = c, true
		}
	}
	if !found {
		t.Fatalf("no %s condition recorded for %q (have %v)", condType, policyUID, s.conditions[policyUID])
	}
	return got
}

// TestUnenforceablePathsSurfaceOnPolicyStatus pins the failure mode this repo
// forbids: a value the kernel maps cannot hold is never programmed, and the
// policy says so instead of looking healthy.
func TestUnenforceablePathsSurfaceOnPolicyStatus(t *testing.T) {
	tooLong := "/" + strings.Repeat("a", compiler.MaxPathValueLen)
	tests := []struct {
		name       string
		mode       string
		openPair   *compiler.AllowDenyPair
		execPair   *compiler.AllowDenyPair
		wantExec   metav1.ConditionStatus
		wantOpen   metav1.ConditionStatus
		wantReason string
	}{{
		name:       "over-length exec value",
		mode:       compiler.ModeEnforce,
		execPair:   pair(nil, []string{"/bin/sh", tooLong}),
		wantExec:   metav1.ConditionFalse,
		wantOpen:   metav1.ConditionTrue,
		wantReason: v1alpha1.ReasonUnsupportedPaths,
	}, {
		name:       "NUL-bearing exec value",
		mode:       compiler.ModeEnforce,
		execPair:   pair([]string{"/bin/sh\x00"}, nil),
		wantExec:   metav1.ConditionFalse,
		wantOpen:   metav1.ConditionTrue,
		wantReason: v1alpha1.ReasonUnsupportedPaths,
	}, {
		name:       "observe mode reports the same values it can never match",
		mode:       compiler.ModeMonitor,
		execPair:   pair(nil, []string{tooLong}),
		wantExec:   metav1.ConditionFalse,
		wantOpen:   metav1.ConditionTrue,
		wantReason: v1alpha1.ReasonUnsupportedPaths,
	}, {
		name:       "every value supported",
		mode:       compiler.ModeEnforce,
		openPair:   pair(nil, []string{"/etc/shadow"}),
		execPair:   pair([]string{"/bin/ls"}, []string{compiler.StarTarget}),
		wantExec:   metav1.ConditionTrue,
		wantOpen:   metav1.ConditionTrue,
		wantReason: v1alpha1.ReasonAllPathsSupported,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			rp := result("rp1", tt.mode, labels.Everything(), tt.openPair, tt.execPair)
			if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}

			execCond := condOfType(t, h.status, "rp1", v1alpha1.ConditionExecRulesValid)
			if execCond.Status != tt.wantExec {
				t.Errorf("%s = %v, want %v (message %q)", v1alpha1.ConditionExecRulesValid, execCond.Status, tt.wantExec, execCond.Message)
			}
			if execCond.Reason != tt.wantReason {
				t.Errorf("%s reason = %q, want %q", v1alpha1.ConditionExecRulesValid, execCond.Reason, tt.wantReason)
			}
			if execCond.LastTransitionTime.Time != fixedTime {
				t.Errorf("%s LastTransitionTime = %v, want the injected clock %v",
					v1alpha1.ConditionExecRulesValid, execCond.LastTransitionTime.Time, fixedTime)
			}
			if got := condOfType(t, h.status, "rp1", v1alpha1.ConditionOpenRulesValid).Status; got != tt.wantOpen {
				t.Errorf("%s = %v, want %v", v1alpha1.ConditionOpenRulesValid, got, tt.wantOpen)
			}

			if tt.mode != compiler.ModeEnforce || tt.execPair == nil {
				return
			}
			execEnf := h.enf("rp1", exec)
			for _, bad := range []string{tooLong, "/bin/sh\x00"} {
				if slices.Contains(execEnf.denySet(), bad) || slices.Contains(execEnf.allowSet(), bad) {
					t.Errorf("value %q reached the kernel maps: allow=%v deny=%v",
						bad, execEnf.allowSet(), execEnf.denySet())
				}
			}
		})
	}
}

// a policy whose values become enforceable again must stop reporting the
// failure, so the condition follows the spec rather than latching.
func TestPathRulesConditionClearsWhenValuesBecomeEnforceable(t *testing.T) {
	tooLong := "/" + strings.Repeat("a", compiler.MaxPathValueLen)
	h := newHarness(t)
	sel := labels.Everything()

	create := result("rp1", compiler.ModeEnforce, sel, nil, pair(nil, []string{"/bin/sh", tooLong}))
	if err := h.l.RuntimePolicyEvent(create, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if got := condOfType(t, h.status, "rp1", v1alpha1.ConditionExecRulesValid).Status; got != metav1.ConditionFalse {
		t.Fatalf("%s = %v, want False", v1alpha1.ConditionExecRulesValid, got)
	}

	update := result("rp1", compiler.ModeEnforce, sel, nil, pair(nil, []string{"/bin/sh"}))
	if err := h.l.RuntimePolicyEvent(update, events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	cond := condOfType(t, h.status, "rp1", v1alpha1.ConditionExecRulesValid)
	if cond.Status != metav1.ConditionTrue || cond.Reason != v1alpha1.ReasonAllPathsSupported {
		t.Errorf("%s = %v/%q, want True/%s", v1alpha1.ConditionExecRulesValid, cond.Status, cond.Reason, v1alpha1.ReasonAllPathsSupported)
	}
}

// a value that trims to "*" without being it must not flip the policy to
// default deny; it is surfaced on the policy status like any other value the
// schema refuses, so the author corrects it instead of guessing.
func TestPaddedStarIsRejectedNotDefaultDeny(t *testing.T) {
	h := newHarness(t)
	rp := result("rp1", compiler.ModeEnforce, labels.Everything(), nil, pair([]string{"/bin/ls"}, []string{" * \n"}))
	if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	execEnf := h.enf("rp1", exec)
	if execEnf.denyAll {
		t.Error("exec default deny = true, want false")
	}
	if got := execEnf.denySet(); len(got) != 0 {
		t.Errorf("exec deny set = %v, want empty", got)
	}
	cond := condOfType(t, h.status, "rp1", v1alpha1.ConditionExecRulesValid)
	if cond.Status != metav1.ConditionFalse || cond.Reason != v1alpha1.ReasonUnsupportedPaths {
		t.Errorf("%s = %v/%q, want False/%s", v1alpha1.ConditionExecRulesValid, cond.Status, cond.Reason, v1alpha1.ReasonUnsupportedPaths)
	}
}
