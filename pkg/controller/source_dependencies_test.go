package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSourceDependenciesFollowDeclaredTargets covers every observation producer
// while keeping a behavior without values or expressions independent of it.
func TestSourceDependenciesFollowDeclaredTargets(t *testing.T) {
	monitor, enforce, emptyMode := v1alpha1.PolicyModeMonitor, v1alpha1.PolicyModeEnforce, v1alpha1.RuntimePolicyMode("")
	values := &v1alpha1.Behavior{Deny: &v1alpha1.BehaviorRule{Values: []string{"*"}}}
	emptyRules := &v1alpha1.Behavior{Allow: &v1alpha1.BehaviorRule{}, Deny: &v1alpha1.BehaviorRule{Values: []string{}}}
	expression := &v1alpha1.Behavior{Allow: &v1alpha1.BehaviorRule{Expression: `["/bin/sh"].filter(value, false)`}}
	cases := []struct {
		name      string
		mode      *v1alpha1.RuntimePolicyMode
		behaviors []v1alpha1.PolicyBehavior
		want      []string
	}{
		{name: "nil mode bypassed API defaulting", behaviors: []v1alpha1.PolicyBehavior{{Exec: values}}},
		{name: "empty mode", mode: &emptyMode, behaviors: []v1alpha1.PolicyBehavior{{Exec: values}}},
		{name: "enforcement", mode: &enforce, behaviors: []v1alpha1.PolicyBehavior{{Exec: values}, {Network: values}}},
		{name: "empty behavior", mode: &monitor, behaviors: []v1alpha1.PolicyBehavior{{Exec: &v1alpha1.Behavior{}}}},
		{name: "empty rules", mode: &monitor, behaviors: []v1alpha1.PolicyBehavior{{DNS: emptyRules}, {Open: emptyRules}}},
		{name: "open", mode: &monitor, behaviors: []v1alpha1.PolicyBehavior{{Open: values}}, want: []string{openExecObserveSource}},
		{name: "exec", mode: &monitor, behaviors: []v1alpha1.PolicyBehavior{{Exec: values}}, want: []string{execTraceSource, openExecObserveSource}},
		{name: "network", mode: &monitor, behaviors: []v1alpha1.PolicyBehavior{{Network: values}}, want: []string{egressObserveSource}},
		{name: "protocol", mode: &monitor, behaviors: []v1alpha1.PolicyBehavior{{Protocol: values}}, want: []string{egressObserveSource}},
		{name: "dns", mode: &monitor, behaviors: []v1alpha1.PolicyBehavior{{DNS: values}}, want: []string{dnsQuerySource}},
		{name: "shared sources deduplicated", mode: &monitor,
			behaviors: []v1alpha1.PolicyBehavior{{Open: values}, {Exec: values}, {Network: values}, {Protocol: values}, {DNS: values}},
			want:      []string{dnsQuerySource, egressObserveSource, execTraceSource, openExecObserveSource}},
		{name: "expression can be reevaluated", mode: &monitor, behaviors: []v1alpha1.PolicyBehavior{{Exec: expression}},
			want: []string{execTraceSource, openExecObserveSource}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sourceDependencies(v1alpha1.RuntimePolicySpec{Mode: tc.mode, Behaviors: tc.behaviors})
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("source dependencies mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestPollSourceFailureGatesMonitorApplied prevents an active policy from
// remaining applied when its only counter reader is retrying after failure.
func TestPollSourceFailureGatesMonitorApplied(t *testing.T) {
	targets := &v1alpha1.Behavior{Deny: &v1alpha1.BehaviorRule{Values: []string{"*"}}}
	cases := []struct {
		name     string
		behavior v1alpha1.PolicyBehavior
		source   string
	}{
		{name: "open", behavior: v1alpha1.PolicyBehavior{Open: targets}, source: openExecObserveSource},
		{name: "exec", behavior: v1alpha1.PolicyBehavior{Exec: targets}, source: openExecObserveSource},
		{name: "network", behavior: v1alpha1.PolicyBehavior{Network: targets}, source: egressObserveSource},
		{name: "protocol", behavior: v1alpha1.PolicyBehavior{Protocol: targets}, source: egressObserveSource},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := monitorPolicyWithBehaviors("p", "uid-1", tc.behavior)
			sw, client := newTestStatusWriter(t, "node-a", policy)
			sw.SetExpectedSourceNodes(func() ExpectedSourceNodes {
				return ExpectedSourceNodes{Names: []string{"node-a"}, Desired: 1, Synced: true}
			})
			if err := sw.RuntimePolicyEvent(&compiler.EvaluationResult{UID: "uid-1", Name: "p", Mode: compiler.ModeMonitor}, events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			sw.RecordSourceStatus(execTraceSource, runtimeevent.SourceStateAvailable, runtimeevent.SourceReasonReady)
			for _, step := range []struct {
				state  runtimeevent.SourceState
				reason string
				want   metav1.ConditionStatus
			}{
				{state: runtimeevent.SourceStateUnavailable, reason: runtimeevent.SourceReasonReaderFailed, want: metav1.ConditionFalse},
				{state: runtimeevent.SourceStateAvailable, reason: runtimeevent.SourceReasonReady, want: metav1.ConditionTrue},
			} {
				sw.RecordSourceStatus(tc.source, step.state, step.reason)
				if err := sw.Flush(context.Background()); err != nil {
					t.Fatal(err)
				}
				got := getPolicy(t, client, "p")
				for _, typ := range []string{v1alpha1.ConditionEventSourcesAvailable, v1alpha1.ConditionApplied} {
					condition := conditionOfType(t, got.Status.Conditions, typ)
					if condition.Status != step.want {
						t.Errorf("%s after %s = %s, want %s", typ, step.state, condition.Status, step.want)
					}
					if step.want == metav1.ConditionFalse && !strings.Contains(condition.Message, tc.source) {
						t.Errorf("%s message = %q, want failing source %q", typ, condition.Message, tc.source)
					}
				}
			}
		})
	}
}

// TestEmptyRulesDoNotDependOnUnavailableSources keeps a no-op policy from
// reporting the state of readers it cannot use.
func TestEmptyRulesDoNotDependOnUnavailableSources(t *testing.T) {
	for _, tc := range []struct {
		name     string
		behavior *v1alpha1.Behavior
	}{
		{name: "absent"},
		{name: "empty behavior", behavior: &v1alpha1.Behavior{}},
		{name: "empty allow and deny", behavior: &v1alpha1.Behavior{
			Allow: &v1alpha1.BehaviorRule{}, Deny: &v1alpha1.BehaviorRule{Values: []string{}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := monitorPolicyWithBehaviors("p", "uid-1", v1alpha1.PolicyBehavior{
				Open: tc.behavior, Exec: tc.behavior, Network: tc.behavior, Protocol: tc.behavior, DNS: tc.behavior,
			})
			sw, client := newTestStatusWriter(t, "node-a", policy)
			for _, source := range []string{openExecObserveSource, egressObserveSource, execTraceSource, dnsQuerySource} {
				sw.RecordSourceStatus(source, runtimeevent.SourceStateUnavailable, runtimeevent.SourceReasonInitializationFailed)
			}
			if err := sw.RuntimePolicyEvent(&compiler.EvaluationResult{UID: "uid-1", Name: "p", Mode: compiler.ModeMonitor}, events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			if err := sw.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := getPolicy(t, client, "p")
			if hasCondition(got.Status.Conditions, v1alpha1.ConditionEventSourcesAvailable) || len(got.Status.Nodes[0].EventSources) != 0 {
				t.Errorf("empty rules produced source status: %+v", got.Status)
			}
			if applied := conditionOfType(t, got.Status.Conditions, v1alpha1.ConditionApplied); applied.Status != metav1.ConditionTrue {
				t.Errorf("Applied = %+v, want True", applied)
			}
		})
	}
}

// TestEmptyEvaluationRetainsDeclaredExpressionSources keeps a transient empty
// result from erasing coverage requirements before the next evaluation.
func TestEmptyEvaluationRetainsDeclaredExpressionSources(t *testing.T) {
	policy := monitorPolicyWithBehaviors("p", "uid-1", v1alpha1.PolicyBehavior{Exec: &v1alpha1.Behavior{
		Deny: &v1alpha1.BehaviorRule{Expression: `["/bin/sh"].filter(value, false)`},
	}})
	sw, client := newTestStatusWriter(t, "node-a", policy)
	sw.SetExpectedSourceNodes(func() ExpectedSourceNodes {
		return ExpectedSourceNodes{Names: []string{"node-a"}, Desired: 1, Synced: true}
	})
	sw.RecordSourceStatus(execTraceSource, runtimeevent.SourceStateAvailable, runtimeevent.SourceReasonReady)
	sw.RecordSourceStatus(openExecObserveSource, runtimeevent.SourceStateUnavailable, runtimeevent.SourceReasonReaderFailed)
	for _, eventType := range []string{events.EventTypeCreate, events.EventTypeUpdate} {
		t.Run(eventType, func(t *testing.T) {
			if err := sw.RuntimePolicyEvent(&compiler.EvaluationResult{UID: "uid-1", Name: "p", Mode: compiler.ModeMonitor,
				Exec: &compiler.AllowDenyPair{}}, eventType); err != nil {
				t.Fatal(err)
			}
			if err := sw.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := getPolicy(t, client, "p")
			for _, typ := range []string{v1alpha1.ConditionEventSourcesAvailable, v1alpha1.ConditionApplied} {
				if condition := conditionOfType(t, got.Status.Conditions, typ); condition.Status != metav1.ConditionFalse {
					t.Errorf("%s = %+v, want False for declared expression", typ, condition)
				}
			}
		})
	}
}

// TestExecDependencyFailureReportsLostFilenameCoverage distinguishes a reader
// failure from loss of the manager that supplies both observation paths.
func TestExecDependencyFailureReportsLostFilenameCoverage(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   string
	}{
		{reason: runtimeevent.SourceReasonReaderFailed, want: "exec filename observations may remain available"},
		{reason: runtimeevent.SourceReasonDependencyUnavailable, want: "argv and exec filename observations are unavailable"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			status := eventSourceStatus(execTraceSource, sourceStatus{state: runtimeevent.SourceStateUnavailable, reason: tc.reason})
			if status.Status != metav1.ConditionFalse || !strings.Contains(status.Message, tc.want) {
				t.Fatalf("source status = %+v, want False and %q", status, tc.want)
			}
		})
	}
}
