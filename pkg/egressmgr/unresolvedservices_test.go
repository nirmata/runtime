package egressmgr

import (
	"strings"
	"testing"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func rpWithUnresolved(uid string, allow, deny []string, unresolved ...string) *compiler.EvaluationResult {
	res := rp(uid, "enforce", webLabels, allow, deny)
	res.UnresolvedServices = unresolved
	return res
}

func TestTargetsConditionReportsUnresolvedServices(t *testing.T) {
	tests := []struct {
		name       string
		res        *compiler.EvaluationResult
		wantStatus metav1.ConditionStatus
		wantReason string
		wantIn     []string
	}{
		{
			name:       "an unresolved service is the policy's only target",
			res:        rpWithUnresolved("rp-1", nil, []string{"*"}, "api.prod.svc.cluster.local"),
			wantStatus: metav1.ConditionFalse,
			wantReason: v1alpha1.ReasonUnresolvedServices,
			wantIn:     []string{"api.prod.svc.cluster.local"},
		},
		{
			name:       "resolved literals alongside an unresolved service",
			res:        rpWithUnresolved("rp-1", []string{"1.1.1.1"}, []string{"*"}, "api.prod.svc.cluster.local"),
			wantStatus: metav1.ConditionFalse,
			wantReason: v1alpha1.ReasonUnresolvedServices,
			wantIn:     []string{"api.prod.svc.cluster.local"},
		},
		{
			name:       "an unresolved service and a rejected literal are both reported",
			res:        rpWithUnresolved("rp-1", []string{"2001:db8::1"}, nil, "api.prod.svc.cluster.local"),
			wantStatus: metav1.ConditionFalse,
			wantReason: v1alpha1.ReasonUnresolvedServices,
			wantIn:     []string{"api.prod.svc.cluster.local", "2001:db8::1"},
		},
		{
			name:       "an unresolved service is not reported as an absence of targets",
			res:        rpWithUnresolved("rp-1", nil, nil, "api.prod.svc.cluster.local"),
			wantStatus: metav1.ConditionFalse,
			wantReason: v1alpha1.ReasonUnresolvedServices,
			wantIn:     []string{"api.prod.svc.cluster.local"},
		},
		{
			name: "several unresolved services are all named",
			res: rpWithUnresolved("rp-1", nil, nil,
				"api.prod.svc.cluster.local", "cache.staging.svc.cluster.local"),
			wantStatus: metav1.ConditionFalse,
			wantReason: v1alpha1.ReasonUnresolvedServices,
			wantIn:     []string{"api.prod.svc.cluster.local", "cache.staging.svc.cluster.local"},
		},
		{
			name:       "no unresolved services keeps the supported reason",
			res:        rpWithUnresolved("rp-1", []string{"1.1.1.1"}, nil),
			wantStatus: metav1.ConditionTrue,
			wantReason: v1alpha1.ReasonAllTargetsSupported,
		},
		{
			name:       "no unresolved services and no targets keeps the empty reason",
			res:        rpWithUnresolved("rp-1", nil, nil),
			wantStatus: metav1.ConditionTrue,
			wantReason: v1alpha1.ReasonNoTargets,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _, status := newTestManager()

			mustRpEvent(t, e, tc.res, events.EventTypeCreate)

			cond, ok := status.latest("rp-1", v1alpha1.ConditionTargetsValid)
			if !ok {
				t.Fatalf("no %s condition was recorded for rp-1 (all: %v)", v1alpha1.ConditionTargetsValid, status.all("rp-1"))
			}
			if cond.Status != tc.wantStatus {
				t.Errorf("condition status: got %s, want %s (message %q)", cond.Status, tc.wantStatus, cond.Message)
			}
			if cond.Reason != tc.wantReason {
				t.Errorf("condition reason: got %s, want %s (message %q)", cond.Reason, tc.wantReason, cond.Message)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(cond.Message, want) {
					t.Errorf("condition message %q does not mention %q", cond.Message, want)
				}
			}
		})
	}
}

// the update path reports the condition too, so a Service that resolves on a
// later evaluation clears the failure.
func TestTargetsConditionClearsWhenAServiceResolves(t *testing.T) {
	e, _, status := newTestManager()

	mustRpEvent(t, e, rpWithUnresolved("rp-1", nil, []string{"*"}, "api.prod.svc.cluster.local"), events.EventTypeCreate)
	mustRpEvent(t, e, rpWithUnresolved("rp-1", []string{"10.0.0.1"}, []string{"*"}), events.EventTypeUpdate)

	cond, ok := status.latest("rp-1", v1alpha1.ConditionTargetsValid)
	if !ok {
		t.Fatalf("no %s condition was recorded for rp-1", v1alpha1.ConditionTargetsValid)
	}
	if cond.Status != metav1.ConditionTrue || cond.Reason != v1alpha1.ReasonAllTargetsSupported {
		t.Errorf("condition after the Service resolved: got %s/%s, want %s/%s",
			cond.Status, cond.Reason, metav1.ConditionTrue, v1alpha1.ReasonAllTargetsSupported)
	}
}
