package egressmgr

import (
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func svcRef(namespace, name string) v1alpha1.ServiceReference {
	return v1alpha1.ServiceReference{Namespace: namespace, Name: name}
}

func rpWithUnresolved(uid string, allow, deny []string, unresolved ...v1alpha1.ServiceReference) *compiler.EvaluationResult {
	res := rp(uid, "enforce", webLabels, allow, deny)
	res.UnresolvedServiceRefs = unresolved
	return res
}

func TestTargetsConditionReportsUnresolvedServiceRefs(t *testing.T) {
	tests := []struct {
		name       string
		res        *compiler.EvaluationResult
		wantStatus metav1.ConditionStatus
		wantReason string
		wantIn     []string
	}{
		{
			name:       "an unresolved ref is the policy's only target",
			res:        rpWithUnresolved("rp-1", nil, []string{"*"}, svcRef("prod", "api")),
			wantStatus: metav1.ConditionFalse,
			wantReason: ReasonUnresolvedServiceRefs,
			wantIn:     []string{"prod/api"},
		},
		{
			name:       "resolved literals alongside an unresolved ref",
			res:        rpWithUnresolved("rp-1", []string{"1.1.1.1"}, []string{"*"}, svcRef("prod", "api")),
			wantStatus: metav1.ConditionFalse,
			wantReason: ReasonUnresolvedServiceRefs,
			wantIn:     []string{"prod/api"},
		},
		{
			name:       "an unresolved ref and a rejected literal are both reported",
			res:        rpWithUnresolved("rp-1", []string{"api.example.com"}, nil, svcRef("prod", "api")),
			wantStatus: metav1.ConditionFalse,
			wantReason: ReasonUnresolvedServiceRefs,
			wantIn:     []string{"prod/api", "api.example.com"},
		},
		{
			name:       "several unresolved refs are all named",
			res:        rpWithUnresolved("rp-1", nil, nil, svcRef("prod", "api"), svcRef("staging", "cache")),
			wantStatus: metav1.ConditionFalse,
			wantReason: ReasonUnresolvedServiceRefs,
			wantIn:     []string{"prod/api", "staging/cache"},
		},
		{
			name:       "no unresolved refs keeps the supported reason",
			res:        rpWithUnresolved("rp-1", []string{"1.1.1.1"}, nil),
			wantStatus: metav1.ConditionTrue,
			wantReason: ReasonAllTargetsSupported,
		},
		{
			name:       "no unresolved refs and no targets keeps the empty reason",
			res:        rpWithUnresolved("rp-1", nil, nil),
			wantStatus: metav1.ConditionTrue,
			wantReason: ReasonNoTargets,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _, status := newTestManager()

			mustRpEvent(t, e, tc.res, events.EventTypeCreate)

			cond, ok := status.latest("rp-1", ConditionTargetsValid)
			if !ok {
				t.Fatalf("no %s condition was recorded for rp-1 (all: %v)", ConditionTargetsValid, status.all("rp-1"))
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

// the update path reports the condition too, so a ref that resolves on a later
// evaluation clears the failure.
func TestTargetsConditionClearsWhenAServiceRefResolves(t *testing.T) {
	e, _, status := newTestManager()

	mustRpEvent(t, e, rpWithUnresolved("rp-1", nil, []string{"*"}, svcRef("prod", "api")), events.EventTypeCreate)
	mustRpEvent(t, e, rpWithUnresolved("rp-1", []string{"10.0.0.1"}, []string{"*"}), events.EventTypeUpdate)

	cond, ok := status.latest("rp-1", ConditionTargetsValid)
	if !ok {
		t.Fatalf("no %s condition was recorded for rp-1", ConditionTargetsValid)
	}
	if cond.Status != metav1.ConditionTrue || cond.Reason != ReasonAllTargetsSupported {
		t.Errorf("condition after the ref resolved: got %s/%s, want %s/%s",
			cond.Status, cond.Reason, metav1.ConditionTrue, ReasonAllTargetsSupported)
	}
}
