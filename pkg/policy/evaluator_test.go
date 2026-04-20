package policy

import (
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

func TestMatchesPolicySelectors(t *testing.T) {
	e := NewEvaluator()

	policy := &v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}}}

	ok, err := e.MatchesPolicy(policy, pod, map[string]string{"env": "prod"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected policy to match")
	}

	ok, err = e.MatchesPolicy(policy, pod, map[string]string{"env": "dev"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected policy not to match")
	}
}

func TestMatchesPolicyRejectsNonPodResourceRules(t *testing.T) {
	e := NewEvaluator()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{}}}

	cases := []struct {
		name    string
		rules   []admissionregistrationv1.NamedRuleWithOperations
		wantErr bool
	}{
		{
			name: "pods allowed",
			rules: []admissionregistrationv1.NamedRuleWithOperations{{
				RuleWithOperations: admissionregistrationv1.RuleWithOperations{
					Rule: admissionregistrationv1.Rule{APIGroups: []string{""}, Resources: []string{"pods"}},
				},
			}},
			wantErr: false,
		},
		{
			name: "deployments rejected",
			rules: []admissionregistrationv1.NamedRuleWithOperations{{
				RuleWithOperations: admissionregistrationv1.RuleWithOperations{
					Rule: admissionregistrationv1.Rule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
				},
			}},
			wantErr: true,
		},
		{
			name: "wrong api group rejected",
			rules: []admissionregistrationv1.NamedRuleWithOperations{{
				RuleWithOperations: admissionregistrationv1.RuleWithOperations{
					Rule: admissionregistrationv1.Rule{APIGroups: []string{"apps"}, Resources: []string{"pods"}},
				},
			}},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					MatchConstraints: &admissionregistrationv1.MatchResources{
						ResourceRules: tc.rules,
					},
				},
			}
			_, err := e.MatchesPolicy(p, pod, nil)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestEvaluateRuntime_OpenPolicyMatchesWithPathAliases(t *testing.T) {
	e := NewEvaluator()

	policy := &v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name:     "detect-sensitive-open",
				Event:    "open",
				Severity: "high",
				Message:  "Sensitive file open detected",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["fname"].contains("/etc/hosts") || event["file.path"].contains("/etc/hosts")`,
				}},
			}},
		},
	}

	events := []runtimeevents.Event{{
		Type: "open",
		Fields: map[string]string{
			"path": "/etc/hosts",
		},
	}}

	result := e.EvaluateRuntime(policy, events)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].RuleName != "detect-sensitive-open" {
		t.Fatalf("unexpected rule name: %s", result.Findings[0].RuleName)
	}
}

func TestBuildCELActivationAddsOpenFieldAliases(t *testing.T) {
	activation := buildCELActivation(runtimeevents.Event{
		Type: "open",
		Fields: map[string]string{
			"path": "/tmp/demo.txt",
		},
	})

	eventMap, ok := activation["event"].(map[string]string)
	if !ok {
		t.Fatalf("expected event map in activation")
	}
	if eventMap["file.path"] != "/tmp/demo.txt" {
		t.Fatalf("expected file.path alias, got %q", eventMap["file.path"])
	}
	if eventMap["fname"] != "/tmp/demo.txt" {
		t.Fatalf("expected fname alias, got %q", eventMap["fname"])
	}
}

func TestCompileCELProgramCacheHitMiss(t *testing.T) {
	e := NewEvaluator()

	prog1, err := e.compileCELProgram(`event["type"] == "open"`)
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}
	prog2, err := e.compileCELProgram(`event["type"] == "open"`)
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}
	if prog1 == nil || prog2 == nil {
		t.Fatal("expected non-nil programs")
	}
	if e.cacheMiss.Load() != 1 {
		t.Fatalf("expected 1 cache miss, got %d", e.cacheMiss.Load())
	}
	if e.cacheHits.Load() != 1 {
		t.Fatalf("expected 1 cache hit, got %d", e.cacheHits.Load())
	}
}
