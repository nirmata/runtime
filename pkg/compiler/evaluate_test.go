package compiler_test

import (
	"reflect"
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEvaluate_MergesHardcodedAndExpressionValuesPerKind(t *testing.T) {
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{
					Network: &v1alpha1.Behavior{
						Allow: behaviorRule([]string{"net-allow-hardcoded"}, `["net-allow-expr"]`),
						Deny:  behaviorRule([]string{"net-deny-hardcoded"}, `["net-deny-expr"]`),
					},
					Open: &v1alpha1.Behavior{
						Allow: behaviorRule([]string{"open-allow-hardcoded"}, ""),
					},
					Exec: &v1alpha1.Behavior{
						Deny: behaviorRule([]string{"exec-deny-hardcoded"}, ""),
					},
				},
			},
		},
	}

	compiled, err := c.Compile(rp)
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}

	if !reflect.DeepEqual(res.IPs.Allow, []string{"net-allow-expr", "net-allow-hardcoded"}) {
		t.Errorf("IPs.Allow = %v, want expr result before hardcoded values", res.IPs.Allow)
	}
	if !reflect.DeepEqual(res.IPs.Deny, []string{"net-deny-expr", "net-deny-hardcoded"}) {
		t.Errorf("IPs.Deny = %v, want expr result before hardcoded values", res.IPs.Deny)
	}
	if !reflect.DeepEqual(res.Open.Allow, []string{"open-allow-hardcoded"}) {
		t.Errorf("Open.Allow = %v, want %v", res.Open.Allow, []string{"open-allow-hardcoded"})
	}
	if len(res.Open.Deny) != 0 {
		t.Errorf("Open.Deny = %v, want empty", res.Open.Deny)
	}
	if !reflect.DeepEqual(res.Exec.Deny, []string{"exec-deny-hardcoded"}) {
		t.Errorf("Exec.Deny = %v, want %v", res.Exec.Deny, []string{"exec-deny-hardcoded"})
	}
	if len(res.Exec.Allow) != 0 {
		t.Errorf("Exec.Allow = %v, want empty", res.Exec.Allow)
	}
	// net/open/exec pairs must stay independent accumulators.
	if len(res.IPs.Allow) == len(res.Open.Allow) && reflect.DeepEqual(res.IPs.Allow, res.Open.Allow) {
		t.Error("Network and Open allow lists should not be aliased/equal here")
	}
}

func TestEvaluate_MultipleBehaviorsOfSameKindAccumulate(t *testing.T) {
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"a"}, "")}},
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"b"}, "")}},
			},
		},
	}
	compiled, err := c.Compile(rp)
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}
	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if !reflect.DeepEqual(res.IPs.Allow, []string{"a", "b"}) {
		t.Errorf("IPs.Allow = %v, want %v", res.IPs.Allow, []string{"a", "b"})
	}
}

func TestEvaluate_BadLabelSelectorReturnsError(t *testing.T) {
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			PodSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: "NotARealOperator"},
				},
			},
		},
	}

	compiled, err := c.Compile(rp)
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	_, err = compiled.Evaluate(t.Context())
	if err == nil {
		t.Fatal("Evaluate() expected error for invalid label selector operator, got nil")
	}
}

func TestEvaluate_VariableErrorPropagates(t *testing.T) {
	// division by zero at eval time inside a variable expression must
	// surface as an Evaluate() error, not be silently swallowed/ignored.
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Variables: []admissionregistrationv1.Variable{
				// statically typed list<string> so it type-checks as a valid
				// `variables.bad` reference, but errors when actually evaluated.
				{Name: "bad", Expression: `[1,2,0].map(i, string(1/i))`},
			},
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{
					Allow: behaviorRule(nil, `variables.bad`),
				}},
			},
		},
	}

	compiled, err := c.Compile(rp)
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	_, err = compiled.Evaluate(t.Context())
	if err == nil {
		t.Fatal("Evaluate() expected error to propagate from failing variable expression, got nil")
	}
}

func TestEvaluate_ExpressionEvalErrorPropagates(t *testing.T) {
	// a behavior expression that errors at eval time (not compile time)
	// must cause Evaluate() to return an error rather than a partial result.
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{
					// list.map returning strings but dividing by zero to force a runtime error
					Allow: behaviorRule(nil, `[1,2,0].map(i, string(1/i))`),
				}},
			},
		},
	}

	compiled, err := c.Compile(rp)
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	_, err = compiled.Evaluate(t.Context())
	if err == nil {
		t.Fatal("Evaluate() expected runtime error from division by zero, got nil")
	}
}
