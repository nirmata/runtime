package compiler

import (
	"errors"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	"github.com/google/go-cmp/cmp"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// newTestCompiler builds a Compiler backed by a fake dynamic client, so no
// network/apiserver access happens during Compile/Evaluate.
func newTestCompiler(t *testing.T) *compiler {
	t.Helper()
	return newTestCompilerWithResolver(t, mapResolver{})
}

func newTestCompilerWithResolver(t *testing.T, resolver ServiceResolver) *compiler {
	t.Helper()
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme)
	c, err := NewCompiler(client, resolver)
	if err != nil {
		t.Fatalf("NewCompiler() error = %v", err)
	}
	got, ok := c.(*compiler)
	if !ok {
		t.Fatalf("NewCompiler() returned %T, want *compiler", c)
	}
	return got
}

func behaviorRule(values []string, expr string) *v1alpha1.BehaviorRule {
	return &v1alpha1.BehaviorRule{Values: values, Expression: expr}
}

func TestNewCompiler_NilResolverPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewCompiler() with a nil resolver did not panic")
		}
	}()
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	if _, err := NewCompiler(client, nil); err != nil {
		t.Fatalf("NewCompiler() error = %v, want a panic", err)
	}
}

func TestCompile_ValidBehaviors(t *testing.T) {
	tests := []struct {
		name string
		rp   v1alpha1.RuntimePolicy
	}{
		{
			name: "hardcoded values only for network",
			rp: v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Behaviors: []v1alpha1.PolicyBehavior{
						{Network: &v1alpha1.Behavior{
							Allow: behaviorRule([]string{"1.2.3.4"}, ""),
							Deny:  behaviorRule([]string{"5.6.7.8"}, ""),
						}},
					},
				},
			},
		},
		{
			name: "hardcoded values only for open",
			rp: v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Behaviors: []v1alpha1.PolicyBehavior{
						{Open: &v1alpha1.Behavior{
							Allow: behaviorRule([]string{"/etc/passwd"}, ""),
						}},
					},
				},
			},
		},
		{
			name: "hardcoded values only for exec",
			rp: v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Behaviors: []v1alpha1.PolicyBehavior{
						{Exec: &v1alpha1.Behavior{
							Deny: behaviorRule([]string{"/bin/sh"}, ""),
						}},
					},
				},
			},
		},
		{
			name: "hardcoded values only for protocol",
			rp: v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Behaviors: []v1alpha1.PolicyBehavior{
						{Protocol: &v1alpha1.Behavior{
							Allow: behaviorRule([]string{"tls/h2", "tls/http/1.1"}, ""),
							Deny:  behaviorRule([]string{"*", "ssh"}, ""),
						}},
					},
				},
			},
		},
		{
			name: "valid CEL expression returning list<string>",
			rp: v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Behaviors: []v1alpha1.PolicyBehavior{
						{Network: &v1alpha1.Behavior{
							Allow: behaviorRule(nil, `["1.2.3.4", "5.6.7.8"]`),
						}},
					},
				},
			},
		},
		{
			name: "multiple behavior kinds in one entry",
			rp: v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Behaviors: []v1alpha1.PolicyBehavior{
						{
							Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"1.1.1.1"}, "")},
							Open:    &v1alpha1.Behavior{Allow: behaviorRule([]string{"/tmp"}, "")},
							Exec:    &v1alpha1.Behavior{Allow: behaviorRule([]string{"/bin/ls"}, "")},
						},
					},
				},
			},
		},
		{
			name: "default deny sentinel in network deny values",
			rp: v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Behaviors: []v1alpha1.PolicyBehavior{
						{Network: &v1alpha1.Behavior{
							Allow: behaviorRule([]string{"10.0.0.0/24"}, ""),
							Deny:  behaviorRule([]string{"*"}, ""),
						}},
					},
				},
			},
		},
		{
			name: "empty policy compiles",
			rp:   v1alpha1.RuntimePolicy{},
		},
	}

	c := newTestCompiler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Compile(tt.rp)
			if err != nil {
				t.Fatalf("Compile() unexpected error = %v", err)
			}
			if got == nil {
				t.Fatal("Compile() returned nil CompiledRuntimePolicy with no error")
			}
		})
	}
}

func TestCompile_InvalidReturnType(t *testing.T) {
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{
					Allow: behaviorRule(nil, `1 + 1`), // returns int, not list<string>
				}},
			},
		},
	}

	_, err := c.Compile(rp)
	if err == nil {
		t.Fatal("Compile() expected error for non-list<string> expression output, got nil")
	}

	var fieldErr *field.Error
	if !errors.As(err, &fieldErr) {
		t.Fatalf("Compile() error type = %T, want *field.Error", err)
	}
	if fieldErr.Field != "spec.behaviors[0].network" {
		t.Errorf("Compile() error field path = %q, want %q", fieldErr.Field, "spec.behaviors[0].network")
	}
	if fieldErr.Detail != "invalid return type for array" {
		t.Errorf("Compile() error detail = %q, want %q", fieldErr.Detail, "invalid return type for array")
	}
}

func TestCompile_InvalidExpressionErrorPaths(t *testing.T) {
	// each behavior kind should propagate a field.Invalid error naming its
	// own index/kind when the expression is syntactically broken.
	tests := []struct {
		name      string
		behaviors []v1alpha1.PolicyBehavior
		wantField string
	}{
		{
			name: "syntax error in network at index 0",
			behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule(nil, `this is + not valid cel`)}},
			},
			wantField: "spec.behaviors[0].network",
		},
		{
			name: "syntax error in open at index 0",
			behaviors: []v1alpha1.PolicyBehavior{
				{Open: &v1alpha1.Behavior{Deny: behaviorRule(nil, `this is + not valid cel`)}},
			},
			wantField: "spec.behaviors[0].open",
		},
		{
			name: "syntax error in exec at index 0",
			behaviors: []v1alpha1.PolicyBehavior{
				{Exec: &v1alpha1.Behavior{Allow: behaviorRule(nil, `this is + not valid cel`)}},
			},
			wantField: "spec.behaviors[0].exec",
		},
		{
			name: "syntax error in protocol at index 0",
			behaviors: []v1alpha1.PolicyBehavior{
				{Protocol: &v1alpha1.Behavior{Deny: behaviorRule(nil, `this is + not valid cel`)}},
			},
			wantField: "spec.behaviors[0].protocol",
		},
		{
			name: "syntax error at second index",
			behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"1.1.1.1"}, "")}},
				{Network: &v1alpha1.Behavior{Allow: behaviorRule(nil, `this is + not valid cel`)}},
			},
			wantField: "spec.behaviors[1].network",
		},
	}

	c := newTestCompiler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{Behaviors: tt.behaviors},
			}
			_, err := c.Compile(rp)
			if err == nil {
				t.Fatal("Compile() expected error for invalid expression, got nil")
			}
			var fieldErr *field.Error
			if !errors.As(err, &fieldErr) {
				t.Fatalf("Compile() error type = %T, want *field.Error", err)
			}
			if fieldErr.Field != tt.wantField {
				t.Errorf("Compile() error field path = %q, want %q", fieldErr.Field, tt.wantField)
			}
		})
	}
}

func TestCompile_VariablesRoundTrip(t *testing.T) {
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Variables: []admissionregistrationv1.Variable{
				{Name: "allowedIPs", Expression: `["10.0.0.1", "10.0.0.2"]`},
			},
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{
					Allow: behaviorRule(nil, `variables.allowedIPs`),
				}},
			},
		},
	}

	compiled, err := c.Compile(rp)
	if err != nil {
		t.Fatalf("Compile() unexpected error referencing declared variable = %v", err)
	}
	if len(compiled.variables) != 1 {
		t.Fatalf("compiled variables = %d, want 1", len(compiled.variables))
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2"}
	if diff := cmp.Diff(want, res.IPs.Allow); diff != "" {
		t.Errorf("IPs.Allow mismatch (-want +got):\n%s", diff)
	}
}

func TestCompile_VariableInvalidExpression(t *testing.T) {
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Variables: []admissionregistrationv1.Variable{
				{Name: "bad", Expression: `this is + not valid cel`},
			},
		},
	}

	_, err := c.Compile(rp)
	if err == nil {
		t.Fatal("Compile() expected error for invalid variable expression, got nil")
	}
	var fieldErr *field.Error
	if !errors.As(err, &fieldErr) {
		t.Fatalf("Compile() error type = %T, want *field.Error", err)
	}
	if fieldErr.Field != "spec.variables[0].expression" {
		t.Errorf("Compile() error field path = %q, want %q", fieldErr.Field, "spec.variables[0].expression")
	}
}

func TestCompile_UndeclaredVariableReference(t *testing.T) {
	// referencing variables.foo without declaring "foo" in spec.variables
	// must fail to compile (registerField never happened for "foo").
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{
					Allow: behaviorRule(nil, `variables.foo`),
				}},
			},
		},
	}

	if _, err := c.Compile(rp); err == nil {
		t.Fatal("Compile() expected error for undeclared variable reference, got nil")
	}
}

func TestCompile_ModeUIDNameIntervalSelectorPropagate(t *testing.T) {
	c := newTestCompiler(t)
	enforce := v1alpha1.PolicyModeEnforce

	t.Run("explicit fields propagate", func(t *testing.T) {
		rp := v1alpha1.RuntimePolicy{
			ObjectMeta: metav1.ObjectMeta{UID: "abc-123", Name: "block-egress"},
			Spec: v1alpha1.RuntimePolicySpec{
				Mode:               &enforce,
				EvaluationInterval: &metav1.Duration{Duration: 5 * time.Minute},
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "nginx"},
				},
			},
		}

		compiled, err := c.Compile(rp)
		if err != nil {
			t.Fatalf("Compile() unexpected error = %v", err)
		}
		if compiled.UID != "abc-123" {
			t.Errorf("UID = %q, want %q", compiled.UID, "abc-123")
		}
		if compiled.Name != "block-egress" {
			t.Errorf("Name = %q, want %q", compiled.Name, "block-egress")
		}
		if compiled.ReevalInterval == nil || *compiled.ReevalInterval != 5*time.Minute {
			t.Errorf("ReevalInterval = %v, want %v", compiled.ReevalInterval, 5*time.Minute)
		}

		res, err := compiled.Evaluate(t.Context())
		if err != nil {
			t.Fatalf("Evaluate() unexpected error = %v", err)
		}
		if res.Mode != string(enforce) {
			t.Errorf("Mode = %q, want %q", res.Mode, enforce)
		}
		if res.UID != "abc-123" {
			t.Errorf("UID = %q, want %q", res.UID, "abc-123")
		}
		if res.Name != "block-egress" {
			t.Errorf("Name = %q, want %q", res.Name, "block-egress")
		}
		if !res.AppliesTo.Matches(nil, map[string]string{"app": "nginx"}) {
			t.Error("target should match pod with label app=nginx")
		}
		if res.AppliesTo.Matches(nil, map[string]string{"app": "other"}) {
			t.Error("target should not match pod with label app=other")
		}
	})

	t.Run("nil EvaluationInterval defaults to zero duration, not nil", func(t *testing.T) {
		compiled, err := c.Compile(v1alpha1.RuntimePolicy{})
		if err != nil {
			t.Fatalf("Compile() unexpected error = %v", err)
		}
		if compiled.ReevalInterval == nil {
			t.Fatal("ReevalInterval is nil, want a pointer to zero duration")
		}
		if *compiled.ReevalInterval != 0 {
			t.Errorf("ReevalInterval = %v, want 0", *compiled.ReevalInterval)
		}
	})

	t.Run("nil mode and nil selector propagate as empty/nothing", func(t *testing.T) {
		compiled, err := c.Compile(v1alpha1.RuntimePolicy{})
		if err != nil {
			t.Fatalf("Compile() unexpected error = %v", err)
		}
		res, err := compiled.Evaluate(t.Context())
		if err != nil {
			t.Fatalf("Evaluate() unexpected error = %v", err)
		}
		if res.Mode != "" {
			t.Errorf("Mode = %q, want empty string", res.Mode)
		}
		// nil PodSelector maps to labels.Nothing(), which must not match any pod.
		if res.AppliesTo.Matches(nil, map[string]string{"app": "nginx"}) {
			t.Error("nil selector should match nothing")
		}
	})

	t.Run("monitor mode propagates and is an observe mode", func(t *testing.T) {
		monitor := v1alpha1.PolicyModeMonitor
		compiled, err := c.Compile(v1alpha1.RuntimePolicy{
			Spec: v1alpha1.RuntimePolicySpec{Mode: &monitor},
		})
		if err != nil {
			t.Fatalf("Compile() unexpected error = %v", err)
		}
		res, err := compiled.Evaluate(t.Context())
		if err != nil {
			t.Fatalf("Evaluate() unexpected error = %v", err)
		}
		if res.Mode != ModeMonitor {
			t.Errorf("Mode = %q, want %q", res.Mode, ModeMonitor)
		}
		if !IsObserveMode(res.Mode) {
			t.Errorf("IsObserveMode(%q) = false, want true", res.Mode)
		}
	})
}
