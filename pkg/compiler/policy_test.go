package compiler

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/go-cmp/cmp"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAllowDenyPair_HasEntries(t *testing.T) {
	tests := []struct {
		name string
		p    *AllowDenyPair
		want bool
	}{
		{name: "nil receiver", p: nil, want: false},
		{name: "empty pair", p: &AllowDenyPair{}, want: false},
		{name: "empty slices explicitly", p: &AllowDenyPair{Allow: []string{}, Deny: []string{}}, want: false},
		{name: "only allow populated", p: &AllowDenyPair{Allow: []string{"a"}}, want: true},
		{name: "only deny populated", p: &AllowDenyPair{Deny: []string{"d"}}, want: true},
		{name: "both populated", p: &AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.HasEntries(); got != tt.want {
				t.Errorf("HasEntries() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllowDenyPair_DiffPair(t *testing.T) {
	tests := []struct {
		name   string
		p      *AllowDenyPair
		target *AllowDenyPair
		want   *AllowDenyPair
	}{
		{
			name:   "nil target returns empty pair",
			p:      &AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}},
			target: nil,
			want:   &AllowDenyPair{},
		},
		{
			name:   "nil receiver returns target unchanged",
			p:      nil,
			target: &AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}},
			want:   &AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}},
		},
		{
			name:   "nil receiver and nil target",
			p:      nil,
			target: nil,
			want:   &AllowDenyPair{},
		},
		{
			name:   "both empty",
			p:      &AllowDenyPair{},
			target: &AllowDenyPair{},
			want:   &AllowDenyPair{},
		},
		{
			name:   "disjoint entries: everything in target is new",
			p:      &AllowDenyPair{Allow: []string{"a"}, Deny: []string{"x"}},
			target: &AllowDenyPair{Allow: []string{"b"}, Deny: []string{"y"}},
			want:   &AllowDenyPair{Allow: []string{"b"}, Deny: []string{"y"}},
		},
		{
			name:   "identical entries: nothing new in target",
			p:      &AllowDenyPair{Allow: []string{"a", "b"}, Deny: []string{"x", "y"}},
			target: &AllowDenyPair{Allow: []string{"a", "b"}, Deny: []string{"x", "y"}},
			want:   &AllowDenyPair{},
		},
		{
			name:   "overlapping: only entries unique to target survive",
			p:      &AllowDenyPair{Allow: []string{"a", "b"}, Deny: []string{"x"}},
			target: &AllowDenyPair{Allow: []string{"b", "c"}, Deny: []string{"x", "y"}},
			want:   &AllowDenyPair{Allow: []string{"c"}, Deny: []string{"y"}},
		},
		{
			name:   "duplicate entries in target not in p are preserved",
			p:      &AllowDenyPair{Allow: []string{"a"}},
			target: &AllowDenyPair{Allow: []string{"b", "b", "c"}},
			want:   &AllowDenyPair{Allow: []string{"b", "b", "c"}},
		},
		{
			name:   "allow and deny sides are diffed independently",
			p:      &AllowDenyPair{Allow: []string{"shared"}, Deny: []string{}},
			target: &AllowDenyPair{Allow: []string{}, Deny: []string{"shared"}},
			want:   &AllowDenyPair{Deny: []string{"shared"}},
		},
		{
			name:   "empty target sides against non-empty p",
			p:      &AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}},
			target: &AllowDenyPair{},
			want:   &AllowDenyPair{},
		},
		{
			name:   "default deny sentinel is diffed like any other entry",
			p:      &AllowDenyPair{Deny: []string{"*"}},
			target: &AllowDenyPair{Deny: []string{"*", "1.2.3.4"}},
			want:   &AllowDenyPair{Deny: []string{"1.2.3.4"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.p.DiffPair(tt.target)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("DiffPair() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEvaluate_MergesHardcodedAndExpressionValuesPerKind(t *testing.T) {
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{
					Network: &v1alpha1.Behavior{
						Allow: behaviorRule([]string{"1.1.1.1"}, `["2.2.2.2"]`),
						Deny:  behaviorRule([]string{"3.3.3.3"}, `["4.4.4.4"]`),
					},
					Open: &v1alpha1.Behavior{
						Allow: behaviorRule([]string{"/open/allow/hardcoded"}, ""),
					},
					Exec: &v1alpha1.Behavior{
						Deny: behaviorRule([]string{"/exec/deny/hardcoded"}, ""),
					},
					Protocol: &v1alpha1.Behavior{
						Allow: behaviorRule([]string{"tls/h2"}, `["quic"]`),
						Deny:  behaviorRule([]string{"*"}, `["ssh"]`),
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

	// expression results are accumulated before the hardcoded values, and the
	// behavior kinds stay independent accumulators.
	if diff := cmp.Diff(&AllowDenyPair{Allow: []string{"2.2.2.2", "1.1.1.1"}, Deny: []string{"4.4.4.4", "3.3.3.3"}}, res.IPs); diff != "" {
		t.Errorf("IPs mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(&AllowDenyPair{Allow: []string{"/open/allow/hardcoded"}}, res.Open); diff != "" {
		t.Errorf("Open mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(&AllowDenyPair{Deny: []string{"/exec/deny/hardcoded"}}, res.Exec); diff != "" {
		t.Errorf("Exec mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(&AllowDenyPair{Allow: []string{"quic", "tls/h2"}, Deny: []string{"ssh", "*"}}, res.Protocols); diff != "" {
		t.Errorf("Protocols mismatch (-want +got):\n%s", diff)
	}
}

func TestEvaluate_MultipleBehaviorsOfSameKindAccumulate(t *testing.T) {
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"1.1.1.1"}, "")}},
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"2.2.2.2"}, "")}},
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
	if diff := cmp.Diff([]string{"1.1.1.1", "2.2.2.2"}, res.IPs.Allow); diff != "" {
		t.Errorf("IPs.Allow mismatch (-want +got):\n%s", diff)
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
	if _, err := compiled.Evaluate(t.Context()); err == nil {
		t.Fatal("Evaluate() expected error for invalid label selector operator, got nil")
	}
}

func TestEvaluate_EvalErrorsPropagate(t *testing.T) {
	// runtime (not compile time) CEL failures must surface as Evaluate errors
	// rather than a partial result.
	tests := []struct {
		name string
		spec v1alpha1.RuntimePolicySpec
	}{
		{
			name: "error inside a variable expression referenced by a behavior",
			spec: v1alpha1.RuntimePolicySpec{
				Variables: []admissionregistrationv1.Variable{
					// type-checks as list<string>, divides by zero at eval time.
					{Name: "bad", Expression: `[1,2,0].map(i, string(1/i))`},
				},
				Behaviors: []v1alpha1.PolicyBehavior{
					{Network: &v1alpha1.Behavior{Allow: behaviorRule(nil, `variables.bad`)}},
				},
			},
		},
		{
			name: "error inside a behavior expression",
			spec: v1alpha1.RuntimePolicySpec{
				Behaviors: []v1alpha1.PolicyBehavior{
					{Network: &v1alpha1.Behavior{Allow: behaviorRule(nil, `[1,2,0].map(i, string(1/i))`)}},
				},
			},
		},
	}

	c := newTestCompiler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := c.Compile(v1alpha1.RuntimePolicy{Spec: tt.spec})
			if err != nil {
				t.Fatalf("Compile() unexpected error = %v", err)
			}
			if _, err := compiled.Evaluate(t.Context()); err == nil {
				t.Fatal("Evaluate() expected a runtime error to propagate, got nil")
			}
		})
	}
}

// panickingVal is a ref.Val whose conversion panics. Conversion of a program
// result happens in this package (toStringSlice), OUTSIDE cel-go's own
// recover, so this is the panic class that only utils.Guard catches.
type panickingVal struct{}

func (panickingVal) ConvertToNative(reflect.Type) (any, error) {
	panic("deliberate panic converting a CEL result")
}
func (panickingVal) ConvertToType(ref.Type) ref.Val { return types.NewErr("unsupported conversion") }
func (panickingVal) Equal(ref.Val) ref.Val          { return types.False }
func (panickingVal) Type() ref.Type                 { return types.ListType }
func (panickingVal) Value() any                     { return nil }

// newPanickingCompiler builds a compiler whose CEL env exposes two hostile
// functions, standing in for any third-party CEL library binding reachable
// from a user-authored expression:
//
//	boom() -- panics inside its binding, i.e. inside cel-go's interpreter;
//	evil() -- returns a value that panics when this package converts it.
func newPanickingCompiler(t *testing.T) *compiler {
	t.Helper()
	base, err := newBaseEnv()
	if err != nil {
		t.Fatalf("newBaseEnv() error = %v", err)
	}
	provider := newVariablesProvider(base.CELTypeProvider())
	env, err := base.Extend(
		cel.Variable(variablesKey, VariablesType),
		cel.CustomTypeProvider(provider),
		cel.Function("boom",
			cel.Overload("boom_list_string", nil, types.NewListType(types.StringType),
				cel.FunctionBinding(func(...ref.Val) ref.Val {
					panic("deliberate panic inside a CEL binding")
				}),
			),
		),
		cel.Function("evil",
			cel.Overload("evil_list_string", nil, types.NewListType(types.StringType),
				cel.FunctionBinding(func(...ref.Val) ref.Val { return panickingVal{} }),
			),
		),
	)
	if err != nil {
		t.Fatalf("Extend() error = %v", err)
	}
	return &compiler{env: env}
}

// TestEvaluate_PanickingCELBindingBecomesError covers the other half:
// a CEL function that panics inside the interpreter must surface as an
// evaluation error (cel-go recovers it, and Evaluate must not mask it).
func TestEvaluate_PanickingCELBindingBecomesError(t *testing.T) {
	c := newPanickingCompiler(t)

	tests := []struct {
		name string
		spec v1alpha1.RuntimePolicySpec
	}{
		{
			name: "panicking function in a behavior expression",
			spec: v1alpha1.RuntimePolicySpec{
				Behaviors: []v1alpha1.PolicyBehavior{
					{Open: &v1alpha1.Behavior{Deny: behaviorRule(nil, `boom()`)}},
				},
			},
		},
		{
			name: "panicking function reached through a variable",
			spec: v1alpha1.RuntimePolicySpec{
				Variables: []admissionregistrationv1.Variable{
					{Name: "bad", Expression: `boom()`},
				},
				Behaviors: []v1alpha1.PolicyBehavior{
					{Open: &v1alpha1.Behavior{Deny: behaviorRule(nil, `variables.bad`)}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := c.Compile(v1alpha1.RuntimePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "panicky"},
				Spec:       tt.spec,
			})
			if err != nil {
				t.Fatalf("Compile() unexpected error = %v", err)
			}
			res, err := compiled.Evaluate(t.Context())
			if err == nil {
				t.Fatal("Evaluate() error = nil, want the panic converted to an error")
			}
			if res != nil {
				t.Errorf("Evaluate() result = %+v with an error, want nil", res)
			}
			if !strings.Contains(err.Error(), "deliberate panic inside a CEL binding") {
				t.Errorf("Evaluate() error = %q, want it to carry the panic message", err.Error())
			}
		})
	}
}
