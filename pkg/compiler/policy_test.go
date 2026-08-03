package compiler

import (
	"reflect"
	"slices"
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

// mapResolver resolves only the Services present in its map, keyed
// "namespace/name". An entry with an empty address list is a Service that
// exists with no ready endpoints, which the interface distinguishes from an
// absent Service.
type mapResolver struct {
	services map[string][]string
}

func (m mapResolver) ResolveService(namespace, name string) ([]string, bool) {
	addrs, found := m.services[namespace+"/"+name]
	return addrs, found
}

// recordingResolver resolves nothing and remembers what it was asked for.
type recordingResolver struct {
	calls []string
}

func (r *recordingResolver) ResolveService(namespace, name string) ([]string, bool) {
	r.calls = append(r.calls, namespace+"/"+name)
	return nil, false
}

func svcValue(name, namespace string) string {
	return name + "." + namespace + ".svc." + ClusterDomain
}

func netPolicy(b *v1alpha1.Behavior) v1alpha1.RuntimePolicy {
	return v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{{Network: b}},
		},
	}
}

func TestEvaluate_ServiceValueIsReplacedByItsAddressesOnItsOwnSide(t *testing.T) {
	resolver := mapResolver{services: map[string][]string{
		"prod/api":     {"10.0.0.2", "10.0.0.1"},
		"prod/metrics": {"10.1.0.1"},
	}}
	c := newTestCompilerWithResolver(t, resolver)

	api := svcValue("api", "prod")
	metrics := svcValue("metrics", "prod")
	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: behaviorRule([]string{api}, ""),
		Deny:  behaviorRule([]string{metrics}, ""),
	}))
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	want := &AllowDenyPair{Allow: []string{"10.0.0.1", "10.0.0.2"}, Deny: []string{"10.1.0.1"}}
	if diff := cmp.Diff(want, res.IPs); diff != "" {
		t.Errorf("IPs mismatch (-want +got):\n%s", diff)
	}
	if slices.Contains(res.IPs.Allow, api) || slices.Contains(res.IPs.Deny, metrics) {
		t.Errorf("IPs = %+v, want the Service DNS names replaced, not kept alongside their addresses", res.IPs)
	}
	if len(res.UnresolvedServices) != 0 {
		t.Errorf("UnresolvedServices = %v, want none", res.UnresolvedServices)
	}
}

func TestEvaluate_ServiceValueInDenyResolvesIntoDeny(t *testing.T) {
	resolver := mapResolver{services: map[string][]string{"prod/api": {"10.0.0.1"}}}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Deny: behaviorRule([]string{svcValue("api", "prod")}, ""),
	}))
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if diff := cmp.Diff([]string{"10.0.0.1"}, res.IPs.Deny); diff != "" {
		t.Errorf("IPs.Deny mismatch (-want +got):\n%s", diff)
	}
	if len(res.IPs.Allow) != 0 {
		t.Errorf("IPs.Allow = %v, want none", res.IPs.Allow)
	}
}

func TestEvaluate_ServiceValuesAreResolvedAtEvaluationTime(t *testing.T) {
	resolver := mapResolver{services: map[string][]string{}}
	c := newTestCompilerWithResolver(t, resolver)

	value := svcValue("api", "prod")
	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{Allow: behaviorRule([]string{value}, "")}))
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if len(res.IPs.Allow) != 0 {
		t.Fatalf("IPs.Allow = %v before the Service exists, want none", res.IPs.Allow)
	}

	resolver.services["prod/api"] = []string{"10.0.0.1"}
	res, err = compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if diff := cmp.Diff([]string{"10.0.0.1"}, res.IPs.Allow); diff != "" {
		t.Errorf("IPs.Allow mismatch after the Service appeared (-want +got):\n%s", diff)
	}
}

func TestEvaluate_LiteralAndServiceValuesDeduplicate(t *testing.T) {
	resolver := mapResolver{services: map[string][]string{
		"prod/api":       {"10.0.0.1", "10.0.0.2"},
		"prod/api-alias": {"10.0.0.2", "10.0.0.3"},
	}}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: behaviorRule([]string{"10.0.0.1", svcValue("api", "prod"), svcValue("api-alias", "prod")}, ""),
	}))
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if diff := cmp.Diff(want, res.IPs.Allow); diff != "" {
		t.Errorf("IPs.Allow mismatch (-want +got):\n%s", diff)
	}
}

func TestEvaluate_UnresolvedServiceValueIsReportedVerbatim(t *testing.T) {
	resolver := mapResolver{services: map[string][]string{"prod/present": {"10.0.0.1"}}}
	c := newTestCompilerWithResolver(t, resolver)

	missing := svcValue("missing", "prod")
	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: behaviorRule([]string{svcValue("present", "prod"), missing}, ""),
	}))
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if diff := cmp.Diff([]string{"10.0.0.1"}, res.IPs.Allow); diff != "" {
		t.Errorf("IPs.Allow mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{missing}, res.UnresolvedServices); diff != "" {
		t.Errorf("UnresolvedServices mismatch (-want +got):\n%s", diff)
	}
}

func TestEvaluate_ResolvedServiceWithNoEndpointsIsNotUnresolved(t *testing.T) {
	resolver := mapResolver{services: map[string][]string{"prod/scaled-to-zero": {}}}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: behaviorRule([]string{svcValue("scaled-to-zero", "prod")}, ""),
	}))
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if len(res.IPs.Allow) != 0 {
		t.Errorf("IPs.Allow = %v, want none", res.IPs.Allow)
	}
	if len(res.UnresolvedServices) != 0 {
		t.Errorf("UnresolvedServices = %v, want none for a Service that exists", res.UnresolvedServices)
	}
}

func TestEvaluate_ExternalHostnameIsNotResolved(t *testing.T) {
	resolver := &recordingResolver{}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: behaviorRule([]string{"api.example.com"}, ""),
	}))
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if diff := cmp.Diff([]string{"api.example.com"}, res.IPs.Allow); diff != "" {
		t.Errorf("IPs.Allow mismatch (-want +got):\n%s", diff)
	}
	if len(resolver.calls) != 0 {
		t.Errorf("resolver was called with %v, want an external hostname never resolved", resolver.calls)
	}
	if len(res.UnresolvedServices) != 0 {
		t.Errorf("UnresolvedServices = %v, want none", res.UnresolvedServices)
	}
}

func TestEvaluate_ServiceValuesCoexistWithDefaultDenySentinel(t *testing.T) {
	resolver := mapResolver{services: map[string][]string{"prod/api": {"10.0.0.1"}}}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: behaviorRule([]string{svcValue("api", "prod")}, ""),
		Deny:  behaviorRule([]string{StarTarget}, ""),
	}))
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	want := &AllowDenyPair{Allow: []string{"10.0.0.1"}, Deny: []string{StarTarget}}
	if diff := cmp.Diff(want, res.IPs); diff != "" {
		t.Errorf("IPs mismatch (-want +got):\n%s", diff)
	}
}

func TestEvaluate_ResolvedOutputIsStableAcrossEvaluations(t *testing.T) {
	resolver := mapResolver{services: map[string][]string{
		"prod/a": {"10.0.0.3", "10.0.0.1"},
		"prod/b": {"10.0.0.2"},
		"prod/c": {"10.2.0.1", "10.1.0.1"},
	}}
	c := newTestCompilerWithResolver(t, resolver)

	missing := svcValue("missing", "prod")
	compiled, err := c.Compile(v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{
					Allow: behaviorRule([]string{"10.9.9.9", svcValue("a", "prod"), missing}, ""),
					Deny:  behaviorRule([]string{StarTarget, svcValue("c", "prod")}, ""),
				}},
				{Network: &v1alpha1.Behavior{
					Allow: behaviorRule([]string{svcValue("b", "prod"), missing}, ""),
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	first, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	for range 5 {
		next, err := compiled.Evaluate(t.Context())
		if err != nil {
			t.Fatalf("Evaluate() unexpected error = %v", err)
		}
		if diff := cmp.Diff(first.IPs, next.IPs); diff != "" {
			t.Fatalf("successive Evaluate() IPs differ (-first +next):\n%s", diff)
		}
		if diff := cmp.Diff(first.UnresolvedServices, next.UnresolvedServices); diff != "" {
			t.Fatalf("successive Evaluate() UnresolvedServices differ (-first +next):\n%s", diff)
		}
	}

	want := &AllowDenyPair{
		Allow: []string{"10.9.9.9", "10.0.0.1", "10.0.0.3", "10.0.0.2"},
		Deny:  []string{StarTarget, "10.1.0.1", "10.2.0.1"},
	}
	if diff := cmp.Diff(want, first.IPs); diff != "" {
		t.Errorf("IPs mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{missing}, first.UnresolvedServices); diff != "" {
		t.Errorf("UnresolvedServices mismatch (-want +got):\n%s", diff)
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

	// expression results are accumulated before the hardcoded values, and the
	// three behavior kinds stay independent accumulators.
	if diff := cmp.Diff(&AllowDenyPair{Allow: []string{"2.2.2.2", "1.1.1.1"}, Deny: []string{"4.4.4.4", "3.3.3.3"}}, res.IPs); diff != "" {
		t.Errorf("IPs mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(&AllowDenyPair{Allow: []string{"open-allow-hardcoded"}}, res.Open); diff != "" {
		t.Errorf("Open mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(&AllowDenyPair{Deny: []string{"exec-deny-hardcoded"}}, res.Exec); diff != "" {
		t.Errorf("Exec mismatch (-want +got):\n%s", diff)
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
	return &compiler{env: env, resolver: mapResolver{}}
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
