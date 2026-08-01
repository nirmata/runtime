package compiler

import (
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// fakeResolver resolves only the refs present in its map. An entry with an
// empty address list is a Service that exists with no ready endpoints, which
// the interface distinguishes from an absent Service.
type fakeResolver struct {
	services map[v1alpha1.ServiceReference][]string
}

func (f fakeResolver) ResolveService(ref v1alpha1.ServiceReference) ([]string, bool) {
	addrs, found := f.services[ref]
	return addrs, found
}

func svcRef(name, namespace string) v1alpha1.ServiceReference {
	return v1alpha1.ServiceReference{Name: name, Namespace: namespace}
}

func refRule(values []string, refs ...v1alpha1.ServiceReference) *v1alpha1.BehaviorRule {
	return &v1alpha1.BehaviorRule{Values: values, ServiceRefs: refs}
}

func netPolicy(b *v1alpha1.Behavior) v1alpha1.RuntimePolicy {
	return v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{{Network: b}},
		},
	}
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

func TestEvaluate_ServiceRefsResolveOntoTheirOwnSide(t *testing.T) {
	resolver := fakeResolver{services: map[v1alpha1.ServiceReference][]string{
		svcRef("api", "prod"):     {"10.0.0.2", "10.0.0.1"},
		svcRef("metrics", "prod"): {"10.1.0.1"},
	}}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: refRule(nil, svcRef("api", "prod")),
		Deny:  refRule(nil, svcRef("metrics", "prod")),
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
	if len(res.UnresolvedServiceRefs) != 0 {
		t.Errorf("UnresolvedServiceRefs = %v, want none", res.UnresolvedServiceRefs)
	}
}

func TestEvaluate_ServiceRefsAreNotResolvedAtCompileTime(t *testing.T) {
	ref := svcRef("api", "prod")
	resolver := fakeResolver{services: map[v1alpha1.ServiceReference][]string{}}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{Allow: refRule(nil, ref)}))
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

	resolver.services[ref] = []string{"10.0.0.1"}
	res, err = compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if diff := cmp.Diff([]string{"10.0.0.1"}, res.IPs.Allow); diff != "" {
		t.Errorf("IPs.Allow mismatch after the Service appeared (-want +got):\n%s", diff)
	}
}

func TestEvaluate_ServiceRefsAndLiteralValuesDeduplicate(t *testing.T) {
	resolver := fakeResolver{services: map[v1alpha1.ServiceReference][]string{
		svcRef("api", "prod"):       {"10.0.0.1", "10.0.0.2"},
		svcRef("api-alias", "prod"): {"10.0.0.2", "10.0.0.3"},
	}}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: refRule([]string{"10.0.0.1"}, svcRef("api", "prod"), svcRef("api-alias", "prod")),
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

func TestEvaluate_UnresolvedServiceRefContributesNoAddresses(t *testing.T) {
	resolver := fakeResolver{services: map[v1alpha1.ServiceReference][]string{
		svcRef("present", "prod"): {"10.0.0.1"},
	}}
	c := newTestCompilerWithResolver(t, resolver)

	missing := svcRef("missing", "prod")
	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: refRule(nil, svcRef("present", "prod"), missing),
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
	if diff := cmp.Diff([]v1alpha1.ServiceReference{missing}, res.UnresolvedServiceRefs); diff != "" {
		t.Errorf("UnresolvedServiceRefs mismatch (-want +got):\n%s", diff)
	}
}

func TestEvaluate_ResolvedServiceWithNoEndpointsIsNotUnresolved(t *testing.T) {
	scaledToZero := svcRef("scaled-to-zero", "prod")
	resolver := fakeResolver{services: map[v1alpha1.ServiceReference][]string{
		scaledToZero: {},
	}}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{Allow: refRule(nil, scaledToZero)}))
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
	if len(res.UnresolvedServiceRefs) != 0 {
		t.Errorf("UnresolvedServiceRefs = %v, want none for a Service that exists", res.UnresolvedServiceRefs)
	}
}

func TestEvaluate_ServiceRefsCoexistWithDefaultDenySentinel(t *testing.T) {
	resolver := fakeResolver{services: map[v1alpha1.ServiceReference][]string{
		svcRef("api", "prod"): {"10.0.0.1"},
	}}
	c := newTestCompilerWithResolver(t, resolver)

	compiled, err := c.Compile(netPolicy(&v1alpha1.Behavior{
		Allow: refRule(nil, svcRef("api", "prod")),
		Deny:  refRule([]string{StarTarget}),
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

func TestEvaluate_ServiceRefOrderingIsStableAcrossEvaluations(t *testing.T) {
	resolver := fakeResolver{services: map[v1alpha1.ServiceReference][]string{
		svcRef("a", "prod"): {"10.0.0.3", "10.0.0.1"},
		svcRef("b", "prod"): {"10.0.0.2"},
		svcRef("c", "prod"): {"10.2.0.1", "10.1.0.1"},
	}}
	c := newTestCompilerWithResolver(t, resolver)

	missing := svcRef("missing", "prod")
	compiled, err := c.Compile(v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{
					Allow: refRule([]string{"10.9.9.9"}, svcRef("a", "prod"), missing),
					Deny:  refRule([]string{StarTarget}, svcRef("c", "prod")),
				}},
				{Network: &v1alpha1.Behavior{
					Allow: refRule(nil, svcRef("b", "prod"), missing),
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
		if diff := cmp.Diff(first.UnresolvedServiceRefs, next.UnresolvedServiceRefs); diff != "" {
			t.Fatalf("successive Evaluate() UnresolvedServiceRefs differ (-first +next):\n%s", diff)
		}
	}

	want := &AllowDenyPair{
		Allow: []string{"10.9.9.9", "10.0.0.1", "10.0.0.3", "10.0.0.2"},
		Deny:  []string{StarTarget, "10.1.0.1", "10.2.0.1"},
	}
	if diff := cmp.Diff(want, first.IPs); diff != "" {
		t.Errorf("IPs mismatch (-want +got):\n%s", diff)
	}
}
