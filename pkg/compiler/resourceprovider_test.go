package compiler

import (
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// TestResourceProviderToGVR_ReturnsErrorNotPanic_Issue40 pins the direct fix:
// ToGVR is reachable from a user-authored CEL expression, so it must report an
// error instead of panicking.
func TestResourceProviderToGVR_ReturnsErrorNotPanic_Issue40(t *testing.T) {
	tests := []struct {
		name       string
		apiVersion string
		kind       string
	}{
		{name: "group version and kind", apiVersion: "apps/v1", kind: "Deployment"},
		{name: "core version and kind", apiVersion: "v1", kind: "Pod"},
		{name: "empty arguments", apiVersion: "", kind: ""},
		{name: "garbage arguments", apiVersion: "///", kind: "\x00"},
	}

	rp := newResourceProvider(dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gvr, err := rp.ToGVR(tt.apiVersion, tt.kind)
			if err == nil {
				t.Fatalf("ToGVR(%q, %q) error = nil, want an error", tt.apiVersion, tt.kind)
			}
			if gvr != nil {
				t.Errorf("ToGVR() = %v, want nil alongside the error", gvr)
			}
			if !strings.Contains(err.Error(), "not implemented") {
				t.Errorf("ToGVR() error = %q, want it to say the function is not implemented", err.Error())
			}
		})
	}
}

// TestEvaluate_ToGVRPolicyFailsWithoutCrashing_Issue40 is the end-to-end half:
// the policy from issue #40 must fail evaluation, not take the process down.
func TestEvaluate_ToGVRPolicyFailsWithoutCrashing_Issue40(t *testing.T) {
	c := newTestCompiler(t)

	rp := v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "crash", UID: "uid-crash"},
		Spec: v1alpha1.RuntimePolicySpec{
			Variables: []admissionregistrationv1.Variable{
				{Name: "gvr", Expression: `resource.toGVR("apps/v1", "Deployment")`},
			},
			Behaviors: []v1alpha1.PolicyBehavior{
				{Open: &v1alpha1.Behavior{
					// forces the lazily evaluated variable to be resolved.
					Deny: behaviorRule(nil, `variables.gvr == variables.gvr ? ["/etc/shadow"] : ["/etc/passwd"]`),
				}},
			},
		},
	}

	compiled, err := c.Compile(rp)
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err == nil {
		t.Fatalf("Evaluate() error = nil (result %+v), want an error from resource.toGVR", res)
	}
	if res != nil {
		t.Errorf("Evaluate() result = %+v with an error, want nil", res)
	}
	if !strings.Contains(err.Error(), "toGVR") {
		t.Errorf("Evaluate() error = %q, want it to mention toGVR", err.Error())
	}
}
