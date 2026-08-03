package compiler

import (
	"errors"
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	"github.com/google/go-cmp/cmp"
)

func TestIsObserveMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want bool
	}{
		{name: "enforce", mode: ModeEnforce, want: false},
		{name: "monitor", mode: ModeMonitor, want: true},
		{name: "empty", mode: "", want: false},
		{name: "unknown", mode: "audit", want: false},
		{name: "case sensitive", mode: "Monitor", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsObserveMode(tt.mode); got != tt.want {
				t.Errorf("IsObserveMode(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestModeConstantsMatchAPI(t *testing.T) {
	if ModeEnforce != string(v1alpha1.PolicyModeEnforce) {
		t.Errorf("ModeEnforce = %q, want %q", ModeEnforce, v1alpha1.PolicyModeEnforce)
	}
	if ModeMonitor != string(v1alpha1.PolicyModeMonitor) {
		t.Errorf("ModeMonitor = %q, want %q", ModeMonitor, v1alpha1.PolicyModeMonitor)
	}
}

// TestCompile_RejectsBadNetworkValuesWithFieldPath pins the admission-time
// half: an unsupported hardcoded network target is rejected with the field
// path of the exact offending value instead of being dropped silently when it
// reaches the BPF maps.
func TestCompile_RejectsBadNetworkValuesWithFieldPath(t *testing.T) {
	tests := []struct {
		name      string
		behaviors []v1alpha1.PolicyBehavior
		wantPaths []string
	}{
		{
			name: "IPv6 in network deny values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Deny: behaviorRule([]string{"1.2.3.4", "2001:db8::1"}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].network.deny.values[1]"},
		},
		{
			name: "wildcard hostname in network allow values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"*.openai.com"}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].network.allow.values[0]"},
		},
		{
			name: "single-label hostname in network allow values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"localhost"}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].network.allow.values[0]"},
		},
		{
			name: "pod record in network allow values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"kube-dns.kube-system.svc.cluster.local", "10-1-2-3.default.pod.cluster.local"}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].network.allow.values[1]"},
		},
		{
			name: "Service name in another cluster domain",
			behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"foo.bar.svc.example.com"}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].network.allow.values[0]"},
		},
		{
			name: "offenders in both allow and deny of the second behavior",
			behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Deny: behaviorRule([]string{"*"}, "")}},
				{Network: &v1alpha1.Behavior{
					Allow: behaviorRule([]string{"not-an-ip"}, ""),
					Deny:  behaviorRule([]string{"10.0.0.1", "also-not-an-ip"}, ""),
				}},
			},
			wantPaths: []string{
				"spec.behaviors[1].network.allow.values[0]",
				"spec.behaviors[1].network.deny.values[1]",
			},
		},
	}

	c := newTestCompiler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Compile(v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{Behaviors: tt.behaviors},
			})
			if err == nil {
				t.Fatal("Compile() error = nil, want rejection of unsupported network values")
			}
			for _, want := range tt.wantPaths {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Compile() error = %q, want it to name %q", err.Error(), want)
				}
			}
		})
	}
}

// Admission must never reject a value the runtime accepts, so every form
// ParseNetworkValue admits has to survive Compile untouched.
func TestCompile_AcceptsEveryNetworkValueForm(t *testing.T) {
	values := []string{"1.2.3.4", "10.0.0.0/24", "*", "api.openai.com", "Example.COM.", "redis.default"}

	c := newTestCompiler(t)
	compiled, err := c.Compile(v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule(values, "")}},
			},
		},
	})
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if diff := cmp.Diff(values, res.IPs.Allow); diff != "" {
		t.Errorf("IPs.Allow mismatch (-want +got):\n%s", diff)
	}
}

func TestCompile_WildcardHostnameErrorNamesTheRemedy(t *testing.T) {
	c := newTestCompiler(t)
	_, err := c.Compile(v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Deny: behaviorRule([]string{"*.openai.com"}, "")}},
			},
		},
	})
	if err == nil {
		t.Fatal("Compile() error = nil, want rejection of a wildcard hostname")
	}
	if !strings.Contains(err.Error(), ErrWildcardNetworkValue.Error()) {
		t.Errorf("Compile() error = %q, want it to contain %q", err.Error(), ErrWildcardNetworkValue.Error())
	}
}

func TestCompile_AcceptsCanonicalClusterServiceValues(t *testing.T) {
	c := newTestCompiler(t)
	if _, err := c.Compile(v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{
					Allow: behaviorRule([]string{"kube-dns.kube-system.svc.cluster.local", "API.Default.SVC.Cluster.Local."}, ""),
					Deny:  behaviorRule([]string{"redis.2ns.svc.cluster.local"}, ""),
				}},
			},
		},
	}); err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}
}

// Admission owns no grammar of its own: the message an operator sees is the one
// ParseNetworkValue produced for the same value.
func TestCompile_ClusterServiceErrorsComeFromTheOneGrammar(t *testing.T) {
	values := []string{
		"kube-dns.svc.cluster.local",
		"pod-0.redis.default.svc.cluster.local",
		"foo.bar.svc.example.com",
		"1redis.default.svc.cluster.local",
	}

	c := newTestCompiler(t)
	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			_, want := ParseNetworkValue(v)
			if want == nil {
				t.Fatalf("ParseNetworkValue(%q) error = nil, want a rejection", v)
			}
			_, err := c.Compile(v1alpha1.RuntimePolicy{
				Spec: v1alpha1.RuntimePolicySpec{
					Behaviors: []v1alpha1.PolicyBehavior{
						{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{v}, "")}},
					},
				},
			})
			if err == nil {
				t.Fatalf("Compile() error = nil, want rejection of %q", v)
			}
			if !strings.Contains(err.Error(), want.Error()) {
				t.Errorf("Compile() error = %q, want it to contain %q", err.Error(), want.Error())
			}
			if errors.Is(want, ErrServiceLabelNetworkValue) {
				return
			}
			if !strings.Contains(err.Error(), "<service>.<namespace>.svc.") || !strings.Contains(err.Error(), ClusterDomain) {
				t.Errorf("Compile() error = %q, want it to name the canonical form and %q", err.Error(), ClusterDomain)
			}
		})
	}
}

// open and exec targets are paths, not addresses: they must not be run through
// the network validation.
func TestCompile_DoesNotValidateOpenAndExecValuesAsNetworkTargets(t *testing.T) {
	c := newTestCompiler(t)

	compiled, err := c.Compile(v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Open: &v1alpha1.Behavior{Deny: behaviorRule([]string{"/etc/shadow"}, "")}},
				{Exec: &v1alpha1.Behavior{Deny: behaviorRule([]string{"/bin/sh"}, "")}},
			},
		},
	})
	if err != nil {
		t.Fatalf("Compile() unexpected error = %v", err)
	}

	res, err := compiled.Evaluate(t.Context())
	if err != nil {
		t.Fatalf("Evaluate() unexpected error = %v", err)
	}
	if diff := cmp.Diff([]string{"/etc/shadow"}, res.Open.Deny); diff != "" {
		t.Errorf("Open.Deny mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"/bin/sh"}, res.Exec.Deny); diff != "" {
		t.Errorf("Exec.Deny mismatch (-want +got):\n%s", diff)
	}
}
