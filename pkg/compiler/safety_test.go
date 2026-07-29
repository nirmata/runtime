package compiler

import (
	"fmt"
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

func TestValidateNetworkValues(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		// wantIdx lists the input indexes expected to be reported invalid.
		wantIdx []int
	}{
		{name: "no values", in: nil},
		{name: "IPv4 literal", in: []string{"1.2.3.4"}},
		{name: "IPv4 literal with padding and quotes", in: []string{" \"10.0.0.1\" "}},
		{name: "IPv4 CIDR /24", in: []string{"10.0.0.0/24"}},
		{name: "IPv4 CIDR /32", in: []string{"10.0.0.1/32"}},
		{name: "wide IPv4 CIDR accepted at admission time", in: []string{"10.0.0.0/8"}},
		{name: "default deny sentinel", in: []string{"*"}},
		{name: "mixed valid values", in: []string{"1.2.3.4", "10.0.0.0/24", "*"}},
		{name: "IPv4 mapped IPv6 literal", in: []string{"::ffff:1.2.3.4"}},

		{name: "IPv6 literal rejected", in: []string{"2001:db8::1"}, wantIdx: []int{0}},
		{name: "IPv6 CIDR rejected", in: []string{"2001:db8::/32"}, wantIdx: []int{0}},
		{name: "hostname rejected", in: []string{"api.openai.com"}, wantIdx: []int{0}},
		{name: "url rejected", in: []string{"https://api.openai.com/v1"}, wantIdx: []int{0}},
		{name: "empty string rejected", in: []string{""}, wantIdx: []int{0}},
		{name: "whitespace only rejected", in: []string{"   "}, wantIdx: []int{0}},
		{name: "partial address rejected", in: []string{"10.0.0"}, wantIdx: []int{0}},
		{name: "glob other than star rejected", in: []string{"*.openai.com"}, wantIdx: []int{0}},
		{name: "bad mask rejected", in: []string{"10.0.0.0/64"}, wantIdx: []int{0}},
		{
			name:    "only the invalid entries of a mixed list are reported",
			in:      []string{"1.2.3.4", "example.com", "10.0.0.0/24", "2001:db8::1"},
			wantIdx: []int{1, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateNetworkValues(tt.in)
			if len(errs) != len(tt.wantIdx) {
				t.Fatalf("ValidateNetworkValues(%v) = %v, want %d errors", tt.in, errs, len(tt.wantIdx))
			}
			for i, idx := range tt.wantIdx {
				marker := fmt.Sprintf("values[%d]", idx)
				if !strings.Contains(errs[i].Error(), marker) {
					t.Errorf("error %d = %q, want it to name %q", i, errs[i], marker)
				}
			}
		})
	}
}

// TestCompile_RejectsBadNetworkValuesWithFieldPath pins the admission-time half
// of #41: an unsupported hardcoded network target is rejected with the field
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
			name: "hostname in network allow values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule([]string{"api.openai.com"}, "")}},
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
