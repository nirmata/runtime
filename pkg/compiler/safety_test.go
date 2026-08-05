package compiler

import (
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

// TestCompile_RejectsBadPathValuesWithFieldPath pins the admission-time half for
// exec and open: a value the kernel maps cannot hold is rejected with the field
// path of the exact offender rather than being dropped when it reaches those
// maps. Both behaviors are checked because both program the same maps, so a
// schema enforced for only one of them is not a chokepoint.
func TestCompile_RejectsBadPathValuesWithFieldPath(t *testing.T) {
	tooLong := "/" + strings.Repeat("a", MaxPathValueLen)
	tests := []struct {
		name      string
		behaviors []v1alpha1.PolicyBehavior
		wantPaths []string
	}{
		{
			name: "over-length path in exec deny values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Exec: &v1alpha1.Behavior{Deny: behaviorRule([]string{"/bin/sh", tooLong}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].exec.deny.values[1]"},
		},
		{
			name: "empty value in exec allow values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Exec: &v1alpha1.Behavior{Allow: behaviorRule([]string{"  "}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].exec.allow.values[0]"},
		},
		{
			name: "NUL byte in exec deny values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Exec: &v1alpha1.Behavior{Deny: behaviorRule([]string{"/bin/sh\x00"}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].exec.deny.values[0]"},
		},
		{
			name: "over-length path in open deny values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Open: &v1alpha1.Behavior{Deny: behaviorRule([]string{"/etc/shadow", tooLong}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].open.deny.values[1]"},
		},
		{
			name: "NUL byte in open deny values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Open: &v1alpha1.Behavior{Deny: behaviorRule([]string{"/etc/shadow\x00"}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].open.deny.values[0]"},
		},
		{
			name: "relative path in open allow values",
			behaviors: []v1alpha1.PolicyBehavior{
				{Open: &v1alpha1.Behavior{Allow: behaviorRule([]string{"etc/hosts"}, "")}},
			},
			wantPaths: []string{"spec.behaviors[0].open.allow.values[0]"},
		},
		{
			name: "offenders in both allow and deny of the second behavior",
			behaviors: []v1alpha1.PolicyBehavior{
				{Exec: &v1alpha1.Behavior{Deny: behaviorRule([]string{"*"}, "")}},
				{Exec: &v1alpha1.Behavior{
					Allow: behaviorRule([]string{""}, ""),
					Deny:  behaviorRule([]string{"/bin/sh", tooLong}, ""),
				}},
			},
			wantPaths: []string{
				"spec.behaviors[1].exec.allow.values[0]",
				"spec.behaviors[1].exec.deny.values[1]",
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
				t.Fatal("Compile() error = nil, want rejection of unsupported exec values")
			}
			for _, want := range tt.wantPaths {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Compile() error = %q, want it to name %q", err.Error(), want)
				}
			}
		})
	}
}
