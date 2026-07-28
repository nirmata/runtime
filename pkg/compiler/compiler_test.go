package compiler

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	"github.com/google/go-cmp/cmp"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// newTestCompiler builds a Compiler backed by a fake dynamic client, so no
// network/apiserver access happens during Compile/Evaluate.
func newTestCompiler(t *testing.T) *compiler {
	t.Helper()
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme)
	c, err := NewCompiler(client)
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
		if !res.Selector.Matches(labels.Set{"app": "nginx"}) {
			t.Error("Selector should match pod with label app=nginx")
		}
		if res.Selector.Matches(labels.Set{"app": "other"}) {
			t.Error("Selector should not match pod with label app=other")
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
		if res.Selector.Matches(labels.Set{"app": "nginx"}) {
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

// aiBehavior is a terse constructor for the AI behavior under test.
func aiBehavior(b v1alpha1.AIBehavior) v1alpha1.PolicyBehavior {
	return v1alpha1.PolicyBehavior{AI: &b}
}

func int32Ptr(v int32) *int32 { return &v }

func modePtr(m v1alpha1.RuntimePolicyMode) *v1alpha1.RuntimePolicyMode { return &m }

// TestCompile_ProposalAIPolicies compiles the five worked policies of the
// proposal (§2.4), adjusted to the shipped CRD: an author copying an example out
// of the design must get a policy that compiles, including the two that carry no
// `match` at all (discovery and the MCP allowlist).
func TestCompile_ProposalAIPolicies(t *testing.T) {
	c := newTestCompiler(t)

	tests := []struct {
		name string
		rp   v1alpha1.RuntimePolicy
	}{
		{
			// (1) ai-discovery: inventory only, no findings, no enforcement.
			name: "sample 1 ai-discovery",
			rp: v1alpha1.RuntimePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ai-discovery"},
				Spec: v1alpha1.RuntimePolicySpec{
					Mode:        modePtr(v1alpha1.PolicyModeDiscover),
					PodSelector: &metav1.LabelSelector{},
					Behaviors: []v1alpha1.PolicyBehavior{
						aiBehavior(v1alpha1.AIBehavior{
							Classes: []v1alpha1.AITrafficClass{
								v1alpha1.AIClassLLM, v1alpha1.AIClassMCP, v1alpha1.AIClassA2A,
							},
						}),
					},
				},
			},
		},
		{
			// (2) unsanctioned-llm-egress: the allowlist comes from a
			// ConfigMap through the EXISTING resource lib + variables +
			// values∪expression machinery; only `match` is new.
			name: "sample 2 unsanctioned-llm-egress",
			rp: v1alpha1.RuntimePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "unsanctioned-llm-egress"},
				Spec: v1alpha1.RuntimePolicySpec{
					Mode:               modePtr(v1alpha1.PolicyModeMonitor),
					EvaluationInterval: &metav1.Duration{Duration: 15 * time.Minute},
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"ai.nirmata.io/workload": "true"},
					},
					Variables: []admissionregistrationv1.Variable{{
						Name: "approved",
						Expression: `resource.Get("v1", "configmaps", "kyverno-runtime", "approved-ai-providers")` +
							`.data["providers"].split(",")`,
					}},
					Behaviors: []v1alpha1.PolicyBehavior{
						aiBehavior(v1alpha1.AIBehavior{
							Classes:       []v1alpha1.AITrafficClass{v1alpha1.AIClassLLM},
							Severity:      "high",
							MinConfidence: int32Ptr(60),
							Allow: behaviorRule(
								[]string{"provider:anthropic", "provider:bedrock"},
								"variables.approved",
							),
							Match: `event.ai.class == "llm" && ` +
								`!(event.ai.provider in ["anthropic", "bedrock"]) && ` +
								`event.ai.confidence >= 60`,
						}),
					},
				},
			},
		},
		{
			// (3) mcp-allowlist: default-deny plus hostname and
			// "mcp-server:" targets, no `match`.
			name: "sample 3 mcp-allowlist",
			rp: v1alpha1.RuntimePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "mcp-allowlist"},
				Spec: v1alpha1.RuntimePolicySpec{
					Mode: modePtr(v1alpha1.PolicyModeEnforce),
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "agent-runtime"},
					},
					Behaviors: []v1alpha1.PolicyBehavior{
						aiBehavior(v1alpha1.AIBehavior{
							Classes:  []v1alpha1.AITrafficClass{v1alpha1.AIClassMCP},
							Severity: "critical",
							Deny:     behaviorRule([]string{StarTarget}, ""),
							Allow: behaviorRule([]string{
								"mcp.internal.corp",
								"mcp-server:@modelcontextprotocol/server-filesystem",
								"mcp-server:@modelcontextprotocol/server-git",
							}, ""),
						}),
					},
				},
			},
		},
		{
			// (4) external-a2a-discovery: cidr() comes from the base env, so
			// it is available per event.
			name: "sample 4 external-a2a-discovery",
			rp: v1alpha1.RuntimePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "external-a2a-discovery"},
				Spec: v1alpha1.RuntimePolicySpec{
					Mode:        modePtr(v1alpha1.PolicyModeMonitor),
					PodSelector: &metav1.LabelSelector{},
					Behaviors: []v1alpha1.PolicyBehavior{
						aiBehavior(v1alpha1.AIBehavior{
							Classes:  []v1alpha1.AITrafficClass{v1alpha1.AIClassA2A},
							Severity: "medium",
							Match: `event.http.path.startsWith("/.well-known/agent") && ` +
								`!cidr("10.0.0.0/8").containsIP(event.net.destIP)`,
						}),
					},
				},
			},
		},
		{
			// (5) metadata-only degraded mode, with evidence membership
			// instead of the proposal's ill-typed `evidence == "sni"`.
			name: "sample 5 metadata-only degraded mode",
			rp: v1alpha1.RuntimePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "metadata-only"},
				Spec: v1alpha1.RuntimePolicySpec{
					Mode: modePtr(v1alpha1.PolicyModeMonitor),
					Behaviors: []v1alpha1.PolicyBehavior{
						aiBehavior(v1alpha1.AIBehavior{
							Classes:  []v1alpha1.AITrafficClass{v1alpha1.AIClassLLM},
							Severity: "low",
							Match: `"sni" in event.ai.evidence && ` +
								`event.ai.provider == "unknown" && ` +
								`event.net.destPort == 443`,
						}),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := c.Compile(tt.rp)
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}
			if len(compiled.compiledAIs) != 1 {
				t.Fatalf("compiledAIs = %d, want 1", len(compiled.compiledAIs))
			}
			ai := compiled.compiledAIs[0]
			wantMatch := tt.rp.Spec.Behaviors[0].AI.Match != ""
			if (ai.match != nil) != wantMatch {
				t.Errorf("match predicate present = %v, want %v", ai.match != nil, wantMatch)
			}
			if ai.match != nil {
				if got := ai.match.Source(); got != tt.rp.Spec.Behaviors[0].AI.Match {
					t.Errorf("match Source() = %q, want the authored expression", got)
				}
				if ai.match.policy != tt.rp.Name {
					t.Errorf("match policy label = %q, want %q", ai.match.policy, tt.rp.Name)
				}
			}
			// An AI behavior programs nothing in the kernel.
			if len(compiled.compiledNets) != 0 || len(compiled.compiledExecs) != 0 || len(compiled.compiledOpens) != 0 {
				t.Errorf("an ai behavior produced net/exec/open behaviors: %d/%d/%d",
					len(compiled.compiledNets), len(compiled.compiledExecs), len(compiled.compiledOpens))
			}
		})
	}
}

// TestCompile_AIBehaviorErrorPaths pins that a bad AI behavior is rejected at
// the exact field that caused it -- the same contract as the other behaviors,
// so admission feedback points at the offending line.
func TestCompile_AIBehaviorErrorPaths(t *testing.T) {
	tests := []struct {
		name      string
		behavior  v1alpha1.AIBehavior
		wantField string
		wantErr   string
	}{
		{
			name:      "match is not a bool",
			behavior:  v1alpha1.AIBehavior{Match: `event.ai.provider`},
			wantField: "spec.behaviors[0].ai.match",
			wantErr:   "invalid return type string for match expression",
		},
		{
			name:      "match references an undefined field",
			behavior:  v1alpha1.AIBehavior{Match: `event.ai.klass == "llm"`},
			wantField: "spec.behaviors[0].ai.match",
			wantErr:   "undefined field 'klass'",
		},
		{
			name:      "match reaches for an I/O library",
			behavior:  v1alpha1.AIBehavior{Match: `http.Get("http://x").status == 200`},
			wantField: "spec.behaviors[0].ai.match",
			wantErr:   "undeclared reference to 'http'",
		},
		{
			name:      "allow expression is not a list of string",
			behavior:  v1alpha1.AIBehavior{Allow: behaviorRule(nil, `"a-string"`)},
			wantField: "spec.behaviors[0].ai",
			wantErr:   "invalid return type for array",
		},
		{
			name:      "deny expression does not compile",
			behavior:  v1alpha1.AIBehavior{Deny: behaviorRule(nil, `variables.missing`)},
			wantField: "spec.behaviors[0].ai",
			wantErr:   "undefined field 'missing'",
		},
	}

	c := newTestCompiler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Compile(v1alpha1.RuntimePolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "bad-ai"},
				Spec: v1alpha1.RuntimePolicySpec{
					Behaviors: []v1alpha1.PolicyBehavior{aiBehavior(tt.behavior)},
				},
			})
			if err == nil {
				t.Fatal("Compile() error = nil, want a field error")
			}
			var fieldErr *field.Error
			if !errors.As(err, &fieldErr) {
				t.Fatalf("Compile() error = %v (%T), want a *field.Error", err, err)
			}
			if fieldErr.Field != tt.wantField {
				t.Errorf("field = %q, want %q", fieldErr.Field, tt.wantField)
			}
			if !strings.Contains(fieldErr.Detail, tt.wantErr) {
				t.Errorf("detail = %q, want it to contain %q", fieldErr.Detail, tt.wantErr)
			}
		})
	}
}

// TestCompile_AIBehaviorTargetsAreNotIPValidated pins the deliberate asymmetry
// with network behaviors: AI targets are destination IDENTITIES (hostname globs,
// provider tokens, package names), so the IPv4-only validation that guards the
// BPF maps must not be applied to them -- while it still rejects the same value
// under `network`.
func TestCompile_AIBehaviorTargetsAreNotIPValidated(t *testing.T) {
	c := newTestCompiler(t)
	values := []string{"api.openai.com", "*.openai.azure.com", "provider:anthropic", "mcp-server:@modelcontextprotocol/server-git"}

	if _, err := c.Compile(v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ai-hostnames"},
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				aiBehavior(v1alpha1.AIBehavior{Allow: behaviorRule(values, "")}),
			},
		},
	}); err != nil {
		t.Errorf("Compile() with ai hostname targets error = %v, want nil", err)
	}

	if _, err := c.Compile(v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "net-hostnames"},
		Spec: v1alpha1.RuntimePolicySpec{
			Behaviors: []v1alpha1.PolicyBehavior{
				{Network: &v1alpha1.Behavior{Allow: behaviorRule(values, "")}},
			},
		},
	}); err == nil {
		t.Error("Compile() with network hostname targets error = nil, want the IPv4-only validation to reject them")
	}
}

// TestNewCompiler_OptionsAreAdditive pins that the new options are optional:
// the daemon's existing single-argument call keeps working and still gets a
// usable per-event env (backed by the embedded catalog).
func TestNewCompiler_OptionsAreAdditive(t *testing.T) {
	c := newTestCompiler(t)
	if c.eventEnv == nil {
		t.Fatal("NewCompiler(client) left eventEnv nil; match expressions could not compile")
	}
	if c.metrics != nil {
		t.Error("NewCompiler(client) set metrics, want nil until WithMetrics is passed")
	}
	if _, err := c.compileMatchExpression(`ai.provider(event.tls.sni) == "openai"`); err != nil {
		t.Errorf("compileMatchExpression() with the default catalog error = %v", err)
	}
}
