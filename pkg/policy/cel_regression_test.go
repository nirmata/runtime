package policy

import (
	"testing"
	"time"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// TestCELAccessMissingFieldReturnsError verifies that accessing a non-existent
// map key in CEL (e.g. event["fname"]) produces an evaluation error rather
// than silently returning a zero-value. This is a regression test for the
// "no such key: fname" issue that caused 0 findings when events lacked the
// expected field.
func TestCELAccessMissingFieldReturnsError(t *testing.T) {
	e := NewEvaluator()

	// Expression accesses event["fname"] but the event has no fname field.
	ok, err := e.evaluateCELBoolean(
		`event["fname"].contains("/etc/hosts")`,
		buildCELActivation(runtimeevents.Event{
			Type:   "open",
			Fields: map[string]string{"proc.comm": "cat"},
		}),
	)
	if err == nil {
		t.Fatal("expected error when accessing missing key 'fname', got nil")
	}
	if ok {
		t.Fatal("expected false result on missing key")
	}
	t.Logf("correctly got error for missing key: %v", err)
}

// TestCELHasGuardPreventsNoSuchKeyError verifies that using has() in CEL
// prevents the "no such key" error. Policies should use this pattern when
// a field might be absent.
func TestCELHasGuardPreventsNoSuchKeyError(t *testing.T) {
	e := NewEvaluator()

	// Use has() guard before accessing the key.
	ok, err := e.evaluateCELBoolean(
		`has(event.fname) && event["fname"].contains("/etc/hosts")`,
		buildCELActivation(runtimeevents.Event{
			Type:   "open",
			Fields: map[string]string{"proc.comm": "cat"},
		}),
	)
	if err != nil {
		t.Fatalf("unexpected error with has() guard: %v", err)
	}
	if ok {
		t.Fatal("expected false when field is missing")
	}
}

// TestCELFieldAliasesPreventMissingKeyForOpenEvents verifies that the
// field aliasing in buildCELActivation cross-populates fname/file.path/path
// so that policies using any of those names will work when only one is
// present in the raw event.
func TestCELFieldAliasesPreventMissingKeyForOpenEvents(t *testing.T) {
	e := NewEvaluator()

	tests := []struct {
		name       string
		fields     map[string]string
		expression string
		wantMatch  bool
	}{
		{
			name:       "fname present directly",
			fields:     map[string]string{"fname": "/etc/hosts"},
			expression: `event["fname"].contains("/etc/hosts")`,
			wantMatch:  true,
		},
		{
			name:       "path aliased to fname",
			fields:     map[string]string{"path": "/etc/hosts"},
			expression: `event["fname"].contains("/etc/hosts")`,
			wantMatch:  true,
		},
		{
			name:       "file.path aliased to fname",
			fields:     map[string]string{"file.path": "/etc/hosts"},
			expression: `event["fname"].contains("/etc/hosts")`,
			wantMatch:  true,
		},
		{
			name:       "fullPath aliased to fname",
			fields:     map[string]string{"fullPath": "/etc/hosts"},
			expression: `event["fname"].contains("/etc/hosts")`,
			wantMatch:  true,
		},
		{
			name:       "fname aliased to file.path",
			fields:     map[string]string{"fname": "/etc/hosts"},
			expression: `event["file.path"].contains("/etc/hosts")`,
			wantMatch:  true,
		},
		{
			name:       "path aliased to file.path",
			fields:     map[string]string{"path": "/etc/hosts"},
			expression: `event["file.path"].contains("/etc/hosts")`,
			wantMatch:  true,
		},
		{
			name:       "non-matching path does not match",
			fields:     map[string]string{"fname": "/etc/passwd"},
			expression: `event["fname"].contains("/etc/hosts")`,
			wantMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			activation := buildCELActivation(runtimeevents.Event{
				Type:   "open",
				Fields: tt.fields,
			})
			ok, err := e.evaluateCELBoolean(tt.expression, activation)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.wantMatch {
				t.Fatalf("expression %q with fields %v: got %v, want %v", tt.expression, tt.fields, ok, tt.wantMatch)
			}
		})
	}
}

// TestCELFieldAliasesForExecEvents verifies that process name aliases
// (comm, proc.comm, process.name) are cross-populated correctly.
func TestCELFieldAliasesForExecEvents(t *testing.T) {
	e := NewEvaluator()

	tests := []struct {
		name       string
		fields     map[string]string
		expression string
		wantMatch  bool
	}{
		{
			name:       "proc.comm aliased to comm",
			fields:     map[string]string{"proc.comm": "cat"},
			expression: `event["comm"] == "cat"`,
			wantMatch:  true,
		},
		{
			name:       "proc.comm aliased to process.name",
			fields:     map[string]string{"proc.comm": "cat"},
			expression: `event["process.name"] == "cat"`,
			wantMatch:  true,
		},
		{
			name:       "exepath preferred over proc.comm for process.name",
			fields:     map[string]string{"exepath": "/bin/sh", "proc.comm": "sh"},
			expression: `event["process.name"] == "/bin/sh"`,
			wantMatch:  true,
		},
		{
			name:       "file used for process.name when exepath missing",
			fields:     map[string]string{"file": "/tmp/iptables", "proc.comm": "iptables"},
			expression: `event["process.name"].contains("iptables")`,
			wantMatch:  true,
		},
		{
			name:       "comm does not overwrite existing process.name",
			fields:     map[string]string{"process.name": "/bin/sh", "comm": "sh"},
			expression: `event["process.name"] == "/bin/sh"`,
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			activation := buildCELActivation(runtimeevents.Event{
				Type:   "exec",
				Fields: tt.fields,
			})
			ok, err := e.evaluateCELBoolean(tt.expression, activation)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tt.wantMatch {
				t.Fatalf("expression %q with fields %v: got %v, want %v", tt.expression, tt.fields, ok, tt.wantMatch)
			}
		})
	}
}

func TestCELNetworkExpressionsAgainstNormalizedDestinationIP(t *testing.T) {
	e := NewEvaluator()
	activation := buildCELActivation(runtimeevents.Event{
		Type: "tcpconnect",
		Fields: map[string]string{
			"destination.ip": "8.8.8.8",
		},
	})

	t.Run("current quickstart expression", func(t *testing.T) {
		ok, err := e.evaluateCELBoolean(
			`(("destination.ip" in event) && (event["destination.ip"] == "8.8.8.8" || event["destination.ip"] == "1.1.1.1")) || (("dst.addr" in event) && (event["dst.addr"] == "8.8.8.8" || event["dst.addr"] == "1.1.1.1"))`,
			activation,
		)
		if err != nil {
			t.Fatalf("unexpected error evaluating current quickstart expression: %v", err)
		}
		if !ok {
			t.Fatal("expected current quickstart network expression to match normalized destination.ip")
		}
	})

	t.Run("simplified normalized destination expression", func(t *testing.T) {
		ok, err := e.evaluateCELBoolean(
			`event["destination.ip"] == "8.8.8.8" || event["destination.ip"] == "1.1.1.1"`,
			activation,
		)
		if err != nil {
			t.Fatalf("unexpected error evaluating simplified network expression: %v", err)
		}
		if !ok {
			t.Fatal("expected simplified network expression to match normalized destination.ip")
		}
	})
}

// TestEvaluateRuntimeOpenPolicyWithIGFields simulates the exact field names
// that Inspektor Gadget trace_open produces and verifies the full evaluation
// pipeline matches.
func TestEvaluateRuntimeOpenPolicyWithIGFields(t *testing.T) {
	e := NewEvaluator()

	policy := &v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name:     "detect-sensitive-open",
				Event:    "open",
				Severity: "high",
				Message:  "Sensitive file open detected",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["fname"].contains("/etc/hosts") || event["file.path"].contains("/etc/hosts")`,
				}},
				Actions: []v1alpha1.RuntimeActionRef{{Type: "generate_report"}},
			}},
		},
	}

	// These are the exact field names from Inspektor Gadget trace_open.
	events := []runtimeevents.Event{{
		Type:      "open",
		Source:    "inspektorgadget",
		PodName:   "demo",
		Namespace: "runtime-demo",
		Timestamp: time.Now().UTC(),
		Fields: map[string]string{
			"proc.comm":     "cat",
			"proc.pid":      "12345",
			"proc.tid":      "12345",
			"fname":         "/etc/hosts",
			"fd":            "3",
			"flags_raw":     "0",
			"mode_raw":      "0",
			"error_raw":     "0",
			"proc.mntns_id": "4026533550",
		},
	}}

	result := e.EvaluateRuntime(policy, events)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].RuleName != "detect-sensitive-open" {
		t.Fatalf("unexpected rule name: %s", result.Findings[0].RuleName)
	}
	if result.Findings[0].Severity != "high" {
		t.Fatalf("expected severity high, got %s", result.Findings[0].Severity)
	}
	if result.Findings[0].Fields["fname"] != "/etc/hosts" {
		t.Fatalf("expected fname in finding fields, got %v", result.Findings[0].Fields)
	}
}

// TestEvaluateRuntimeExecPolicyWithIGFields simulates exact Inspektor Gadget
// trace_exec field names and verifies the evaluation pipeline.
func TestEvaluateRuntimeExecPolicyWithIGFields(t *testing.T) {
	e := NewEvaluator()

	policy := &v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name:     "detect-exec",
				Event:    "exec",
				Severity: "high",
				Message:  "Exec detected via live Inspektor Gadget trace",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					// Use size() > 0 instead of event != null since CEL map types
					// are not nullable. This is a regression test for the exec policy
					// that previously used "event != null" which doesn't compile.
					Expression: `size(event) > 0`,
				}},
				Actions: []v1alpha1.RuntimeActionRef{{Type: "generate_report"}},
			}},
		},
	}

	events := []runtimeevents.Event{{
		Type:      "exec",
		Source:    "inspektorgadget",
		PodName:   "demo",
		Namespace: "runtime-demo",
		Timestamp: time.Now().UTC(),
		Fields: map[string]string{
			"proc.comm":        "cat",
			"proc.pid":         "12345",
			"args":             "/bin/cat /etc/hosts",
			"proc.parent.comm": "sh",
		},
	}}

	result := e.EvaluateRuntime(policy, events)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].RuleName != "detect-exec" {
		t.Fatalf("unexpected rule name: %s", result.Findings[0].RuleName)
	}
}

// TestEvaluateRuntimeSkipsNonMatchingEventType verifies that the evaluator
// correctly filters events by their type, so exec events are not evaluated
// against open policies and vice versa.
func TestEvaluateRuntimeSkipsNonMatchingEventType(t *testing.T) {
	e := NewEvaluator()

	openPolicy := &v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name:  "detect-open",
				Event: "open",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["fname"].contains("/etc/hosts")`,
				}},
			}},
		},
	}

	execEvent := runtimeevents.Event{
		Type:   "exec",
		Fields: map[string]string{"proc.comm": "cat"},
	}

	result := e.EvaluateRuntime(openPolicy, []runtimeevents.Event{execEvent})
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for mismatched event type, got %d", len(result.Findings))
	}
}

// TestEvaluateRuntimeMultipleEventsOneMatch verifies that out of many events
// only the ones matching the condition generate findings.
func TestEvaluateRuntimeMultipleEventsOneMatch(t *testing.T) {
	e := NewEvaluator()

	policy := &v1alpha1.RuntimePolicy{
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{
				Name:    "detect-hosts-open",
				Event:   "open",
				Message: "Sensitive file open",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["fname"].contains("/etc/hosts")`,
				}},
			}},
		},
	}

	events := []runtimeevents.Event{
		{Type: "open", Fields: map[string]string{"fname": "/var/log/syslog"}},
		{Type: "open", Fields: map[string]string{"fname": "/etc/hosts"}},
		{Type: "open", Fields: map[string]string{"fname": "/tmp/test.txt"}},
		{Type: "open", Fields: map[string]string{"fname": "/etc/hosts"}},
	}

	result := e.EvaluateRuntime(policy, events)
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
}

// TestBuildCELActivationBuiltinFields verifies that the activation always
// includes standard fields like type, source, podName, namespace, and
// timestamp, preventing "no such key" errors for these common fields.
func TestBuildCELActivationBuiltinFields(t *testing.T) {
	ev := runtimeevents.Event{
		Type:      "open",
		Source:    "inspektorgadget",
		PodName:   "demo",
		Namespace: "runtime-demo",
		Timestamp: time.Now().UTC(),
		Fields:    map[string]string{"fname": "/etc/hosts"},
	}

	activation := buildCELActivation(ev)
	eventMap, ok := activation["event"].(map[string]string)
	if !ok {
		t.Fatal("expected event map in activation")
	}

	requiredKeys := []string{"type", "source", "podName", "namespace", "timestamp"}
	for _, key := range requiredKeys {
		if _, exists := eventMap[key]; !exists {
			t.Fatalf("expected key %q in event map", key)
		}
	}

	if eventMap["type"] != "open" {
		t.Fatalf("expected type=open, got %q", eventMap["type"])
	}
	if eventMap["source"] != "inspektorgadget" {
		t.Fatalf("expected source=inspektorgadget, got %q", eventMap["source"])
	}
}

// TestBuildCELActivationMetadata verifies that metadata map includes pod info.
func TestBuildCELActivationMetadata(t *testing.T) {
	activation := buildCELActivation(runtimeevents.Event{
		Type:      "exec",
		PodName:   "demo",
		Namespace: "runtime-demo",
	})
	meta, ok := activation["metadata"].(map[string]string)
	if !ok {
		t.Fatal("expected metadata map")
	}
	if meta["podName"] != "demo" {
		t.Fatalf("expected podName=demo, got %q", meta["podName"])
	}
	if meta["namespace"] != "runtime-demo" {
		t.Fatalf("expected namespace=runtime-demo, got %q", meta["namespace"])
	}
}
