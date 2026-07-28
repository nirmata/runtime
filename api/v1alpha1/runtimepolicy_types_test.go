package v1alpha1

import (
	"testing"
)

const runtimePoliciesCRD = "runtime.kyverno.io_runtimepolicies.yaml"

// wantBehaviorXValidationRule is the 4-way exactly-one check. It is asserted
// character-for-character on purpose: dropping a term here silently allows a
// policy that sets two behaviors on one entry, which the compiler and the
// managers both assume cannot happen.
const wantBehaviorXValidationRule = `(has(self.network) ? 1 : 0) + (has(self.exec) ? 1 : 0) + (has(self.open) ? 1 : 0) + (has(self.ai) ? 1 : 0) == 1`

const wantBehaviorXValidationMessage = `exactly one of network, exec, open, or ai must be specified`

func TestRuntimePolicyCRD_BehaviorXValidationIsFourWayExactlyOne(t *testing.T) {
	c := loadCRD(t, runtimePoliciesCRD)
	validations := dig(t, behaviorItems(t, c), "x-kubernetes-validations")
	list, ok := validations.([]any)
	if !ok {
		t.Fatalf("x-kubernetes-validations: got %T, want array", validations)
	}
	if len(list) != 1 {
		t.Fatalf("x-kubernetes-validations: got %d entries, want 1", len(list))
	}
	if got := digString(t, list[0], "rule"); got != wantBehaviorXValidationRule {
		t.Errorf("XValidation rule mismatch:\n got: %s\nwant: %s", got, wantBehaviorXValidationRule)
	}
	if got := digString(t, list[0], "message"); got != wantBehaviorXValidationMessage {
		t.Errorf("XValidation message mismatch:\n got: %s\nwant: %s", got, wantBehaviorXValidationMessage)
	}
}

func TestRuntimePolicyCRD_ModeEnumHasThreeValues(t *testing.T) {
	c := loadCRD(t, runtimePoliciesCRD)
	want := []string{"monitor", "enforce", "discover"}
	got := digStrings(t, specProp(t, c, "mode"), "enum")
	if !equalStrings(want, got) {
		t.Errorf("spec.mode enum mismatch:\n got: %v\nwant: %v", got, want)
	}
	// The Go constants must be exactly the enum the API server will accept.
	consts := []string{string(PolicyModeMonitor), string(PolicyModeEnforce), string(PolicyModeDiscover)}
	if !equalStrings(want, consts) {
		t.Errorf("mode constants drifted from the CRD enum:\n got: %v\nwant: %v", consts, want)
	}
}

func TestRuntimePolicyCRD_BehaviorHasAllFourBehaviorKinds(t *testing.T) {
	c := loadCRD(t, runtimePoliciesCRD)
	props := dig(t, behaviorItems(t, c), "properties")
	m, ok := props.(map[string]any)
	if !ok {
		t.Fatalf("behavior properties: got %T, want map", props)
	}
	for _, name := range []string{"network", "exec", "open", "ai"} {
		if _, ok := m[name]; !ok {
			t.Errorf("behavior schema is missing property %q", name)
		}
	}
	if len(m) != 4 {
		t.Errorf("behavior schema has %d properties, want exactly 4 (network, exec, open, ai); the XValidation only covers those", len(m))
	}
}

func TestRuntimePolicyCRD_AIBehaviorSchema(t *testing.T) {
	c := loadCRD(t, runtimePoliciesCRD)
	ai := dig(t, behaviorItems(t, c), "properties", "ai")

	t.Run("ClassesEnum", func(t *testing.T) {
		want := []string{"llm", "mcp", "a2a"}
		got := digStrings(t, ai, "properties", "classes", "items", "enum")
		if !equalStrings(want, got) {
			t.Errorf("ai.classes item enum mismatch:\n got: %v\nwant: %v", got, want)
		}
		consts := []string{string(AIClassLLM), string(AIClassMCP), string(AIClassA2A)}
		if !equalStrings(want, consts) {
			t.Errorf("AITrafficClass constants drifted from the enum:\n got: %v\nwant: %v", consts, want)
		}
	})

	t.Run("SeverityEnum", func(t *testing.T) {
		want := []string{"info", "low", "medium", "high", "critical"}
		got := digStrings(t, ai, "properties", "severity", "enum")
		if !equalStrings(want, got) {
			t.Errorf("ai.severity enum mismatch:\n got: %v\nwant: %v", got, want)
		}
	})

	t.Run("MinConfidenceBounds", func(t *testing.T) {
		if got := dig(t, ai, "properties", "minConfidence", "minimum"); got != float64(0) {
			t.Errorf("ai.minConfidence minimum = %v (%T), want 0", got, got)
		}
		if got := dig(t, ai, "properties", "minConfidence", "maximum"); got != float64(100) {
			t.Errorf("ai.minConfidence maximum = %v (%T), want 100", got, got)
		}
		if got := digString(t, ai, "properties", "minConfidence", "format"); got != "int32" {
			t.Errorf("ai.minConfidence format = %q, want int32", got)
		}
	})

	t.Run("MatchIsAStringNotAList", func(t *testing.T) {
		// Match is a boolean CEL predicate source string, evaluated per event.
		if got := digString(t, ai, "properties", "match", "type"); got != "string" {
			t.Errorf("ai.match type = %q, want string", got)
		}
	})

	t.Run("AllowDenyReuseBehaviorRule", func(t *testing.T) {
		for _, side := range []string{"allow", "deny"} {
			rule := dig(t, ai, "properties", side)
			if got := digString(t, rule, "properties", "expression", "type"); got != "string" {
				t.Errorf("ai.%s.expression type = %q, want string", side, got)
			}
			if got := digString(t, rule, "properties", "values", "items", "type"); got != "string" {
				t.Errorf("ai.%s.values item type = %q, want string", side, got)
			}
		}
	})

	t.Run("NoRequiredFields", func(t *testing.T) {
		// An `ai: {}` behavior (discover-everything) must be valid.
		if m, ok := ai.(map[string]any); ok {
			if req, present := m["required"]; present {
				t.Errorf("ai schema declares required fields %v; `ai: {}` must be accepted", req)
			}
		}
	})
}
