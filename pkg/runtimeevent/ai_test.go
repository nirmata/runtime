package runtimeevent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestAIFactsJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		facts AIFacts
	}{
		{
			name: "llm with every field set",
			facts: AIFacts{
				Class:         AIClassLLM,
				Provider:      "anthropic",
				Model:         "claude-sonnet-4-5",
				EndpointKind:  "messages",
				JSONRPCMethod: "",
				Transport:     "https",
				Confidence:    99,
				Evidence:      []string{"header:anthropic-version", "sni:api.anthropic.com"},
				Sanctioned:    true,
			},
		},
		{
			name: "mcp stdio",
			facts: AIFacts{
				Class:        AIClassMCP,
				Provider:     "unknown",
				EndpointKind: "mcp.stdio",
				Transport:    "stdio",
				Confidence:   95,
				Evidence:     []string{"argv:@modelcontextprotocol/server-git"},
			},
		},
		{
			name: "a2a jsonrpc",
			facts: AIFacts{
				Class:         AIClassA2A,
				EndpointKind:  "a2a.jsonrpc",
				JSONRPCMethod: "message/send",
				Transport:     "http",
				Confidence:    90,
			},
		},
		{
			name:  "zero value",
			facts: AIFacts{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(tc.facts)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			var got AIFacts
			if err := json.Unmarshal(blob, &got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if diff := cmp.Diff(tc.facts, got); diff != "" {
				t.Errorf("round trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestEventCarriesAIFacts guards the one-field edit to Event: the facts must
// survive a JSON round trip alongside the (redacting) HTTP facts.
func TestEventCarriesAIFacts(t *testing.T) {
	ev := Event{
		Kind: KindHTTP,
		Time: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		HTTP: NewHTTPFacts("POST", "/v1/messages", "api.anthropic.com",
			map[string]string{"authorization": "Bearer sk-secret", "anthropic-version": "2023-06-01"},
			[]byte(`{"model":"claude-sonnet-4-5","messages":[]}`)),
		AI: &AIFacts{
			Class:        AIClassLLM,
			Provider:     "anthropic",
			Model:        "claude-sonnet-4-5",
			EndpointKind: "messages",
			Transport:    "http",
			Confidence:   99,
			Evidence:     []string{"header:anthropic-version", "http-path:/v1/messages"},
		},
	}

	blob, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got Event
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if diff := cmp.Diff(ev.AI, got.AI); diff != "" {
		t.Errorf("AI facts mismatch (-want +got):\n%s", diff)
	}
	if got.HTTP.Header("authorization") != Redacted {
		t.Errorf("authorization = %q, want %q", got.HTTP.Header("authorization"), Redacted)
	}
}

func TestEventWithoutAIFactsOmitsTheField(t *testing.T) {
	blob, err := json.Marshal(Event{Kind: KindDNS, DNS: &DNSFacts{QName: "example.com"}})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got := string(blob); strings.Contains(got, `"ai"`) {
		t.Errorf("marshaled event carries an empty ai field: %s", got)
	}
}

func TestAIFactsClone(t *testing.T) {
	orig := &AIFacts{
		Class:      AIClassLLM,
		Provider:   "openai",
		Confidence: 70,
		Evidence:   []string{"dns:api.openai.com"},
	}
	clone := orig.Clone()
	if diff := cmp.Diff(orig, clone); diff != "" {
		t.Errorf("Clone() mismatch (-want +got):\n%s", diff)
	}
	clone.Evidence[0] = "mutated"
	clone.Provider = "mutated"
	if orig.Evidence[0] != "dns:api.openai.com" {
		t.Error("Clone() aliased the evidence slice")
	}
	if orig.Provider != "openai" {
		t.Error("Clone() aliased the struct")
	}
	if (*AIFacts)(nil).Clone() != nil {
		t.Error("Clone() of nil must be nil")
	}
}
