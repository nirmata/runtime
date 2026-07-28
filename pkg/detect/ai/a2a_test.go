package ai

import (
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

func TestIsA2APath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"agent json", "/.well-known/agent.json", true},
		{"agent card json", "/.well-known/agent-card.json", true},
		{"agent card no extension", "/.well-known/agent-card", true},
		{"agent subpath", "/.well-known/agent/extended", true},
		{"with query", "/.well-known/agent.json?v=1", true},
		{"mixed case", "/.WELL-KNOWN/Agent.json", true},
		{"other well known resource", "/.well-known/openid-configuration", false},
		{"agent outside well known", "/agent.json", false},
		{"root", "/", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsA2APath(tc.path); got != tc.want {
				t.Errorf("IsA2APath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestIsA2AMethod(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   bool
	}{
		{"message send", "message/send", true},
		{"message stream", "message/stream", true},
		{"tasks get", "tasks/get", true},
		{"tasks cancel", "tasks/cancel", true},
		{"tasks push notification config", "tasks/pushNotificationConfig/set", true},
		{"authenticated extended card", "agent/getAuthenticatedExtendedCard", true},
		{"mcp method is not a2a", "tools/call", false},
		{"initialize is not a2a", "initialize", false},
		{"other agent method", "agent/other", false},
		{"prefix without slash", "message", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsA2AMethod(tc.method); got != tc.want {
				t.Errorf("IsA2AMethod(%q) = %v, want %v", tc.method, got, tc.want)
			}
		})
	}
}

// TestClassifyA2A exercises the A2A classifier directly so that "not A2A" cases
// can assert nil even when another class legitimately claims the event.
func TestClassifyA2A(t *testing.T) {
	cat := DefaultCatalog()

	tests := []struct {
		name string
		ev   *runtimeevent.Event
		want *runtimeevent.AIFacts
	}{
		{
			name: "agent card discovery",
			ev:   httpEvent("GET", "/.well-known/agent.json", "agents.partner.example", nil, ""),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassA2A,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointA2AAgentCard,
				Transport:    TransportHTTP,
				Confidence:   ScoreA2AWellKnown,
				Evidence: []string{
					"host:agents.partner.example",
					"http-path:/.well-known/agent.json",
				},
			},
		},
		{
			name: "agent card variant with a query string",
			ev:   httpEvent("GET", "/.well-known/agent-card.json?v=2", "34.117.59.81", nil, ""),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassA2A,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointA2AAgentCard,
				Transport:    TransportHTTP,
				Confidence:   ScoreA2AWellKnown,
				Evidence: []string{
					"host:34.117.59.81",
					"http-path:/.well-known/agent-card.json",
				},
			},
		},
		{
			name: "message send rpc",
			ev: httpEvent("POST", "/a2a", "peer.internal", map[string]string{
				"content-type": "application/json",
			}, `{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{}}}`),
			want: &runtimeevent.AIFacts{
				Class:         runtimeevent.AIClassA2A,
				Provider:      ProviderUnknown,
				EndpointKind:  EndpointA2AJSONRPC,
				JSONRPCMethod: "message/send",
				Transport:     TransportHTTP,
				Confidence:    ScoreJSONRPCMethod,
				Evidence: []string{
					"host:peer.internal",
					"jsonrpc-method:message/send",
				},
			},
		},
		{
			name: "tasks get rpc",
			ev: httpEvent("POST", "/", "peer.internal", map[string]string{
				"content-type": "application/json",
			}, `{"jsonrpc":"2.0","id":"1","method":"tasks/get","params":{"id":"t1"}}`),
			want: &runtimeevent.AIFacts{
				Class:         runtimeevent.AIClassA2A,
				Provider:      ProviderUnknown,
				EndpointKind:  EndpointA2AJSONRPC,
				JSONRPCMethod: "tasks/get",
				Transport:     TransportHTTP,
				Confidence:    ScoreJSONRPCMethod,
				Evidence: []string{
					"host:peer.internal",
					"jsonrpc-method:tasks/get",
				},
			},
		},
		{
			name: "streamed message with the sse transport",
			ev: httpEvent("POST", "/a2a", "peer.internal", map[string]string{
				"content-type": "application/json",
				"accept":       "text/event-stream",
			}, `{"jsonrpc":"2.0","id":"1","method":"message/stream","params":{}}`),
			want: &runtimeevent.AIFacts{
				Class:         runtimeevent.AIClassA2A,
				Provider:      ProviderUnknown,
				EndpointKind:  EndpointA2AJSONRPC,
				JSONRPCMethod: "message/stream",
				Transport:     TransportSSE,
				Confidence:    ScoreJSONRPCMethod,
				Evidence: []string{
					"host:peer.internal",
					"jsonrpc-method:message/stream",
				},
			},
		},
		{
			// Both signals: the well-known path names the request target, so
			// the endpoint kind stays the agent card while the method is still
			// recorded.
			name: "card fetch carrying an rpc body",
			ev: httpEvent("POST", "/.well-known/agent/extended", "peer.internal", map[string]string{
				"content-type": "application/json",
			}, `{"jsonrpc":"2.0","id":"1","method":"agent/getAuthenticatedExtendedCard"}`),
			want: &runtimeevent.AIFacts{
				Class:         runtimeevent.AIClassA2A,
				Provider:      ProviderUnknown,
				EndpointKind:  EndpointA2AAgentCard,
				JSONRPCMethod: "agent/getAuthenticatedExtendedCard",
				Transport:     TransportHTTP,
				Confidence:    99,
				Evidence: []string{
					"host:peer.internal",
					"http-path:/.well-known/agent/extended",
					"jsonrpc-method:agent/getAuthenticatedExtendedCard",
				},
			},
		},
		{
			name: "mcp rpc is not a2a",
			ev: httpEvent("POST", "/mcp", "tools.internal", map[string]string{
				"content-type": "application/json",
			}, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`),
			want: nil,
		},
		{
			name: "other well known resource is not a2a",
			ev:   httpEvent("GET", "/.well-known/openid-configuration", "idp.example.com", nil, ""),
			want: nil,
		},
		{
			// A2A over HTTPS to an arbitrary host is indistinguishable from any
			// other HTTPS: metadata alone can never yield an A2A verdict.
			name: "tls metadata can never be a2a",
			ev:   tlsEvent("agents.partner.example", "h2"),
			want: nil,
		},
		{
			name: "dns metadata can never be a2a",
			ev:   dnsEvent("agents.partner.example"),
			want: nil,
		},
		{
			name: "http facts missing",
			ev:   &runtimeevent.Event{Kind: runtimeevent.KindHTTP},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, classifyA2A(cat, tc.ev)); diff != "" {
				t.Errorf("classifyA2A() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
