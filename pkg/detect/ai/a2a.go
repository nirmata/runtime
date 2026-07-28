package ai

import (
	"strings"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// A2A endpoint kinds.
const (
	EndpointA2AAgentCard = "a2a.agent-card"
	EndpointA2AJSONRPC   = "a2a.jsonrpc"
)

// IsA2APath reports whether path requests an A2A agent card (the whole
// "/.well-known/agent" prefix: agent.json, agent-card.json, agent-card, ...).
// It uses the embedded default catalog.
func IsA2APath(path string) bool { return DefaultCatalog().IsA2APath(path) }

// IsA2AMethod reports whether method is an A2A JSON-RPC method ("message/*",
// "tasks/*", "agent/getAuthenticatedExtendedCard").
func IsA2AMethod(method string) bool { return DefaultCatalog().IsA2AMethod(method) }

// IsA2APath reports whether path requests an A2A agent card.
func (c *Catalog) IsA2APath(path string) bool {
	if c == nil {
		return false
	}
	p := strings.ToLower(NormalizePath(path))
	if p == "" {
		return false
	}
	for _, pre := range c.a2a.PathPrefixes {
		if strings.HasPrefix(p, strings.ToLower(pre)) {
			return true
		}
	}
	return false
}

// IsA2AMethod reports whether method is in the A2A method namespace.
func (c *Catalog) IsA2AMethod(method string) bool {
	if c == nil || method == "" {
		return false
	}
	for _, m := range c.a2a.Methods {
		if method == m {
			return true
		}
	}
	for _, p := range c.a2a.MethodPrefixes {
		if strings.HasPrefix(method, p) {
			return true
		}
	}
	return false
}

// classifyA2A looks for Agent-to-Agent traffic. A2A over HTTPS to an arbitrary
// host is indistinguishable from any other HTTPS, so this is plaintext-only by
// construction (proposal §2.1 class 3).
func classifyA2A(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	if ev.Kind != runtimeevent.KindHTTP || ev.HTTP == nil {
		return nil
	}
	h := ev.HTTP

	var sig signals
	endpointKind := ""

	if cat.IsA2APath(h.Path()) {
		endpointKind = EndpointA2AAgentCard
		sig.add(ScoreA2AWellKnown, Token(EvidencePath, NormalizePath(h.Path())))
	}

	var method string
	if m, ok := SniffJSONRPCMethod(h.BodyPreview(), SniffLimit); ok && cat.IsA2AMethod(m) {
		method = m
		if endpointKind == "" {
			endpointKind = EndpointA2AJSONRPC
		}
		sig.add(ScoreJSONRPCMethod, Token(EvidenceJSONRPC, m))
	}

	if sig.empty() {
		return nil
	}
	if host := NormalizeHost(h.Host()); host != "" {
		sig.add(0, Token(EvidenceHost, host))
	}

	return &runtimeevent.AIFacts{
		Class:         runtimeevent.AIClassA2A,
		Provider:      ProviderUnknown,
		EndpointKind:  endpointKind,
		JSONRPCMethod: method,
		Transport:     httpTransport(h),
		Confidence:    sig.confidence(),
		Evidence:      sig.tokens(),
	}
}
