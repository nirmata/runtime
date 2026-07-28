package ai

import (
	"sort"
	"strconv"
	"strings"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// Provider identities the classifier assigns when the catalog cannot name one.
const (
	// ProviderSelfHosted marks an OpenAI-compatible endpoint recognized by
	// body shape or port with no known hostname — the truest shadow-AI case.
	ProviderSelfHosted = "self-hosted"
	// ProviderUnknown marks AI traffic whose provider could not be resolved.
	ProviderUnknown = "unknown"
)

// Transport values assigned from the observation itself.
const (
	TransportHTTPS = "https"
	TransportHTTP  = "http"
	TransportSSE   = "sse"
	TransportStdio = "stdio"
)

// classifyLLM looks for inference-API traffic in ev. It returns nil when no
// LLM signal fires.
func classifyLLM(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	switch ev.Kind {
	case runtimeevent.KindDNS:
		return llmFromDNS(cat, ev)
	case runtimeevent.KindTLS:
		return llmFromTLS(cat, ev)
	case runtimeevent.KindHTTP:
		return llmFromHTTP(cat, ev)
	case runtimeevent.KindNet:
		return llmFromNet(cat, ev)
	default:
		return nil
	}
}

// llmFromDNS matches a DNS question name against the provider catalog. This is
// the cheapest signal that survives TLS.
func llmFromDNS(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	if ev.DNS == nil {
		return nil
	}
	p, ok := cat.MatchHost(ev.DNS.QName)
	if !ok {
		return nil
	}
	var sig signals
	sig.add(ScoreDNSProvider,
		Token(EvidenceDNS, NormalizeHost(ev.DNS.QName)),
		Token(EvidenceProvider, p.Name),
	)
	return &runtimeevent.AIFacts{
		Class:      runtimeevent.AIClassLLM,
		Provider:   p.Name,
		Sanctioned: p.Sanctioned,
		Confidence: sig.confidence(),
		Evidence:   sig.tokens(),
	}
}

// llmFromTLS matches the ClientHello SNI, which is authoritative for the
// connection actually made (a DNS answer can be cached or shared).
func llmFromTLS(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	if ev.TLS == nil || ev.TLS.SNI == "" {
		return nil
	}
	p, ok := cat.MatchHost(ev.TLS.SNI)
	if !ok {
		return nil
	}
	var sig signals
	sig.add(ScoreSNIProvider,
		Token(EvidenceSNI, NormalizeHost(ev.TLS.SNI)),
		Token(EvidenceProvider, p.Name),
	)
	// ALPN corroborates the SDK shape but never raises confidence on its own.
	for _, a := range ev.TLS.ALPN {
		sig.add(0, Token(EvidenceALPN, a))
	}
	return &runtimeevent.AIFacts{
		Class:      runtimeevent.AIClassLLM,
		Provider:   p.Name,
		Sanctioned: p.Sanctioned,
		Transport:  TransportHTTPS,
		Confidence: sig.confidence(),
		Evidence:   sig.tokens(),
	}
}

// llmFromNet has only an address and a port to work with: it recognizes the
// conventional self-hosted inference ports and nothing else.
func llmFromNet(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	if ev.Net == nil {
		return nil
	}
	p, ok := cat.MatchPort(ev.Net.DestPort)
	if !ok {
		return nil
	}
	var sig signals
	sig.add(ScorePortSelfHosted,
		Token(EvidencePort, strconv.Itoa(int(ev.Net.DestPort))),
		Token(EvidenceProvider, p.Name),
	)
	return &runtimeevent.AIFacts{
		Class:      runtimeevent.AIClassLLM,
		Provider:   p.Name,
		Sanctioned: p.Sanctioned,
		Confidence: sig.confidence(),
		Evidence:   sig.tokens(),
	}
}

// llmFromHTTP is the high-fidelity path: host, endpoint path, provider header
// names, request body shape and self-hosted port, corroborating each other.
func llmFromHTTP(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	if ev.HTTP == nil {
		return nil
	}
	var (
		sig        signals
		host       = ev.HTTP.Host()
		path       = ev.HTTP.Path()
		provider   string
		sanctioned bool
	)

	setProvider := func(name string, s bool) {
		if provider == "" {
			provider, sanctioned = name, s
		}
	}

	if p, ok := cat.MatchHost(host); ok {
		setProvider(p.Name, p.Sanctioned)
		sig.add(ScoreHostProvider, Token(EvidenceProvider, p.Name))
	}

	endpointKind, hasEndpoint := cat.LLMEndpoint(path)
	if hasEndpoint {
		sig.add(ScoreHTTPPath, Token(EvidencePath, NormalizePath(path)))
	}

	// Header NAMES only: MatchHeader never sees a value, and the evidence
	// token carries the name alone.
	for _, name := range sortedHeaderNames(ev.HTTP) {
		pn, ok := cat.MatchHeader(name)
		if !ok {
			continue
		}
		if p, found := cat.Provider(pn); found {
			setProvider(p.Name, p.Sanctioned)
		}
		sig.add(ScoreProviderHeader,
			Token(EvidenceHeader, name),
			Token(EvidenceProvider, pn),
		)
	}

	// Body shape catches self-hosted OpenAI-compatible servers that have no
	// recognizable hostname at all.
	shape, hasShape := BodyShape(ev.HTTP.BodyPreview())
	if hasShape {
		sig.add(ScoreBodyShape, Token(EvidenceBodyShape, shape))
	}

	port := HostPort(host)
	if port == 0 && ev.Net != nil {
		port = ev.Net.DestPort
	}
	if p, ok := cat.MatchPort(port); ok {
		setProvider(p.Name, p.Sanctioned)
		sig.add(ScorePortSelfHosted,
			Token(EvidencePort, strconv.Itoa(int(port))),
			Token(EvidenceProvider, p.Name),
		)
	}

	if sig.empty() {
		return nil
	}

	// The destination is worth recording whether or not the catalog knows it:
	// an unrecognized host IS the interesting part of a shadow-AI finding.
	if h := NormalizeHost(host); h != "" {
		sig.add(0, Token(EvidenceHost, h))
	}

	// Path shape can still name the provider when the hostname could not
	// (IP literal, private DNS); it is already scored above.
	if provider == "" {
		if p, ok := cat.MatchPathProvider(path); ok {
			setProvider(p.Name, p.Sanctioned)
			sig.add(0, Token(EvidenceProvider, p.Name))
		}
	}
	switch {
	case provider != "":
	case hasShape:
		provider = ProviderSelfHosted
	default:
		provider = ProviderUnknown
	}

	facts := &runtimeevent.AIFacts{
		Class:        runtimeevent.AIClassLLM,
		Provider:     provider,
		Sanctioned:   sanctioned,
		EndpointKind: endpointKind,
		Transport:    httpTransport(ev.HTTP),
		Confidence:   sig.confidence(),
	}
	if m, ok := SniffModel(ev.HTTP.BodyPreview(), SniffLimit); ok {
		facts.Model = m
	}
	facts.Evidence = sig.tokens()
	return facts
}

// bodyShapeCompanions are the members that, together with "model", identify an
// inference request body.
var bodyShapeCompanions = []struct{ key, shape string }{
	{`"messages"`, "model+messages"},
	{`"contents"`, "model+contents"},
	{`"prompt"`, "model+prompt"},
	{`"input"`, "model+input"},
}

// BodyShape names the inference request shape of a plaintext body preview, or
// returns false.
//
// The returned shape is one of a closed set of literals — it is never derived
// from body bytes — so it is safe to publish as evidence.
func BodyShape(body string) (string, bool) {
	if !looksLikeJSONObject(body) {
		return "", false
	}
	if strings.Contains(body, `"model"`) {
		for _, c := range bodyShapeCompanions {
			if strings.Contains(body, c.key) {
				return c.shape, true
			}
		}
		return "", false
	}
	// Bedrock and the Anthropic native API on Bedrock carry the model in the
	// path, not the body.
	if strings.Contains(body, `"anthropic_version"`) {
		return "anthropic_version", true
	}
	if strings.Contains(body, `"messages"`) && strings.Contains(body, `"max_tokens"`) {
		return "messages+max_tokens", true
	}
	return "", false
}

// httpTransport reports the transport of a plaintext HTTP observation.
func httpTransport(h *runtimeevent.HTTPFacts) string {
	if acceptsEventStream(h) {
		return TransportSSE
	}
	return TransportHTTP
}

// acceptsEventStream reports whether the request asked for an SSE response.
func acceptsEventStream(h *runtimeevent.HTTPFacts) bool {
	return strings.Contains(strings.ToLower(h.Header("accept")), "text/event-stream")
}

// hasJSONContentType reports whether the request body is declared JSON.
func hasJSONContentType(h *runtimeevent.HTTPFacts) bool {
	return strings.Contains(strings.ToLower(h.Header("content-type")), "application/json")
}

// sortedHeaderNames returns the request's header names in sorted order.
// Iterating a map directly would make evidence order — and therefore golden
// output — depend on Go's randomized map iteration.
func sortedHeaderNames(h *runtimeevent.HTTPFacts) []string {
	hdrs := h.Headers()
	if len(hdrs) == 0 {
		return nil
	}
	names := make([]string, 0, len(hdrs))
	for name := range hdrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
