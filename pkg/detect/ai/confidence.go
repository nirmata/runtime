package ai

import "sort"

// Signal scores, per DESIGN §3.2. Each value is the confidence a single signal
// justifies on its own; Combine folds several signals into one score.
//
// The ranking encodes fidelity, not convenience: signals that survive TLS
// (DNS, SNI) score lower than plaintext signals that name the API family
// outright, because a shared CDN hostname is weaker evidence than
// "POST /v1/messages with an anthropic-version header".
const (
	// ScoreDNSProvider — a DNS question for a catalog provider hostname.
	ScoreDNSProvider = 70
	// ScoreSNIProvider — a TLS ClientHello SNI for a catalog provider.
	ScoreSNIProvider = 70
	// ScoreHostProvider — an HTTP Host header naming a catalog provider.
	ScoreHostProvider = 70
	// ScoreHTTPPath — a request path matching a known inference endpoint.
	ScoreHTTPPath = 90
	// ScoreProviderHeader — a provider-distinctive request header NAME.
	ScoreProviderHeader = 95
	// ScoreBodyShape — an inference request body shape, e.g.
	// {"model":...,"messages":[...]}. Catches self-hosted OpenAI-compatible
	// servers that have no recognizable hostname at all.
	ScoreBodyShape = 95
	// ScorePortSelfHosted — a conventional self-hosted inference port and
	// nothing else. Deliberately low: 11434 is a convention, not a proof.
	ScorePortSelfHosted = 40
	// ScoreExecMCPPackage — exec of a stdio MCP server package.
	ScoreExecMCPPackage = 95
	// ScoreA2AWellKnown — a request for an A2A agent card.
	ScoreA2AWellKnown = 95
	// ScoreJSONRPCMethod — a sniffed JSON-RPC method in a protocol's
	// namespace (tools/, message/, ...).
	ScoreJSONRPCMethod = 90
	// ScoreMCPHeader — MCP-Session-Id / MCP-Protocol-Version: conclusive.
	ScoreMCPHeader = 95
	// ScoreMCPStreamable — POST + Accept: text/event-stream +
	// Content-Type: application/json, the MCP streamable-HTTP signature.
	ScoreMCPStreamable = 80
	// ScoreMCPPath — a conventional MCP path (/mcp, /sse, /messages).
	ScoreMCPPath = 40
	// ScoreMCPConfigOpen — an open of an MCP client configuration file.
	ScoreMCPConfigOpen = 60
)

// corroborationBonus is what each additional independent signal adds beyond
// the strongest one. Two 70-point metadata signals (DNS and SNI for the same
// provider) therefore reach the 90 documented in DESIGN §3.2 without either
// one alone claiming certainty.
const corroborationBonus = 20

// MaxCombinedConfidence caps a corroborated score. The classifier never claims
// 100: it observes traffic shape, it does not read intent.
const MaxCombinedConfidence = 99

// Combine folds independent signal scores into a single 0-100 confidence: the
// strongest signal, plus corroborationBonus for every additional signal,
// clamped to MaxCombinedConfidence.
func Combine(scores ...int) int {
	best, extra := 0, 0
	for _, s := range scores {
		if s <= 0 {
			continue
		}
		if s > best {
			best = s
		}
		extra++
	}
	if best == 0 {
		return 0
	}
	total := best + corroborationBonus*(extra-1)
	if total > MaxCombinedConfidence {
		return MaxCombinedConfidence
	}
	return total
}

// Evidence token prefixes. Every prefix is lowercase and dash-separated so
// tokens satisfy the reporter's ^[a-z0-9.-]+:[\x20-\x7e]*$ contract.
const (
	EvidenceDNS       = "dns"
	EvidenceSNI       = "sni"
	EvidenceALPN      = "alpn"
	EvidenceHost      = "host"
	EvidencePath      = "http-path"
	EvidenceMethod    = "http-method"
	EvidenceHeader    = "header"
	EvidencePort      = "port"
	EvidenceArgv      = "argv"
	EvidenceFile      = "file"
	EvidenceBodyShape = "body-shape"
	EvidenceProvider  = "provider"
	EvidenceJSONRPC   = "jsonrpc-method"
	EvidenceComm      = "comm"
)

// maxEvidenceValueLen bounds a token's value part.
const maxEvidenceValueLen = 128

// Token builds an evidence token "<prefix>:<value>".
//
// The value is reduced to printable, non-space ASCII and bounded. This is the
// classifier-side half of the evidence contract: callers pass header NAMES,
// hostnames, paths, ports and validated method names — never a header value,
// never body text — and Token makes sure whatever arrives cannot smuggle
// whitespace, control bytes, or an unbounded string into a Report.
func Token(prefix, value string) string {
	if prefix == "" {
		return ""
	}
	b := make([]byte, 0, len(value))
	for i := 0; i < len(value) && len(b) < maxEvidenceValueLen; i++ {
		c := value[i]
		if c <= 0x20 || c >= 0x7f {
			continue
		}
		b = append(b, c)
	}
	if len(b) == 0 {
		return ""
	}
	return prefix + ":" + string(b)
}

// signals accumulates the scores and evidence of one classification attempt.
// It is a value type built and discarded per event: nothing here is shared.
type signals struct {
	scores   []int
	evidence []string
}

// add records one signal worth score, with the evidence tokens that justify
// it. Empty tokens are dropped; a zero score records evidence only
// (corroboration that should not raise confidence by itself).
func (s *signals) add(score int, tokens ...string) {
	if score > 0 {
		s.scores = append(s.scores, score)
	}
	for _, t := range tokens {
		if t != "" {
			s.evidence = append(s.evidence, t)
		}
	}
}

// empty reports whether no scoring signal fired.
func (s *signals) empty() bool { return len(s.scores) == 0 }

// confidence folds the accumulated scores.
func (s *signals) confidence() int { return Combine(s.scores...) }

// tokens returns the sorted, deduplicated evidence. Sorting makes classifier
// output deterministic regardless of Go's map iteration order, which golden
// tests depend on.
func (s *signals) tokens() []string {
	if len(s.evidence) == 0 {
		return nil
	}
	out := make([]string, len(s.evidence))
	copy(out, s.evidence)
	sort.Strings(out)
	dedup := out[:0]
	var prev string
	for i, t := range out {
		if i > 0 && t == prev {
			continue
		}
		prev = t
		dedup = append(dedup, t)
	}
	return dedup
}
