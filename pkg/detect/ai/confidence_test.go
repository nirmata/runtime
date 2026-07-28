package ai

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestScoreTableMatchesDesign pins the per-signal scores to DESIGN §3.2. These
// numbers are policy surface: a user writing minConfidence: 60 is relying on
// them, so changing one is a breaking change and must break this test.
func TestScoreTableMatchesDesign(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"dns provider match", ScoreDNSProvider, 70},
		{"sni provider match", ScoreSNIProvider, 70},
		{"http host provider match", ScoreHostProvider, 70},
		{"http path match", ScoreHTTPPath, 90},
		{"provider header", ScoreProviderHeader, 95},
		{"body shape", ScoreBodyShape, 95},
		{"port only self hosted", ScorePortSelfHosted, 40},
		{"exec argv mcp package", ScoreExecMCPPackage, 95},
		{"a2a well known path", ScoreA2AWellKnown, 95},
		{"jsonrpc method", ScoreJSONRPCMethod, 90},
		{"mcp session header", ScoreMCPHeader, 95},
		{"mcp streamable signature", ScoreMCPStreamable, 80},
		{"mcp conventional path", ScoreMCPPath, 40},
		{"mcp config open", ScoreMCPConfigOpen, 60},
		{"corroboration bonus", corroborationBonus, 20},
		{"combined cap", MaxCombinedConfidence, 99},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("score = %d, want %d", tc.got, tc.want)
			}
		})
	}
}

func TestCombine(t *testing.T) {
	tests := []struct {
		name   string
		scores []int
		want   int
	}{
		{"no signals", nil, 0},
		{"only zeros", []int{0, 0}, 0},
		{"negatives ignored", []int{-5, 70}, 70},
		{"single metadata signal", []int{ScoreDNSProvider}, 70},
		// DESIGN §3.2: "dns/sni provider match=70 each (cap 90 combined)".
		{"dns plus sni caps at 90", []int{ScoreDNSProvider, ScoreSNIProvider}, 90},
		{"single conclusive signal", []int{ScoreProviderHeader}, 95},
		{"port only", []int{ScorePortSelfHosted}, 40},
		{"port plus body shape", []int{ScorePortSelfHosted, ScoreBodyShape}, 99},
		{"path plus body shape", []int{ScoreHTTPPath, ScoreBodyShape}, 99},
		{"three signals clamp", []int{70, 90, 95}, 99},
		{"never reaches 100", []int{95, 95, 95, 95, 95}, 99},
		{"order does not matter", []int{95, 70}, 99},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Combine(tc.scores...); got != tc.want {
				t.Errorf("Combine(%v) = %d, want %d", tc.scores, got, tc.want)
			}
		})
	}
}

func TestCombineIsOrderIndependent(t *testing.T) {
	if a, b := Combine(40, 95, 70), Combine(70, 40, 95); a != b {
		t.Errorf("Combine is order dependent: %d != %d", a, b)
	}
}

func TestToken(t *testing.T) {
	tests := []struct {
		name          string
		prefix, value string
		want          string
	}{
		{"header name", EvidenceHeader, "anthropic-version", "header:anthropic-version"},
		{"sni", EvidenceSNI, "api.openai.com", "sni:api.openai.com"},
		{"path", EvidencePath, "/v1/messages", "http-path:/v1/messages"},
		{"port", EvidencePort, "11434", "port:11434"},
		{"argv package", EvidenceArgv, "@modelcontextprotocol/server-git", "argv:@modelcontextprotocol/server-git"},
		{"empty prefix", "", "x", ""},
		{"empty value", EvidenceSNI, "", ""},
		// Whitespace and control bytes are stripped, not escaped: an evidence
		// token is a single word by construction, which is what makes the
		// reporter's "cut at first whitespace" rule a no-op rather than a
		// truncation.
		{"spaces stripped", EvidenceHeader, "x api key", "header:xapikey"},
		{"tabs and newlines stripped", EvidenceHeader, "a\tb\nc", "header:abc"},
		{"nul stripped", EvidenceFile, "/tmp/x\x00y", "file:/tmp/xy"},
		{"non ascii stripped", EvidenceSNI, "café.example.com", "sni:caf.example.com"},
		{"whitespace only value", EvidenceSNI, "   ", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Token(tc.prefix, tc.value); got != tc.want {
				t.Errorf("Token(%q, %q) = %q, want %q", tc.prefix, tc.value, got, tc.want)
			}
		})
	}
}

func TestTokenBoundsTheValue(t *testing.T) {
	got := Token(EvidenceFile, "/"+strings.Repeat("a", 500))
	if want := len(EvidenceFile) + 1 + maxEvidenceValueLen; len(got) != want {
		t.Errorf("len(Token(...)) = %d, want %d", len(got), want)
	}
}

// TestEvidenceTokensSatisfyTheReporterContract guards the seam documented in
// HANDOFFS (A8 -> B3): reporter.sanitizeEvidence drops any token that does not
// match ^[a-z0-9.-]+:[\x20-\x7e]*$ and cuts values at the first whitespace, so
// a token this package emits must already be in that shape or the evidence
// disappears from the Report silently.
func TestEvidenceTokensSatisfyTheReporterContract(t *testing.T) {
	prefixes := []string{
		EvidenceDNS, EvidenceSNI, EvidenceALPN, EvidenceHost, EvidencePath,
		EvidenceMethod, EvidenceHeader, EvidencePort, EvidenceArgv,
		EvidenceFile, EvidenceBodyShape, EvidenceProvider, EvidenceJSONRPC,
		EvidenceComm,
	}
	for _, p := range prefixes {
		t.Run(p, func(t *testing.T) {
			if p == "" {
				t.Fatal("empty evidence prefix")
			}
			for i := 0; i < len(p); i++ {
				c := p[i]
				ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'
				if !ok {
					t.Fatalf("prefix %q contains %q, which the reporter's token regexp rejects", p, string(c))
				}
			}
			tok := Token(p, "value.example-1/x")
			if strings.ContainsAny(tok, " \t\n\r") {
				t.Errorf("token %q contains whitespace", tok)
			}
			if strings.Count(tok, ":") != 1 {
				t.Errorf("token %q must contain exactly one colon", tok)
			}
		})
	}
}

func TestSignalsTokensAreSortedAndDeduplicated(t *testing.T) {
	var sig signals
	sig.add(ScoreDNSProvider, Token(EvidenceProvider, "openai"), Token(EvidenceDNS, "api.openai.com"))
	sig.add(ScoreSNIProvider, Token(EvidenceProvider, "openai"), Token(EvidenceSNI, "api.openai.com"))
	sig.add(0, "", Token(EvidenceALPN, "h2"))

	want := []string{
		"alpn:h2",
		"dns:api.openai.com",
		"provider:openai",
		"sni:api.openai.com",
	}
	if diff := cmp.Diff(want, sig.tokens()); diff != "" {
		t.Errorf("tokens mismatch (-want +got):\n%s", diff)
	}
	if got := sig.confidence(); got != 90 {
		t.Errorf("confidence = %d, want 90 (two 70-point signals)", got)
	}
	if sig.empty() {
		t.Error("signals reported empty after two scoring signals")
	}
}

func TestSignalsEmptyWhenOnlyUnscoredEvidence(t *testing.T) {
	var sig signals
	sig.add(0, Token(EvidenceHost, "example.com"))
	if !sig.empty() {
		t.Error("evidence without a score must not count as a signal")
	}
	if got := sig.confidence(); got != 0 {
		t.Errorf("confidence = %d, want 0", got)
	}
	if got := sig.tokens(); len(got) != 1 {
		t.Errorf("tokens = %v, want the single unscored token", got)
	}
}

func TestSignalsTokensNilWhenNoEvidence(t *testing.T) {
	var sig signals
	if got := sig.tokens(); got != nil {
		t.Errorf("tokens() = %v, want nil", got)
	}
}
