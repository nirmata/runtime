package protofilter

import (
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"github.com/google/go-cmp/cmp"
)

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name         string
		values       []string
		wantTargets  []Target
		wantStar     bool
		wantRejected []RejectedTarget
	}{
		{
			name: "nil input",
		},
		{
			name:        "single bare token",
			values:      []string{"ssh"},
			wantTargets: []Target{{Protocol: "ssh"}},
		},
		{
			name:   "every bare token is programmable",
			values: []string{"ssh", "tls", "dns", "http/1.1", "http/2", "quic"},
			wantTargets: []Target{
				{Protocol: "ssh"}, {Protocol: "tls"}, {Protocol: "dns"},
				{Protocol: "http/1.1"}, {Protocol: "http/2"}, {Protocol: "quic"},
			},
		},
		{
			name:        "tls with ALPN suffix",
			values:      []string{"tls/h2"},
			wantTargets: []Target{{Protocol: "tls", ALPN: "h2"}},
		},
		{
			name:        "bare tls and tls with ALPN are distinct targets",
			values:      []string{"tls", "tls/h2"},
			wantTargets: []Target{{Protocol: "tls"}, {Protocol: "tls", ALPN: "h2"}},
		},
		{
			name:        "duplicates are collapsed preserving first-seen order",
			values:      []string{"ssh", "tls/h2", "ssh", "tls/h2"},
			wantTargets: []Target{{Protocol: "ssh"}, {Protocol: "tls", ALPN: "h2"}},
		},
		{
			name:        "surrounding whitespace and quotes are trimmed",
			values:      []string{"  ssh\t", "\"tls/h2\"", "'quic'"},
			wantTargets: []Target{{Protocol: "ssh"}, {Protocol: "tls", ALPN: "h2"}, {Protocol: "quic"}},
		},
		{
			name:        "newline from a CEL rendered list is trimmed",
			values:      []string{"ssh\r\n"},
			wantTargets: []Target{{Protocol: "ssh"}},
		},
		{
			name:     "star is the default deny sentinel and yields no target",
			values:   []string{"*"},
			wantStar: true,
		},
		{
			name:        "star mixes with tokens",
			values:      []string{"*", "dns"},
			wantTargets: []Target{{Protocol: "dns"}},
			wantStar:    true,
		},
		{
			name:         "empty value is rejected, not ignored",
			values:       []string{""},
			wantRejected: []RejectedTarget{{Value: "", Reason: ReasonEmpty}},
		},
		{
			name:         "whitespace-only value is rejected as empty",
			values:       []string{"  \t"},
			wantRejected: []RejectedTarget{{Value: "  \t", Reason: ReasonEmpty}},
		},
		{
			name:         "ALPN longer than the kernel buffer is rejected",
			values:       []string{"tls/" + strings.Repeat("a", compiler.MaxALPNLength+1)},
			wantRejected: []RejectedTarget{{Value: "tls/" + strings.Repeat("a", compiler.MaxALPNLength+1), Reason: ReasonInvalidALPN}},
		},
		{
			name:         "ALPN with a non-visible byte is rejected",
			values:       []string{"tls/h 2"},
			wantRejected: []RejectedTarget{{Value: "tls/h 2", Reason: ReasonInvalidALPN}},
		},
		{
			name:         "empty ALPN suffix is rejected",
			values:       []string{"tls/"},
			wantRejected: []RejectedTarget{{Value: "tls/", Reason: ReasonInvalidALPN}},
		},
		{
			name:         "unrecognized token is rejected",
			values:       []string{"gopher"},
			wantRejected: []RejectedTarget{{Value: "gopher", Reason: ReasonNotAProtocol}},
		},
		{
			name:         "unknown is not a protocol token",
			values:       []string{"unknown"},
			wantRejected: []RejectedTarget{{Value: "unknown", Reason: ReasonNotAProtocol}},
		},
		{
			name:         "h2c is not a protocol token",
			values:       []string{"h2c"},
			wantRejected: []RejectedTarget{{Value: "h2c", Reason: ReasonNotAProtocol}},
		},
		{
			name:         "ALPN suffix on a non-tls token is rejected",
			values:       []string{"quic/h2"},
			wantRejected: []RejectedTarget{{Value: "quic/h2", Reason: ReasonNotAProtocol}},
		},
		{
			name:         "wrong case is rejected",
			values:       []string{"TLS"},
			wantRejected: []RejectedTarget{{Value: "TLS", Reason: ReasonNotAProtocol}},
		},
		{
			name:        "mixed valid and invalid keeps the valid ones and reports the rest",
			values:      []string{"ssh", "gopher", "tls/", "*", "tls/h2"},
			wantTargets: []Target{{Protocol: "ssh"}, {Protocol: "tls", ALPN: "h2"}},
			wantStar:    true,
			wantRejected: []RejectedTarget{
				{Value: "gopher", Reason: ReasonNotAProtocol},
				{Value: "tls/", Reason: ReasonInvalidALPN},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotTargets, gotStar, gotRejected := ParseTargets(tc.values)

			if diff := cmp.Diff(tc.wantTargets, gotTargets); diff != "" {
				t.Errorf("targets mismatch (-want +got):\n%s", diff)
			}
			if gotStar != tc.wantStar {
				t.Errorf("star = %v, want %v", gotStar, tc.wantStar)
			}
			if diff := cmp.Diff(tc.wantRejected, gotRejected); diff != "" {
				t.Errorf("rejected mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// protoID can encode ProtocolUnclassified for observation keys, so a grammar
// leak here would silently program a policy rule matching unclassifiable
// traffic. The string must be rejected, never turned into a target.
func TestParseTargets_UnclassifiedIsNotProgrammable(t *testing.T) {
	targets, star, rejected := ParseTargets([]string{compiler.ProtocolUnclassified})

	for _, target := range targets {
		if target.Protocol == compiler.ProtocolUnclassified {
			t.Errorf("ParseTargets emitted target %+v", target)
		}
	}
	if len(targets) != 0 || star {
		t.Errorf("ParseTargets = (%v, %v), want no targets and no star", targets, star)
	}
	want := []RejectedTarget{{Value: compiler.ProtocolUnclassified, Reason: ReasonNotAProtocol}}
	if diff := cmp.Diff(want, rejected); diff != "" {
		t.Errorf("rejected mismatch (-want +got):\n%s", diff)
	}
}

func TestRejectedTarget_StringNamesValueAndReason(t *testing.T) {
	got := RejectedTarget{Value: "gopher", Reason: ReasonNotAProtocol}.String()
	want := `"gopher": ` + ReasonNotAProtocol
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestTargetKernelKey_RoundTripsTokenAndALPN(t *testing.T) {
	targets := []Target{
		{Protocol: compiler.ProtocolUnclassified},
		{Protocol: compiler.ProtocolSSH},
		{Protocol: compiler.ProtocolTLS},
		{Protocol: compiler.ProtocolTLS, ALPN: "h2"},
		{Protocol: compiler.ProtocolTLS, ALPN: strings.Repeat("a", compiler.MaxALPNLength)},
		{Protocol: compiler.ProtocolDNS},
		{Protocol: compiler.ProtocolHTTP11},
		{Protocol: compiler.ProtocolHTTP2},
		{Protocol: compiler.ProtocolQUIC},
	}
	for _, target := range targets {
		key, ok := targetKernelKey(target)
		if !ok {
			t.Fatalf("targetKernelKey(%+v) not ok", target)
		}
		token, ok := protoToken(key.Proto)
		if !ok {
			t.Fatalf("protoToken(%d) not ok", key.Proto)
		}
		alpn, err := decodeALPN(key.Alpn)
		if err != nil {
			t.Fatalf("decodeALPN(%v): %v", key.Alpn, err)
		}
		if got := (Target{Protocol: token, ALPN: alpn}); got != target {
			t.Errorf("round trip = %+v, want %+v", got, target)
		}
	}
}

func TestTargetKernelKey_RejectsUnencodableTargets(t *testing.T) {
	for _, target := range []Target{
		{Protocol: "gopher"},
		{Protocol: compiler.ProtocolTLS, ALPN: strings.Repeat("a", compiler.MaxALPNLength+1)},
	} {
		if _, ok := targetKernelKey(target); ok {
			t.Errorf("targetKernelKey(%+v) ok, want not ok", target)
		}
	}
}

func TestProtoToken_UnrecognizedIDIsNotFoldedIntoUnclassified(t *testing.T) {
	if token, ok := protoToken(99); ok {
		t.Errorf("protoToken(99) = %q, want not ok", token)
	}
}

func TestDecodeALPN(t *testing.T) {
	var full [compiler.MaxALPNLength]byte
	for i := range full {
		full[i] = 'a'
	}

	var h2 [compiler.MaxALPNLength]byte
	copy(h2[:], "h2")

	var corrupt [compiler.MaxALPNLength]byte
	copy(corrupt[:], "h\x01")

	if got, err := decodeALPN([compiler.MaxALPNLength]byte{}); err != nil || got != "" {
		t.Errorf("decodeALPN(zero) = (%q, %v), want (\"\", nil)", got, err)
	}
	if got, err := decodeALPN(h2); err != nil || got != "h2" {
		t.Errorf("decodeALPN(h2) = (%q, %v), want (\"h2\", nil)", got, err)
	}
	if got, err := decodeALPN(full); err != nil || got != strings.Repeat("a", compiler.MaxALPNLength) {
		t.Errorf("decodeALPN(full) = (%q, %v), want the full buffer, nil", got, err)
	}
	if _, err := decodeALPN(corrupt); err == nil {
		t.Error("decodeALPN with a non-visible byte returned nil error")
	}
}
