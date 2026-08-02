package compiler

import (
	"errors"
	"strings"
	"testing"
)

func TestParseProtocolValue(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantStar  bool
		wantProto string
		wantALPN  string
		wantErr   error
	}{
		{name: "ssh", in: "ssh", wantProto: ProtocolSSH},
		{name: "tls", in: "tls", wantProto: ProtocolTLS},
		{name: "http/1.1", in: "http/1.1", wantProto: ProtocolHTTP11},
		{name: "h2c", in: "h2c", wantProto: ProtocolH2C},
		{name: "quic", in: "quic", wantProto: ProtocolQUIC},
		{name: "unknown is a real token, not an error", in: "unknown", wantProto: ProtocolUnknown},
		{name: "tls with ALPN h2", in: "tls/h2", wantProto: ProtocolTLS, wantALPN: "h2"},
		{name: "tls with ALPN http/1.1", in: "tls/http/1.1", wantProto: ProtocolTLS, wantALPN: "http/1.1"},
		{name: "ALPN case is preserved", in: "tls/H2", wantProto: ProtocolTLS, wantALPN: "H2"},
		{name: "default deny sentinel", in: "*", wantStar: true},
		{name: "quoted padded sentinel matches the network grammar", in: "\" * \"", wantStar: true},
		{name: "token with padding and quotes", in: " \"ssh\" ", wantProto: ProtocolSSH},
		{name: "trailing newline from CEL list rendering", in: "tls\n", wantProto: ProtocolTLS},
		{name: "max length ALPN", in: "tls/" + strings.Repeat("a", 16), wantProto: ProtocolTLS, wantALPN: strings.Repeat("a", 16)},

		{name: "empty string rejected", in: "", wantErr: ErrEmptyProtocolValue},
		{name: "whitespace only rejected", in: "   ", wantErr: ErrEmptyProtocolValue},
		{name: "unrecognized token rejected", in: "grpc", wantErr: ErrNotAProtocolValue},
		{name: "uppercase token rejected", in: "TLS", wantErr: ErrNotAProtocolValue},
		{name: "ALPN on a non-tls token rejected", in: "ssh/h2", wantErr: ErrNotAProtocolValue},
		{name: "bare http does not cover h2c and is not a token", in: "http", wantErr: ErrNotAProtocolValue},
		{name: "http/1.1 is one token, not http with ALPN 1.1", in: "http/2", wantErr: ErrNotAProtocolValue},
		{name: "ALPN on quic rejected", in: "quic/h3", wantErr: ErrNotAProtocolValue},
		{name: "empty ALPN rejected", in: "tls/", wantErr: ErrInvalidALPNValue},
		{name: "over-length ALPN rejected", in: "tls/" + strings.Repeat("a", 17), wantErr: ErrInvalidALPNValue},
		{name: "ALPN with a space rejected", in: "tls/h 2", wantErr: ErrInvalidALPNValue},
		{name: "ALPN with a control byte rejected", in: "tls/h\x012", wantErr: ErrInvalidALPNValue},
		{name: "ALPN with a non-ASCII byte rejected", in: "tls/hé", wantErr: ErrInvalidALPNValue},
		{name: "glob other than star rejected", in: "tls*", wantErr: ErrNotAProtocolValue},
		{name: "network value is not a protocol value", in: "10.0.0.1", wantErr: ErrNotAProtocolValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProtocolValue(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseProtocolValue(%q) error = %v, want %v", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseProtocolValue(%q) unexpected error = %v", tt.in, err)
			}
			if got.Star != tt.wantStar {
				t.Errorf("Star = %v, want %v", got.Star, tt.wantStar)
			}
			if got.Protocol != tt.wantProto {
				t.Errorf("Protocol = %q, want %q", got.Protocol, tt.wantProto)
			}
			if got.ALPN != tt.wantALPN {
				t.Errorf("ALPN = %q, want %q", got.ALPN, tt.wantALPN)
			}
		})
	}
}

// TestProtocolAndNetworkGrammarsAgreeOnStar pins the admission invariant that
// the two value grammars cannot drift apart on the shared sentinel: any
// rendering of "*" is a star in both, or an error in both.
func TestProtocolAndNetworkGrammarsAgreeOnStar(t *testing.T) {
	for _, in := range []string{"*", " * ", "\"*\"", "'*'", "[*]", "*\r\n", "**", "* *"} {
		t.Run(in, func(t *testing.T) {
			nv, nerr := ParseNetworkValue(in)
			pv, perr := ParseProtocolValue(in)
			if (nerr == nil) != (perr == nil) {
				t.Fatalf("grammars disagree for %q: network err=%v, protocol err=%v", in, nerr, perr)
			}
			if nerr == nil && nv.Star != pv.Star {
				t.Errorf("grammars disagree about Star for %q: network=%v, protocol=%v", in, nv.Star, pv.Star)
			}
		})
	}
}
