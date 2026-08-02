package compiler

import (
	"errors"
	"strings"
)

// Protocol tokens a protocol behavior value may name. Classification happens
// in the kernel against the first data segment of a flow, so the set is
// limited to client-speaks-first protocols with a fixed signature; traffic
// matching none of them is classified ProtocolUnknown.
const (
	ProtocolSSH     = "ssh"
	ProtocolTLS     = "tls"
	ProtocolHTTP11  = "http/1.1"
	ProtocolH2C     = "h2c"
	ProtocolQUIC    = "quic"
	ProtocolUnknown = "unknown"
)

// MaxALPNLength is the size of the kernel's ALPN match buffer. The grammar
// caps the tls/<alpn> suffix at this length so admission never accepts a value
// the classifier cannot match.
const MaxALPNLength = 16

// Sentinel errors returned by ParseProtocolValue. Terse for the same reason as
// the ParseNetworkValue set: callers wrap them into their own vocabulary.
var (
	// ErrEmptyProtocolValue reports a value that is empty after trimming.
	ErrEmptyProtocolValue = errors.New("empty protocol target")
	// ErrInvalidALPNValue reports a tls/<alpn> suffix that is empty, longer
	// than MaxALPNLength, or not visible ASCII.
	ErrInvalidALPNValue = errors.New("ALPN must be 1-16 visible ASCII characters")
	// ErrNotAProtocolValue reports anything else: an unrecognized token, an
	// ALPN suffix on a token other than tls, wrong case.
	ErrNotAProtocolValue = errors.New(`not a protocol token ("ssh", "tls", "tls/<alpn>", "http/1.1", "h2c", "quic", "unknown") or "*"`)
)

// ProtocolValue is the parsed form of one protocol target string. Star is
// true for the "*" sentinel; otherwise Protocol holds one of the Protocol*
// tokens and ALPN is non-empty only for a tls/<alpn> value.
type ProtocolValue struct {
	Star     bool
	Protocol string
	ALPN     string
}

// ParseProtocolValue parses one policy-authored protocol target string. This
// is the ONE definition of the protocol target value grammar: admission
// validation, program-time map filling (protofilter.ParseTargets) and
// monitor-mode matching all consume it, so they cannot disagree about what a
// value is.
//
// The value is trimmed exactly as ParseNetworkValue trims, so the two
// grammars agree about "*". Then:
//
//   - StarTarget ("*") yields Star
//   - a bare token (ssh, tls, http/1.1, h2c, quic, unknown) yields Protocol
//   - tls/<alpn> yields Protocol tls with the ALPN, which must be 1 to
//     MaxALPNLength bytes of visible ASCII (ALPN identifiers are
//     case-sensitive byte strings, so no folding happens)
//   - everything else is ErrEmptyProtocolValue, ErrInvalidALPNValue or
//     ErrNotAProtocolValue
func ParseProtocolValue(raw string) (ProtocolValue, error) {
	cleaned := strings.Trim(raw, " \t\r\n\"'[]")

	switch cleaned {
	case "":
		return ProtocolValue{}, ErrEmptyProtocolValue
	case StarTarget:
		return ProtocolValue{Star: true}, nil
	case ProtocolSSH, ProtocolTLS, ProtocolHTTP11, ProtocolH2C, ProtocolQUIC, ProtocolUnknown:
		return ProtocolValue{Protocol: cleaned}, nil
	}

	token, alpn, ok := strings.Cut(cleaned, "/")
	if !ok || token != ProtocolTLS {
		return ProtocolValue{}, ErrNotAProtocolValue
	}
	if !validALPN(alpn) {
		return ProtocolValue{}, ErrInvalidALPNValue
	}
	return ProtocolValue{Protocol: ProtocolTLS, ALPN: alpn}, nil
}

// validALPN reports whether s can be programmed into the kernel's ALPN match
// buffer: 1 to MaxALPNLength bytes, each visible ASCII. The classifier
// enforces the same character range when it extracts an ALPN off the wire, so
// a value this accepts is always comparable against what the kernel observed.
func validALPN(s string) bool {
	if len(s) == 0 || len(s) > MaxALPNLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
