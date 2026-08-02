package protofilter

import (
	"errors"
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

// Rejection reasons. They are surfaced verbatim to operators (log at V(0) and
// policy status conditions), so they explain the remedy, not just the fault.
const (
	ReasonEmpty        = "empty target value"
	ReasonInvalidALPN  = `ALPN suffix must be 1-16 visible ASCII characters, e.g. "tls/h2"`
	ReasonNotAProtocol = `not a protocol token: use "ssh", "tls", "tls/<alpn>", "http/1.1", "h2c", "quic", "unknown", or "*" for default-deny`
)

// RejectedTarget is a target value that could not be programmed, together with
// the reason. Rejections are returned as typed values (never dropped, never
// folded into an error) so callers can log them and attach them to policy
// status.
type RejectedTarget struct {
	Value  string
	Reason string
}

func (r RejectedTarget) String() string {
	return fmt.Sprintf("%q: %s", r.Value, r.Reason)
}

// Target is one protocol the maps can hold. ALPN is non-empty only for a
// tls/<alpn> value; an empty ALPN programmed for tls matches any ALPN.
type Target struct {
	Protocol string
	ALPN     string
}

// ParseTargets converts policy-authored protocol target strings into the
// targets the protocol maps can hold. The value grammar is defined once, in
// compiler.ParseProtocolValue, and every token it accepts is programmable, so
// no narrowing happens here.
//
//   - a protocol token (ssh, tls, tls/<alpn>, http/1.1, h2c, quic, unknown)
//     yields one target
//   - compiler.StarTarget ("*") sets star, the default-deny sentinel, and
//     yields no target
//   - everything else is returned in rejected
//
// Targets are de-duplicated, preserving first-seen order.
func ParseTargets(values []string) (targets []Target, star bool, rejected []RejectedTarget) {
	seen := make(map[Target]struct{}, len(values))
	reject := func(v, reason string) {
		rejected = append(rejected, RejectedTarget{Value: v, Reason: reason})
	}

	for _, raw := range values {
		v, err := compiler.ParseProtocolValue(raw)
		switch {
		case errors.Is(err, compiler.ErrEmptyProtocolValue):
			reject(raw, ReasonEmpty)

		case errors.Is(err, compiler.ErrInvalidALPNValue):
			reject(raw, ReasonInvalidALPN)

		case err != nil:
			reject(raw, ReasonNotAProtocol)

		case v.Star:
			star = true

		default:
			t := Target{Protocol: v.Protocol, ALPN: v.ALPN}
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			targets = append(targets, t)
		}
	}

	return targets, star, rejected
}

// protoKernelKey mirrors `struct proto_key` in _cprog/maps.h: 20 bytes with no
// padding, compared by the kernel as raw bytes. cilium/ebpf rejects a key whose
// Go layout does not match the loaded map's BTF key.
type protoKernelKey struct {
	Proto uint32
	Alpn  [compiler.MaxALPNLength]byte
}

// Protocol ids, mirroring the PROTO_* defines in _cprog/maps.h.
const (
	protoIDUnknown = 0
	protoIDSSH     = 1
	protoIDTLS     = 2
	protoIDHTTP11  = 3
	protoIDH2C     = 4
	protoIDQUIC    = 5
)

func protoID(token string) (uint32, bool) {
	switch token {
	case compiler.ProtocolUnknown:
		return protoIDUnknown, true
	case compiler.ProtocolSSH:
		return protoIDSSH, true
	case compiler.ProtocolTLS:
		return protoIDTLS, true
	case compiler.ProtocolHTTP11:
		return protoIDHTTP11, true
	case compiler.ProtocolH2C:
		return protoIDH2C, true
	case compiler.ProtocolQUIC:
		return protoIDQUIC, true
	}
	return 0, false
}

// protoToken is the inverse of protoID. Decoding is total over the ids the
// kernel writes; an unrecognized id is not folded into ProtocolUnknown, which
// would merge distinct counters, but reported as not-ok for the reader to
// surface.
func protoToken(id uint32) (string, bool) {
	switch id {
	case protoIDUnknown:
		return compiler.ProtocolUnknown, true
	case protoIDSSH:
		return compiler.ProtocolSSH, true
	case protoIDTLS:
		return compiler.ProtocolTLS, true
	case protoIDHTTP11:
		return compiler.ProtocolHTTP11, true
	case protoIDH2C:
		return compiler.ProtocolH2C, true
	case protoIDQUIC:
		return compiler.ProtocolQUIC, true
	}
	return "", false
}

func targetKernelKey(t Target) (protoKernelKey, bool) {
	id, ok := protoID(t.Protocol)
	if !ok || len(t.ALPN) > compiler.MaxALPNLength {
		return protoKernelKey{}, false
	}
	key := protoKernelKey{Proto: id}
	copy(key.Alpn[:], t.ALPN)
	return key, true
}
