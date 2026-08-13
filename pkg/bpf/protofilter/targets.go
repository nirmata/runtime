package protofilter

import (
	"github.com/nirmata/runtime/pkg/compiler"
)

// Target is one protocol the maps can hold. ALPN is non-empty only for a
// tls/<alpn> value; an empty ALPN programmed for tls matches any ALPN.
type Target struct {
	Protocol string
	ALPN     string
}

// ParseTargets converts policy-authored protocol target strings into the
// targets the protocol maps can hold. The value schema is defined once, in
// compiler.ParseProtocolValue, and every token it accepts is programmable, so
// no narrowing happens here; a rejection carries the parser's own message.
//
//   - a protocol token (ssh, tls, tls/<alpn>, dns, http/1.1, http/2, quic)
//     yields one target
//   - compiler.StarTarget ("*") sets star, the default-deny sentinel, and
//     yields no target
//   - everything else is returned in rejected
//
// Targets are de-duplicated, preserving first-seen order.
func ParseTargets(values []string) (targets []Target, star bool, rejected []compiler.RejectedTarget) {
	seen := make(map[Target]struct{}, len(values))

	for _, raw := range values {
		v, err := compiler.ParseProtocolValue(raw)
		switch {
		case err != nil:
			rejected = append(rejected, compiler.RejectedTarget{Value: raw, Reason: err.Error()})

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
	protoIDUnclassified = 0
	protoIDSSH          = 1
	protoIDTLS          = 2
	protoIDHTTP11       = 3
	protoIDHTTP2        = 4
	protoIDQUIC         = 5
	protoIDDNS          = 6
)

// protoID also encodes ProtocolUnclassified, which the schema rejects: it can
// appear in an observation key (SeedProtoEvent) but never reaches the policy
// maps, whose only feed is ParseTargets.
func protoID(token string) (uint32, bool) {
	switch token {
	case compiler.ProtocolUnclassified:
		return protoIDUnclassified, true
	case compiler.ProtocolSSH:
		return protoIDSSH, true
	case compiler.ProtocolTLS:
		return protoIDTLS, true
	case compiler.ProtocolDNS:
		return protoIDDNS, true
	case compiler.ProtocolHTTP11:
		return protoIDHTTP11, true
	case compiler.ProtocolHTTP2:
		return protoIDHTTP2, true
	case compiler.ProtocolQUIC:
		return protoIDQUIC, true
	}
	return 0, false
}

// protoToken is the inverse of protoID. Decoding is total over the ids the
// kernel writes; an unrecognized id is not folded into ProtocolUnclassified,
// which would merge distinct counters, but reported as not-ok for the reader
// to surface.
func protoToken(id uint32) (string, bool) {
	switch id {
	case protoIDUnclassified:
		return compiler.ProtocolUnclassified, true
	case protoIDSSH:
		return compiler.ProtocolSSH, true
	case protoIDTLS:
		return compiler.ProtocolTLS, true
	case protoIDDNS:
		return compiler.ProtocolDNS, true
	case protoIDHTTP11:
		return compiler.ProtocolHTTP11, true
	case protoIDHTTP2:
		return compiler.ProtocolHTTP2, true
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

// String renders the target the way a policy spells it, so a value round-trips
// back through ParseTargets.
func (t Target) String() string {
	if t.ALPN == "" {
		return t.Protocol
	}
	return t.Protocol + "/" + t.ALPN
}
