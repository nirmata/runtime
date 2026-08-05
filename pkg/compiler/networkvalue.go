package compiler

import (
	"errors"
	"net/netip"
	"strings"
)

// StarTarget is the sentinel a policy uses to mean "everything", i.e. a
// default-deny (in a deny list) or an allow-all (in an allow list). It applies
// to every behavior kind: network targets as well as open/exec paths. It is
// never programmed into a kernel map; consumers translate it into their own
// default-deny flag.
const StarTarget = "*"

// Sentinel errors returned by ParseNetworkValue. They are deliberately terse:
// callers that surface them to operators (admission's field errors, the egress
// filter's rejected-target conditions) wrap or map them into their own
// remedy-bearing vocabulary.
var (
	// ErrEmptyNetworkValue reports a value that is empty after trimming.
	ErrEmptyNetworkValue = errors.New("empty network target")
	// ErrIPv6NetworkValue reports an IPv6 literal or CIDR (IPv4-mapped IPv6
	// forms are unmapped and accepted, not reported).
	ErrIPv6NetworkValue = errors.New("IPv6 addresses and CIDRs are not supported")
	// ErrNotAnIPNetworkValue reports anything else: hostnames, URLs,
	// truncated addresses, globs other than the bare "*" sentinel.
	ErrNotAnIPNetworkValue = errors.New(`not an IPv4 address, IPv4 CIDR or "*"`)
)

// NetworkValue is the parsed form of one network target string. Exactly one
// of the fields is meaningful: Star for the "*" sentinel, Addr for a single
// address, Prefix for a CIDR.
type NetworkValue struct {
	// Star is true when the value is the StarTarget sentinel.
	Star bool
	// Addr is set for a single-address value. It is already Unmap()ed, so an
	// IPv4-mapped IPv6 literal comes back as its IPv4 form.
	Addr netip.Addr
	// Prefix is set for a CIDR value of ANY width, already unmapped and
	// Masked. Width is deliberately not checked here: ParseNetworkValue
	// defines what a value IS, and each consumer applies its own width
	// policy (see egressfilter.ParseTargets, the single narrowing point).
	Prefix netip.Prefix
}

// ParseNetworkValue parses one policy-authored network target string. This is
// the one definition of the egress target value schema: admission validation
// (validateBehavior), program-time expansion (egressfilter.ParseTargets)
// and monitor-mode matching (monitor.newNetMatcher) all consume it, so they
// cannot disagree about what a value is.
//
// The value is first trimmed of surrounding whitespace, quotes and brackets
// (CEL list rendering and hand-written YAML both leak those). Then:
//
//   - StarTarget ("*") yields Star
//   - an IPv4 literal (or IPv4-mapped IPv6 literal) yields Addr, unmapped
//   - an IPv4 CIDR (or IPv4-mapped IPv6 CIDR) of any width yields Prefix,
//     unmapped and masked
//   - everything else is an error: ErrEmptyNetworkValue,
//     ErrIPv6NetworkValue, or ErrNotAnIPNetworkValue
func ParseNetworkValue(raw string) (NetworkValue, error) {
	cleaned := strings.Trim(raw, " \t\r\n\"'[]")

	switch {
	case cleaned == "":
		return NetworkValue{}, ErrEmptyNetworkValue

	case cleaned == StarTarget:
		return NetworkValue{Star: true}, nil

	case strings.Contains(cleaned, "/"):
		prefix, err := netip.ParsePrefix(cleaned)
		if err != nil {
			return NetworkValue{}, ErrNotAnIPNetworkValue
		}
		// Unmap first so ::ffff:10.0.0.0/120 is not mistaken for IPv6.
		prefix = unmapPrefix(prefix)
		if !prefix.Addr().Is4() {
			return NetworkValue{}, ErrIPv6NetworkValue
		}
		return NetworkValue{Prefix: prefix.Masked()}, nil

	default:
		addr, err := netip.ParseAddr(cleaned)
		if err != nil {
			return NetworkValue{}, ErrNotAnIPNetworkValue
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			return NetworkValue{}, ErrIPv6NetworkValue
		}
		return NetworkValue{Addr: addr}, nil
	}
}

// unmapPrefix converts an IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/N, N >= 96)
// into its IPv4 form. Anything else is returned unchanged, so a prefix wider
// than the v4-mapped range stays IPv6 and is rejected as such.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	addr := p.Addr()
	if !addr.Is4In6() {
		return p
	}
	bits := p.Bits() - 96
	if bits < 0 {
		return p
	}
	return netip.PrefixFrom(addr.Unmap(), bits)
}
