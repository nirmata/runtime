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
	// ErrWildcardNetworkValue reports a wildcard such as "*.example.com",
	// distinct from the bare "*" sentinel.
	ErrWildcardNetworkValue = errors.New(`wildcards are not supported: list each address or fully qualified hostname, or use "*" to match everything`)
	// ErrNotAnIPNetworkValue reports anything else: URLs, truncated
	// addresses, and strings that are not a usable hostname either (a single
	// label, an over-long or malformed label, a numeric last label).
	ErrNotAnIPNetworkValue = errors.New(`not an IPv4 address, IPv4 CIDR, hostname or "*"`)
)

const (
	maxHostnameLen = 253
	maxLabelLen    = 63
)

// NetworkValue is the parsed form of one network target string. Exactly one
// of the fields is meaningful: Star for the "*" sentinel, Addr for a single
// address, Prefix for a CIDR, Host for a hostname.
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
	// Host is set for a hostname value, lowercased and without the root dot,
	// so "API.Example.COM." and "api.example.com" are the same value.
	Host string
}

// ParseNetworkValue parses one policy-authored network target string. This is
// the ONE definition of the egress target value grammar: admission validation
// (validateNetworkBehavior), program-time expansion (egressfilter.ParseTargets)
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
//   - a multi-label DNS name yields Host, lowercased and stripped of its
//     root dot
//   - everything else is an error: ErrEmptyNetworkValue,
//     ErrIPv6NetworkValue, ErrWildcardNetworkValue, or
//     ErrNotAnIPNetworkValue
func ParseNetworkValue(raw string) (NetworkValue, error) {
	cleaned := strings.Trim(raw, " \t\r\n\"'[]")

	switch {
	case cleaned == "":
		return NetworkValue{}, ErrEmptyNetworkValue

	case cleaned == StarTarget:
		return NetworkValue{Star: true}, nil

	case strings.Contains(cleaned, "*"):
		return NetworkValue{}, ErrWildcardNetworkValue

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
		if addr, err := netip.ParseAddr(cleaned); err == nil {
			addr = addr.Unmap()
			if !addr.Is4() {
				return NetworkValue{}, ErrIPv6NetworkValue
			}
			return NetworkValue{Addr: addr}, nil
		}
		host, err := parseHostname(cleaned)
		if err != nil {
			return NetworkValue{}, err
		}
		return NetworkValue{Host: host}, nil
	}
}

func parseHostname(cleaned string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(cleaned, "."))
	if host == "" || len(host) > maxHostnameLen {
		return "", ErrNotAnIPNetworkValue
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", ErrNotAnIPNetworkValue
	}
	for _, label := range labels {
		if !validLabel(label) {
			return "", ErrNotAnIPNetworkValue
		}
	}
	// A numeric last label means a truncated or over-long address ("10.0.0",
	// "1.2.3.4.5"), which must stay an error rather than becoming a name.
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", ErrNotAnIPNetworkValue
	}
	return host, nil
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > maxLabelLen {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
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
