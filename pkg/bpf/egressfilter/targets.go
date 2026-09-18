package egressfilter

import (
	"errors"
	"net/netip"

	"github.com/nirmata/runtime/pkg/compiler"
)

// Rejection reasons. They reach operators unchanged, through logs and policy
// status conditions, so they explain the remedy and not just the fault.
const (
	ReasonEmpty          = "empty target value"
	ReasonIPv6           = "IPv6 targets are not supported: the egress BPF maps are IPv4-only"
	ReasonInvalidEntry   = `not an IPv4 address, IPv4 CIDR, hostname or "*"`
	ReasonWildcard       = "wildcards are not supported: list each address or fully qualified hostname, or use \"*\" for default-deny"
	ReasonDomainTooLong  = "DNS name does not fit the 128 byte domain key: name a shorter destination"
	ReasonTooManyDomains = "the pod already tracks 256 distinct DNS names: reduce the number of DNS targets its policies name"
)

// ParseTargets converts policy-authored network target strings into the IPv4
// prefixes and DNS names the egress maps can hold.
//
//   - an IPv4 literal yields a /32 prefix
//   - an IPv4 CIDR yields that prefix, masked
//   - a DNS name yields one host, normalized by compiler.ParseNetworkValue
//   - compiler.StarTarget ("*") sets star, the default-deny sentinel, and
//     yields neither
//   - IPv6 literals/CIDRs, wildcards, oversized names and empty values are
//     returned in rejected
//   - Domains
//
// Prefixes and hosts are de-duplicated, preserving first-seen order.
func ParseTargets(values []string) (prefixes []netip.Prefix, hosts []string, star bool, rejected []compiler.RejectedTarget) {
	seenPrefix := make(map[netip.Prefix]struct{}, len(values))
	add := func(p netip.Prefix) {
		p = p.Masked()
		if _, ok := seenPrefix[p]; ok {
			return
		}
		seenPrefix[p] = struct{}{}
		prefixes = append(prefixes, p)
	}
	seenHost := make(map[string]struct{}, len(values))
	addHost := func(h string) {
		if _, ok := seenHost[h]; ok {
			return
		}
		seenHost[h] = struct{}{}
		hosts = append(hosts, h)
	}
	reject := func(v, reason string) {
		rejected = append(rejected, compiler.RejectedTarget{Value: v, Reason: reason})
	}

	for _, raw := range values {
		v, err := compiler.ParseNetworkValue(raw)
		switch {
		case errors.Is(err, compiler.ErrEmptyNetworkValue):
			reject(raw, ReasonEmpty)

		case errors.Is(err, compiler.ErrIPv6NetworkValue):
			reject(raw, ReasonIPv6)

		case errors.Is(err, compiler.ErrWildcardNetworkValue):
			reject(raw, ReasonWildcard)

		case err != nil:
			reject(raw, ReasonInvalidEntry)

		case v.Star:
			star = true

		case v.Host != "":
			switch _, err := encodeDomainKey(v.Host); {
			case errors.Is(err, errDomainKeyTooLong):
				reject(raw, ReasonDomainTooLong)
			case err != nil:
				reject(raw, ReasonInvalidEntry)
			default:
				addHost(v.Host)
			}

		case v.Prefix.IsValid():
			add(v.Prefix)

		default:
			add(netip.PrefixFrom(v.Addr, v.Addr.BitLen()))
		}
	}

	return prefixes, hosts, star, rejected
}

// ipv4LpmKey mirrors `struct ipv4_lpm_key` in _cprog/maps.h. cilium/ebpf
// rejects a key whose Go layout does not match the loaded map's BTF key.
type ipv4LpmKey struct {
	Prefixlen uint32
	Addr      [4]byte
}

// prefixKey converts an IPv4 prefix into the longest-prefix-match key. The trie
// compares Addr most-significant-byte first, which is the order the address
// already has on the wire, so the four bytes are copied verbatim instead of
// going through a native-order word the way the ip_events key does.
func prefixKey(prefix netip.Prefix) (ipv4LpmKey, bool) {
	addr := prefix.Addr().Unmap()
	if !addr.Is4() {
		return ipv4LpmKey{}, false
	}
	return ipv4LpmKey{
		Prefixlen: uint32(prefix.Bits()),
		Addr:      addr.As4(),
	}, true
}
