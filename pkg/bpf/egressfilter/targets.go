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
	ReasonInvalidEntry   = `not an IP address, CIDR, hostname or "*"`
	ReasonWildcard       = "wildcards are not supported: list each address or fully qualified hostname, or use \"*\" for default-deny"
	ReasonDomainTooLong  = "DNS name does not fit the 128 byte domain key: name a shorter destination"
	ReasonTooManyDomains = "the pod already tracks 256 distinct DNS names: reduce the number of DNS targets its policies name"
)

// ParseTargets converts policy-authored network target strings into the IP
// prefixes and DNS names the egress maps can hold.
//
//   - an IPv4 or IPv6 literal yields a full-length prefix
//   - a CIDR yields that prefix, masked
//   - a DNS name yields one host, normalized by compiler.ParseNetworkValue
//   - compiler.StarTarget ("*") sets star, the default-deny sentinel, and
//     yields neither
//   - wildcards, oversized names and empty values are returned in rejected
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

// Address families as `FAMILY_IPV4` and `FAMILY_IPV6` in _cprog/maps.h.
const (
	familyIPv4 = 4
	familyIPv6 = 6
)

// lpmKey mirrors `struct lpm_key` in _cprog/maps.h. cilium/ebpf rejects a key
// whose Go layout does not match the loaded map's BTF key.
type lpmKey struct {
	Prefixlen uint32
	Family    uint32
	Addr      [16]byte
}

// prefixKey converts a prefix into the longest-prefix-match key. Prefixlen
// counts the Family word too, so the trie never matches across families.
func prefixKey(prefix netip.Prefix) lpmKey {
	family, addr := familyAddr(prefix.Addr())
	return lpmKey{
		Prefixlen: 32 + uint32(prefix.Bits()),
		Family:    family,
		Addr:      addr,
	}
}

// familyAddr lays addr out the way the kernel keys do: an IPv4 address in the
// first 4 bytes, in wire order, so the trie compares it most-significant byte
// first.
func familyAddr(addr netip.Addr) (uint32, [16]byte) {
	var b [16]byte
	if addr = addr.Unmap(); addr.Is4() {
		a4 := addr.As4()
		copy(b[:], a4[:])
		return familyIPv4, b
	}
	return familyIPv6, addr.As16()
}

// keyAddr is the inverse of familyAddr.
func keyAddr(family uint32, b [16]byte) netip.Addr {
	if family == familyIPv4 {
		return netip.AddrFrom4([4]byte(b[:4]))
	}
	return netip.AddrFrom16(b)
}
