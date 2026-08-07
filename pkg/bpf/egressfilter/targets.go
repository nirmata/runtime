package egressfilter

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

// MinCIDRPrefixBits is the narrowest (numerically smallest) IPv4 prefix length
// ParseTargets will expand. /24 expands to MaxExpandedTargets addresses;
// anything wider is rejected rather than expanded, because the deny/allow maps
// are plain hashes of individual /32 keys.
const MinCIDRPrefixBits = 24

// MaxExpandedTargets bounds the number of addresses a single CIDR may expand to.
const MaxExpandedTargets = 256

// Rejection reasons. They reach operators unchanged, through logs and policy
// status conditions, so they explain the remedy and not just the fault.
const (
	ReasonEmpty          = "empty target value"
	ReasonIPv6           = "IPv6 targets are not supported: the egress BPF maps are IPv4-only"
	ReasonCIDRTooWide    = "CIDR prefix is wider than /24: expand it into narrower prefixes, or use \"*\" for default-deny"
	ReasonNotAnIP        = `not an IPv4 address, IPv4 CIDR, hostname or "*"`
	ReasonWildcard       = "wildcards are not supported: list each address or fully qualified hostname, or use \"*\" for default-deny"
	ReasonDomainTooLong  = "DNS name does not fit the 128 byte domain key: name a shorter destination"
	ReasonTooManyDomains = "the pod already tracks 256 distinct DNS names: reduce the number of DNS targets its policies name"
)

// ParseTargets converts policy-authored network target strings into the IPv4
// addresses and DNS names the egress maps can hold.
//
// The value schema (trimming, star sentinel, IPv4/CIDR forms, DNS names, IPv6
// rejection) is defined once, in compiler.ParseNetworkValue. ParseTargets is
// the single narrowing point on top of it: a CIDR wider than /MinCIDRPrefixBits
// is rejected as ReasonCIDRTooWide instead of expanded, because the deny/allow
// maps are plain hashes of individual /32 keys, and a DNS name whose wire
// encoding overflows the domain key is rejected as ReasonDomainTooLong.
// Admission applies neither, so it never rejects a value the runtime would
// accept.
//
//   - an IPv4 literal yields one address
//   - an IPv4 CIDR with prefix >= /24 yields every address in the prefix
//     (network and broadcast included), at most MaxExpandedTargets
//   - a DNS name yields one host, normalized by compiler.ParseNetworkValue
//   - compiler.StarTarget ("*") sets star, the default-deny sentinel, and
//     yields neither
//   - IPv6 literals/CIDRs, wider CIDRs, oversized names and empty values are
//     returned in rejected
//
// Addresses and hosts are de-duplicated, preserving first-seen order.
func ParseTargets(values []string) (addrs []netip.Addr, hosts []string, star bool, rejected []compiler.RejectedTarget) {
	seenAddr := make(map[netip.Addr]struct{}, len(values))
	add := func(a netip.Addr) {
		if _, ok := seenAddr[a]; ok {
			return
		}
		seenAddr[a] = struct{}{}
		addrs = append(addrs, a)
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
			reject(raw, ReasonNotAnIP)

		case v.Star:
			star = true

		case v.Host != "":
			switch _, err := encodeDomainKey(v.Host); {
			case errors.Is(err, errDomainKeyTooLong):
				reject(raw, ReasonDomainTooLong)
			case err != nil:
				reject(raw, ReasonNotAnIP)
			default:
				addHost(v.Host)
			}

		case v.Prefix.IsValid():
			if v.Prefix.Bits() < MinCIDRPrefixBits {
				reject(raw, ReasonCIDRTooWide)
				continue
			}
			for _, a := range expandPrefix(v.Prefix) {
				add(a)
			}

		default:
			add(v.Addr)
		}
	}

	return addrs, hosts, star, rejected
}

// expandPrefix returns every address in an IPv4 prefix, capped at
// MaxExpandedTargets. The caller guarantees prefix.Bits() >= MinCIDRPrefixBits,
// but the cap is enforced here too so the function is safe on its own.
func expandPrefix(prefix netip.Prefix) []netip.Addr {
	prefix = prefix.Masked()
	// MaxExpandedTargets is 1<<8; keeping the shift below that also keeps it
	// well inside int range on every platform.
	count := MaxExpandedTargets
	if shift := prefix.Addr().BitLen() - prefix.Bits(); shift >= 0 && shift < 8 {
		count = 1 << uint(shift)
	}

	out := make([]netip.Addr, 0, count)
	addr := prefix.Addr()
	for i := 0; i < count && addr.IsValid(); i++ {
		out = append(out, addr)
		addr = addr.Next()
	}
	return out
}

// addrKey converts an IPv4 address into the map key the BPF program uses. The
// program keys on the raw big-endian `daddr` word read out of the packet, and
// cilium/ebpf marshals a uint32 in native byte order, so decoding the address
// bytes with the native order round-trips the on-the-wire layout on both
// little- and big-endian hosts.
func addrKey(addr netip.Addr) (uint32, bool) {
	addr = addr.Unmap()
	if !addr.Is4() {
		return 0, false
	}
	b := addr.As4()
	return binary.NativeEndian.Uint32(b[:]), true
}

// keyAddr is the inverse of addrKey.
func keyAddr(key uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], key)
	return netip.AddrFrom4(b)
}
