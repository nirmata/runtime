package egressfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

// MinCIDRPrefixBits is the narrowest (numerically smallest) IPv4 prefix length
// ParseTargets will expand. /24 expands to MaxExpandedTargets addresses;
// anything wider is rejected rather than expanded, because the deny/allow maps
// are plain hashes of individual /32 keys (see #41 for the LPM-trie follow-up).
const MinCIDRPrefixBits = 24

// MaxExpandedTargets bounds the number of addresses a single CIDR may expand to.
const MaxExpandedTargets = 256

// Rejection reasons. They are surfaced verbatim to operators (log at V(0) and
// policy status conditions), so they explain the remedy, not just the fault.
const (
	ReasonEmpty       = "empty target value"
	ReasonIPv6        = "IPv6 targets are not supported: the egress BPF maps are IPv4-only"
	ReasonCIDRTooWide = "CIDR prefix is wider than /24: expand it into narrower prefixes, or use \"*\" for default-deny"
	ReasonNotAnIP     = "not an IPv4 address or CIDR: hostnames cannot be resolved at policy compile time"
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

// ParseTargets converts policy-authored network target strings into the IPv4
// addresses the egress maps can hold.
//
// The value grammar (trimming, star sentinel, IPv4/CIDR forms, IPv6
// rejection) is defined once, in compiler.ParseNetworkValue; ParseTargets is
// the SINGLE narrowing point where the program-time restriction is applied on
// top of it: a CIDR wider than /MinCIDRPrefixBits is rejected as
// ReasonCIDRTooWide instead of expanded, because the deny/allow maps are
// plain hashes of individual /32 keys (see #41 for the LPM-trie follow-up).
// Admission validation deliberately does NOT apply this restriction, so it
// never rejects a value the runtime would accept.
//
//   - an IPv4 literal yields one address
//   - an IPv4 CIDR with prefix >= /24 yields every address in the prefix
//     (network and broadcast included), at most MaxExpandedTargets
//   - compiler.StarTarget ("*") sets star, the default-deny sentinel, and
//     yields no address
//   - IPv6 literals/CIDRs, wider CIDRs, hostnames and empty values are
//     returned in rejected
//
// Addresses are de-duplicated, preserving first-seen order.
func ParseTargets(values []string) (addrs []netip.Addr, star bool, rejected []RejectedTarget) {
	seen := make(map[netip.Addr]struct{}, len(values))
	add := func(a netip.Addr) {
		if _, ok := seen[a]; ok {
			return
		}
		seen[a] = struct{}{}
		addrs = append(addrs, a)
	}
	reject := func(v, reason string) {
		rejected = append(rejected, RejectedTarget{Value: v, Reason: reason})
	}

	for _, raw := range values {
		v, err := compiler.ParseNetworkValue(raw)
		switch {
		case errors.Is(err, compiler.ErrEmptyNetworkValue):
			reject(raw, ReasonEmpty)

		case errors.Is(err, compiler.ErrIPv6NetworkValue):
			reject(raw, ReasonIPv6)

		case err != nil:
			reject(raw, ReasonNotAnIP)

		case v.Star:
			star = true

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

	return addrs, star, rejected
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
