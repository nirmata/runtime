package egressmgr

import (
	"net/netip"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

// claim records that uid wants every address in pair programmed on this pod.
func (pa *podAttachment) claim(uid string, pair *compiler.AllowDenyPair) {
	if pair == nil {
		return
	}
	if pa.allowOwners == nil {
		pa.allowOwners = make(map[netip.Addr]map[string]struct{})
	}
	if pa.denyOwners == nil {
		pa.denyOwners = make(map[netip.Addr]map[string]struct{})
	}
	claimSide(pa.allowOwners, uid, pair.Allow)
	claimSide(pa.denyOwners, uid, pair.Deny)
}

// release drops uid's claim on pair and returns only the addresses that no
// policy wants any more. One filter is shared by every policy attached to the
// pod, so deleting a detaching policy's pair wholesale would revoke addresses
// another policy still depends on.
func (pa *podAttachment) release(uid string, pair *compiler.AllowDenyPair) *compiler.AllowDenyPair {
	if pair == nil {
		return &compiler.AllowDenyPair{}
	}
	return &compiler.AllowDenyPair{
		Allow: releaseSide(pa.allowOwners, uid, pair.Allow),
		Deny:  releaseSide(pa.denyOwners, uid, pair.Deny),
	}
}

// Ownership is keyed on the parsed address rather than the authored string so
// that two policies spelling one address differently still refcount as one
// entry. compiler.StarTarget yields no address and is refcounted separately, by
// the default-deny uid set.
func claimSide(owners map[netip.Addr]map[string]struct{}, uid string, values []string) {
	addrs, _, _ := egressfilter.ParseTargets(values)
	for _, addr := range addrs {
		if owners[addr] == nil {
			owners[addr] = make(map[string]struct{})
		}
		owners[addr][uid] = struct{}{}
	}
}

// releaseSide returns the canonical spelling of each orphaned address, which
// ParseTargets accepts, so the result feeds straight back into the filter.
func releaseSide(owners map[netip.Addr]map[string]struct{}, uid string, values []string) []string {
	addrs, _, _ := egressfilter.ParseTargets(values)
	var orphaned []string
	for _, addr := range addrs {
		holders, ok := owners[addr]
		if !ok {
			continue
		}
		delete(holders, uid)
		if len(holders) == 0 {
			delete(owners, addr)
			orphaned = append(orphaned, addr.String())
		}
	}
	return orphaned
}
