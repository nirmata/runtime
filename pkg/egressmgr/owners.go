package egressmgr

import (
	"net/netip"

	"github.com/nirmata/runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/runtime/pkg/bpf/protofilter"
	"github.com/nirmata/runtime/pkg/compiler"
)

// sideOwners holds, for one side of a pair, the policy uids that asked for each
// programmed target. Prefixes and DNS names live in separate kernel maps and
// so are refcounted separately.
type sideOwners struct {
	prefixes map[netip.Prefix]map[string]struct{}
	hosts    map[string]map[string]struct{}
}

func newSideOwners() sideOwners {
	return sideOwners{
		prefixes: make(map[netip.Prefix]map[string]struct{}),
		hosts:    make(map[string]map[string]struct{}),
	}
}

// claim records that uid wants every target in pair programmed on this pod.
func (pa *podAttachment) claim(uid string, pair *compiler.AllowDenyPair) {
	if pair == nil {
		return
	}
	claimSide(pa.allowOwners, uid, pair.Allow)
	claimSide(pa.denyOwners, uid, pair.Deny)
}

// release drops uid's claim on pair and returns only the targets that no policy
// wants any more. One filter is shared by every policy attached to the pod, so
// deleting a detaching policy's pair wholesale would revoke targets another
// policy still depends on.
func (pa *podAttachment) release(uid string, pair *compiler.AllowDenyPair) *compiler.AllowDenyPair {
	if pair == nil {
		return &compiler.AllowDenyPair{}
	}
	return &compiler.AllowDenyPair{
		Allow: releaseSide(pa.allowOwners, uid, pair.Allow),
		Deny:  releaseSide(pa.denyOwners, uid, pair.Deny),
	}
}

// Ownership is keyed on the masked prefix and the normalized host rather than
// the authored string, so that two policies spelling one target differently
// still refcount as one entry. compiler.StarTarget yields neither and is
// refcounted separately, by the default-deny uid set.
func claimSide(owners sideOwners, uid string, values []string) {
	prefixes, hosts, _, _ := egressfilter.ParseTargets(values)
	claimKeys(owners.prefixes, uid, prefixes)
	claimKeys(owners.hosts, uid, hosts)
}

// releaseSide returns the canonical spelling of each orphaned target, which
// ParseTargets accepts, so the result feeds straight back into the filter.
func releaseSide(owners sideOwners, uid string, values []string) []string {
	prefixes, hosts, _, _ := egressfilter.ParseTargets(values)

	orphanedPrefixes := releaseKeys(owners.prefixes, uid, prefixes)
	orphanedHosts := releaseKeys(owners.hosts, uid, hosts)
	if len(orphanedPrefixes)+len(orphanedHosts) == 0 {
		return nil
	}

	orphaned := make([]string, 0, len(orphanedPrefixes)+len(orphanedHosts))
	for _, prefix := range orphanedPrefixes {
		orphaned = append(orphaned, prefix.String())
	}
	return append(orphaned, orphanedHosts...)
}

func claimKeys[K comparable](owners map[K]map[string]struct{}, uid string, keys []K) {
	for _, k := range keys {
		if owners[k] == nil {
			owners[k] = make(map[string]struct{})
		}
		owners[k][uid] = struct{}{}
	}
}

func releaseKeys[K comparable](owners map[K]map[string]struct{}, uid string, keys []K) []K {
	var orphaned []K
	for _, k := range keys {
		holders, ok := owners[k]
		if !ok {
			continue
		}
		delete(holders, uid)
		if len(holders) == 0 {
			delete(owners, k)
			orphaned = append(orphaned, k)
		}
	}
	return orphaned
}

// protoOwners holds, for one side of a pair, the policy uids that asked for
// each programmed protocol target.
type protoOwners map[protofilter.Target]map[string]struct{}

func newProtoOwners() protoOwners {
	return make(protoOwners)
}

// claimProtos records that uid wants every protocol target in pair programmed
// on this pod.
func (pa *podAttachment) claimProtos(uid string, pair *compiler.AllowDenyPair) {
	if pair == nil {
		return
	}
	claimProtoSide(pa.allowProtoOwners, uid, pair.Allow)
	claimProtoSide(pa.denyProtoOwners, uid, pair.Deny)
}

// releaseProtos drops uid's claim on pair and returns only the protocol targets
// no policy wants any more. The protocol maps are shared by every policy
// attached to the pod, exactly as the address maps are, so deleting a detaching
// policy's pair wholesale would revoke protocols another policy still allows or
// denies.
func (pa *podAttachment) releaseProtos(uid string, pair *compiler.AllowDenyPair) *compiler.AllowDenyPair {
	if pair == nil {
		return &compiler.AllowDenyPair{}
	}
	return &compiler.AllowDenyPair{
		Allow: releaseProtoSide(pa.allowProtoOwners, uid, pair.Allow),
		Deny:  releaseProtoSide(pa.denyProtoOwners, uid, pair.Deny),
	}
}

// Ownership is keyed on the parsed target, so "tls/h2" and " tls/h2 " refcount
// as one entry. compiler.StarTarget yields no target and is refcounted
// separately, by the protocol default-deny uid set.
func claimProtoSide(owners protoOwners, uid string, values []string) {
	targets, _, _ := protofilter.ParseTargets(values)
	claimKeys(owners, uid, targets)
}

// releaseProtoSide returns the canonical spelling of each orphaned target,
// which ParseTargets accepts, so the result feeds straight back into the filter.
func releaseProtoSide(owners protoOwners, uid string, values []string) []string {
	targets, _, _ := protofilter.ParseTargets(values)

	orphaned := releaseKeys(owners, uid, targets)
	if len(orphaned) == 0 {
		return nil
	}
	out := make([]string, 0, len(orphaned))
	for _, t := range orphaned {
		out = append(out, t.String())
	}
	return out
}
