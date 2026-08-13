package e2e_test

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/nirmata/runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
)

// egressMaps holds handles onto the maps of one freshly loaded filter. Reading
// domain_ids and seeding ip_domain is how this lane stands in for the DNS
// snooper, and the filter keeps its own handles private, so the maps are
// reopened by id: ids rise monotonically per boot, so an id minted after the
// load cannot belong to anything else.
type egressMaps struct {
	filter *egressfilter.EgressFilter

	domainIDs      *ebpf.Map
	ipDomain       *ebpf.Map
	ipEvents       *ebpf.Map
	allowedDomains *ebpf.Map
	bannedDomains  *ebpf.Map
}

func loadFilterWithMaps(t *testing.T) *egressMaps {
	t.Helper()

	before := highestMapID(t)

	logger := logr.Discard()
	f, err := egressfilter.New(&logger)
	if err != nil {
		t.Fatalf("loading egressblock objects: %+v", err)
	}

	em := &egressMaps{filter: f}
	wanted := map[string]**ebpf.Map{
		"domain_ids":      &em.domainIDs,
		"ip_domain":       &em.ipDomain,
		"ip_events":       &em.ipEvents,
		"allowed_domains": &em.allowedDomains,
		"banned_domains":  &em.bannedDomains,
	}

	for id := before; ; {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			t.Fatalf("walking map ids from %d: %v", id, err)
		}
		id = next

		m, err := ebpf.NewMapFromID(next)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			m.Close()
			continue
		}
		slot, ok := wanted[info.Name]
		if !ok || *slot != nil {
			m.Close()
			continue
		}
		*slot = m
		t.Cleanup(func() { m.Close() })
	}

	for name, slot := range wanted {
		if *slot == nil {
			t.Fatalf("no map named %q was created by the load; cannot reach it from this package", name)
		}
	}
	return em
}

func highestMapID(t *testing.T) ebpf.MapID {
	t.Helper()
	var high ebpf.MapID
	for {
		next, err := ebpf.MapGetNextID(high)
		if errors.Is(err, os.ErrNotExist) {
			return high
		}
		if err != nil {
			t.Fatalf("walking map ids from %d: %v", high, err)
		}
		high = next
	}
}

// domainWireKey states the domain_ids key encoding independently of the encoder
// under test: length-prefixed lowercase labels, a terminating zero, zero padded
// to the key width.
func domainWireKey(t *testing.T, labels ...string) [128]byte {
	t.Helper()
	var key [128]byte
	n := 0
	for _, label := range labels {
		key[n] = byte(len(label))
		n++
		n += copy(key[n:], label)
	}
	if n >= len(key) {
		t.Fatalf("fixture encodes to %d bytes, which does not fit the %d byte key", n+1, len(key))
	}
	return key
}

// ipDomainKey mirrors the raw big-endian daddr word the BPF program reads off
// the packet; cilium/ebpf marshals a uint32 in native order.
func ipDomainKey(addr netip.Addr) uint32 {
	b := addr.As4()
	return binary.NativeEndian.Uint32(b[:])
}

func domainID(t *testing.T, m *ebpf.Map, key [128]byte, what string) uint32 {
	t.Helper()
	var id uint32
	if err := m.Lookup(&key, &id); err != nil {
		t.Fatalf("domain_ids lookup for %s: %v", what, err)
	}
	return id
}

func requireDomainAbsent(t *testing.T, m *ebpf.Map, key [128]byte, what string) {
	t.Helper()
	var id uint32
	err := m.Lookup(&key, &id)
	if err == nil {
		t.Fatalf("domain_ids still holds %s with id %d; the snooper can still mint that id", what, id)
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("domain_ids lookup for %s: %v", what, err)
	}
}

func attributedDomainID(t *testing.T, m *ebpf.Map, addr netip.Addr) (uint32, bool) {
	t.Helper()
	key := ipDomainKey(addr)
	var id uint32
	err := m.Lookup(&key, &id)
	switch {
	case err == nil:
		return id, true
	case errors.Is(err, ebpf.ErrKeyNotExist):
		return 0, false
	default:
		t.Fatalf("ip_domain lookup for %s: %v", addr, err)
		return 0, false
	}
}

func hasDomainID(t *testing.T, m *ebpf.Map, id uint32, what string) bool {
	t.Helper()
	var val uint8
	err := m.Lookup(&id, &val)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ebpf.ErrKeyNotExist):
		return false
	default:
		t.Fatalf("%s lookup for id %d: %v", what, id, err)
		return false
	}
}

// TestBPFRetiredDomainIDIsReusableWithoutInheritingStaleAttribution is the
// assertion the retire ordering exists for. ip_domain entries outlive the policy
// that caused the name to be interned, so handing the id to a different domain
// while one survives would authorize an address nobody resolved and report it
// under the new name.
func TestBPFRetiredDomainIDIsReusableWithoutInheritingStaleAttribution(t *testing.T) {
	requireBPFCapableHost(t)

	em := loadFilterWithMaps(t)

	keepKey := domainWireKey(t, "keep", "example", "com")
	retiredKey := domainWireKey(t, "api", "foo", "com")
	reusedKey := domainWireKey(t, "evil", "bar", "com")

	// keep.example.com is interned first only so the reused id is not also the
	// first id the allocator would hand out; without it the assertion in step 4
	// would pass on a filter that never reused anything.
	if rejected, err := em.filter.AddIps(&compiler.AllowDenyPair{
		Allow: []string{"keep.example.com", "api.foo.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("programming allowed domains: err = %v, rejected = %v", err, rejected)
	}

	keepID := domainID(t, em.domainIDs, keepKey, "keep.example.com")
	retiredID := domainID(t, em.domainIDs, retiredKey, "api.foo.com")
	if keepID == retiredID {
		t.Fatalf("both names interned to id %d", retiredID)
	}
	if !hasDomainID(t, em.allowedDomains, retiredID, "allowed_domains") {
		t.Fatalf("allowed_domains does not hold id %d for api.foo.com", retiredID)
	}

	// What the snooper would have recorded from an A record for api.foo.com.
	staleAddr := netip.MustParseAddr("198.51.100.7")
	staleKey := ipDomainKey(staleAddr)
	if err := em.ipDomain.Put(&staleKey, &retiredID); err != nil {
		t.Fatalf("seeding ip_domain[%s] = %d: %v", staleAddr, retiredID, err)
	}
	if got, ok := attributedDomainID(t, em.ipDomain, staleAddr); !ok || got != retiredID {
		t.Fatalf("seeded ip_domain[%s] reads back as (%d, %v), want (%d, true)", staleAddr, got, ok, retiredID)
	}

	if rejected, err := em.filter.DeleteIps(&compiler.AllowDenyPair{
		Allow: []string{"api.foo.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("removing api.foo.com: err = %v, rejected = %v", err, rejected)
	}

	requireDomainAbsent(t, em.domainIDs, retiredKey, "api.foo.com")
	if hasDomainID(t, em.allowedDomains, retiredID, "allowed_domains") {
		t.Errorf("allowed_domains still authorizes id %d after api.foo.com was removed", retiredID)
	}
	if got, ok := attributedDomainID(t, em.ipDomain, staleAddr); ok {
		t.Errorf("ip_domain still attributes %s to id %d after the retire; the sweep did not run", staleAddr, got)
	}
	if got := domainID(t, em.domainIDs, keepKey, "keep.example.com"); got != keepID {
		t.Errorf("keep.example.com id changed from %d to %d; the wrong name was retired", keepID, got)
	}

	if rejected, err := em.filter.AddIps(&compiler.AllowDenyPair{
		Allow: []string{"evil.bar.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("programming evil.bar.com: err = %v, rejected = %v", err, rejected)
	}
	reusedID := domainID(t, em.domainIDs, reusedKey, "evil.bar.com")
	if reusedID != retiredID {
		t.Errorf("evil.bar.com got id %d, want the retired %d back in circulation", reusedID, retiredID)
	}

	// The discriminating assertion: the reused id must not carry the previous
	// domain's addresses with it.
	if got, ok := attributedDomainID(t, em.ipDomain, staleAddr); ok {
		t.Errorf("ip_domain attributes %s to id %d, now evil.bar.com: an address nobody resolved is authorized as the new domain", staleAddr, got)
	}
}

// ipEventKey mirrors `struct ip_event_key` in _cprog/maps.h, which the filter
// spells privately. cilium/ebpf rejects a key whose size does not match the
// loaded map's, so a layout drift fails here rather than corrupting an entry.
type ipEventKey struct {
	Daddr    uint32
	Decision uint32
	DomainID uint32
}

// ip_events keys carry domain_id and only drain on the next read, so a counter
// recorded for a retired domain would otherwise be reported under whichever name
// received the id next: traffic attributed to a domain that never resolved it.
func TestBPFRetiredDomainObservationsDoNotSurfaceUnderTheReusedName(t *testing.T) {
	requireBPFCapableHost(t)

	em := loadFilterWithMaps(t)

	if rejected, err := em.filter.AddIps(&compiler.AllowDenyPair{
		Allow: []string{"keep.example.com", "api.foo.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("programming allowed domains: err = %v, rejected = %v", err, rejected)
	}
	keepID := domainID(t, em.domainIDs, domainWireKey(t, "keep", "example", "com"), "keep.example.com")
	retiredID := domainID(t, em.domainIDs, domainWireKey(t, "api", "foo", "com"), "api.foo.com")

	// What the program would have counted for each domain's resolved address.
	retiredAddr := netip.MustParseAddr("198.51.100.7")
	keptAddr := netip.MustParseAddr("198.51.100.8")
	seedIPEvent(t, em.ipEvents, retiredAddr, retiredID, 3)
	seedIPEvent(t, em.ipEvents, keptAddr, keepID, 5)

	if rejected, err := em.filter.DeleteIps(&compiler.AllowDenyPair{
		Allow: []string{"api.foo.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("removing api.foo.com: err = %v, rejected = %v", err, rejected)
	}
	if rejected, err := em.filter.AddIps(&compiler.AllowDenyPair{
		Allow: []string{"evil.bar.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("programming evil.bar.com: err = %v, rejected = %v", err, rejected)
	}
	reusedID := domainID(t, em.domainIDs, domainWireKey(t, "evil", "bar", "com"), "evil.bar.com")
	if reusedID != retiredID {
		t.Fatalf("evil.bar.com got id %d, not the retired %d: this test asserts nothing unless the id is reused", reusedID, retiredID)
	}

	events, err := em.filter.ReadIPEvents()
	if err != nil {
		t.Fatalf("reading ip_events: %v", err)
	}
	for key, count := range events {
		if key.Addr == retiredAddr {
			t.Errorf("ReadIPEvents reports %s as domain %q with count %d; api.foo.com's counter survived the retire",
				key.Addr, key.Domain, count)
		}
		if key.Domain == "evil.bar.com" {
			t.Errorf("ReadIPEvents attributes %s to evil.bar.com with count %d, which never resolved it",
				key.Addr, count)
		}
	}

	// The sweep is per id, not a flush: another domain's counters must survive.
	kept := egressfilter.IPEventKey{
		Addr:     keptAddr,
		Decision: runtimeevent.DecisionAllow,
		Domain:   "keep.example.com",
	}
	if got := events[kept]; got != 5 {
		t.Errorf("ReadIPEvents()[%v] = %d, want 5: retiring one domain discarded another's counters (full map: %v)",
			kept, got, events)
	}
}

func seedIPEvent(t *testing.T, m *ebpf.Map, addr netip.Addr, id uint32, count uint32) {
	t.Helper()
	key := ipEventKey{
		Daddr:    ipDomainKey(addr),
		Decision: uint32(runtimeevent.DecisionAllow),
		DomainID: id,
	}
	if err := m.Put(&key, &count); err != nil {
		t.Fatalf("seeding ip_events[%s, domain %d]: %v", addr, id, err)
	}
}

// A domain named by one policy's allow list and another's deny list holds a
// single id in both maps. Detaching one policy must not retire it: the id is
// still enforced on the other side, and reusing it would repoint that
// enforcement at an unrelated name.
func TestBPFDomainReferencedByBothSidesIsNotRetired(t *testing.T) {
	requireBPFCapableHost(t)

	em := loadFilterWithMaps(t)

	dualKey := domainWireKey(t, "dual", "example", "com")
	otherKey := domainWireKey(t, "other", "example", "com")

	if rejected, err := em.filter.AddIps(&compiler.AllowDenyPair{
		Allow: []string{"dual.example.com"},
		Deny:  []string{"dual.example.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("programming dual.example.com on both sides: err = %v, rejected = %v", err, rejected)
	}

	dualID := domainID(t, em.domainIDs, dualKey, "dual.example.com")
	if !hasDomainID(t, em.allowedDomains, dualID, "allowed_domains") ||
		!hasDomainID(t, em.bannedDomains, dualID, "banned_domains") {
		t.Fatalf("id %d is not present on both sides", dualID)
	}

	dualAddr := netip.MustParseAddr("198.51.100.9")
	dualAddrKey := ipDomainKey(dualAddr)
	if err := em.ipDomain.Put(&dualAddrKey, &dualID); err != nil {
		t.Fatalf("seeding ip_domain[%s] = %d: %v", dualAddr, dualID, err)
	}

	if rejected, err := em.filter.DeleteIps(&compiler.AllowDenyPair{
		Allow: []string{"dual.example.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("removing dual.example.com from the allow side: err = %v, rejected = %v", err, rejected)
	}

	if hasDomainID(t, em.allowedDomains, dualID, "allowed_domains") {
		t.Errorf("allowed_domains still holds id %d after the allow side was removed", dualID)
	}
	if !hasDomainID(t, em.bannedDomains, dualID, "banned_domains") {
		t.Errorf("banned_domains lost id %d, which no caller removed", dualID)
	}
	if got := domainID(t, em.domainIDs, dualKey, "dual.example.com"); got != dualID {
		t.Errorf("domain_ids gives dual.example.com id %d, want %d unchanged while banned_domains still references it", got, dualID)
	}
	if got, ok := attributedDomainID(t, em.ipDomain, dualAddr); !ok || got != dualID {
		t.Errorf("ip_domain[%s] = (%d, %v), want (%d, true): sweeping it would blind the still-enforced deny side", dualAddr, got, ok, dualID)
	}

	if rejected, err := em.filter.AddIps(&compiler.AllowDenyPair{
		Allow: []string{"other.example.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("programming other.example.com: err = %v, rejected = %v", err, rejected)
	}
	if got := domainID(t, em.domainIDs, otherKey, "other.example.com"); got == dualID {
		t.Errorf("other.example.com was handed id %d, still enforced as dual.example.com by banned_domains", got)
	}

	// Removing the last reference does retire it, so the both-sides check is a
	// gate rather than a leak.
	if rejected, err := em.filter.DeleteIps(&compiler.AllowDenyPair{
		Deny: []string{"dual.example.com"},
	}); err != nil || len(rejected) != 0 {
		t.Fatalf("removing dual.example.com from the deny side: err = %v, rejected = %v", err, rejected)
	}
	requireDomainAbsent(t, em.domainIDs, dualKey, "dual.example.com")
	if got, ok := attributedDomainID(t, em.ipDomain, dualAddr); ok {
		t.Errorf("ip_domain still attributes %s to id %d after the last reference was removed", dualAddr, got)
	}
}
