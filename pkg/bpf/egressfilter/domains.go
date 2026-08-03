package egressfilter

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// Mirrors MAX_DOMAIN_LEN and the max_entries of domain_ids, allowed_domains
// and banned_domains in _cprog/maps.h.
const (
	maxDomainKeyLen = 128
	maxDomains      = 256

	maxLabelLen = 63
)

var (
	errDomainMalformed  = errors.New("not a DNS name")
	errDomainKeyTooLong = errors.New("wire-encoded DNS name does not fit the domain key")
	errDomainTableFull  = errors.New("domain table is full")
)

// domainKey mirrors `struct domain_key`.
type domainKey struct {
	Name [maxDomainKeyLen]byte
}

// encodeDomainKey renders name in DNS wire form — every label prefixed by its
// length, terminated by a zero byte, ASCII-lowercased — zero padded to the key
// width. The snooper builds the identical bytes from the QNAME it reads off the
// packet, so a divergence here matches nothing and reports nothing.
func encodeDomainKey(name string) (domainKey, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return domainKey{}, errDomainMalformed
	}

	var key domainKey

	n := 0
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > maxLabelLen {
			return domainKey{}, errDomainMalformed
		}
		// +1 for the length prefix, +1 for the terminating zero byte
		if n+1+len(label)+1 > maxDomainKeyLen {
			return domainKey{}, errDomainKeyTooLong
		}
		key.Name[n] = byte(len(label))
		n++
		for i := 0; i < len(label); i++ {
			key.Name[n] = asciiLower(label[i])
			n++
		}
	}
	return key, nil
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// reserveDomainID hands out the id for name, preferring one retired by
// retireDomain. Ids are per-filter, because every pod loads its own map set, and
// start at 1: the kernel writes 0 into ip_event_key.domain_id to mean "no domain
// known". ok is false once the table is full.
func (e *EgressFilter) reserveDomainID(name string) (uint32, bool) {
	if id, ok := e.domainIDs[name]; ok {
		return id, true
	}
	if len(e.domainIDs) >= maxDomains {
		return 0, false
	}
	if e.domainIDs == nil {
		e.domainIDs = make(map[string]uint32, 1)
	}

	if n := len(e.freeDomainIDs); n > 0 {
		id := e.freeDomainIDs[n-1]
		e.freeDomainIDs = e.freeDomainIDs[:n-1]
		e.domainIDs[name] = id
		return id, true
	}

	e.nextDomainID++
	e.domainIDs[name] = e.nextDomainID
	return e.nextDomainID, true
}

// internDomain publishes name in domain_ids and returns its id.
func (e *EgressFilter) internDomain(name string) (uint32, error) {
	if id, ok := e.domainIDs[name]; ok {
		return id, nil
	}
	key, err := encodeDomainKey(name)
	if err != nil {
		return 0, fmt.Errorf("interning %q: %w", name, err)
	}
	id, ok := e.reserveDomainID(name)
	if !ok {
		return 0, errDomainTableFull
	}
	if err := e.putDomainID(key, id); err != nil {
		delete(e.domainIDs, name)
		return 0, err
	}
	return id, nil
}

func (e *EgressFilter) putDomainID(key domainKey, id uint32) error {
	if e.bpfObjs == nil || e.bpfObjs.DomainIds == nil {
		return fmt.Errorf("domain_ids: %w", ErrNotLoaded)
	}
	if err := e.bpfObjs.DomainIds.Put(&key, &id); err != nil {
		return fmt.Errorf("writing domain_ids: %w", err)
	}
	return nil
}

func (e *EgressFilter) domainMaps() (allowed, banned *ebpf.Map) {
	if e.bpfObjs == nil {
		return nil, nil
	}
	return e.bpfObjs.AllowedDomains, e.bpfObjs.BannedDomains
}

func (e *EgressFilter) putDomains(m *ebpf.Map, name string, hosts []string) ([]RejectedTarget, error) {
	var (
		rejected []RejectedTarget
		errs     []error
	)
	for _, host := range hosts {
		id, err := e.internDomain(host)
		switch {
		case errors.Is(err, errDomainTableFull):
			rejected = append(rejected, RejectedTarget{Value: host, Reason: ReasonTooManyDomains})
			continue
		case err != nil:
			errs = append(errs, err)
			continue
		}
		if m == nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, ErrNotLoaded))
			continue
		}
		if err := m.Put(&id, uint8(0)); err != nil {
			errs = append(errs, fmt.Errorf("writing %s: %w", name, err))
		}
	}
	return rejected, errors.Join(errs...)
}

func (e *EgressFilter) deleteDomains(m *ebpf.Map, name string, hosts []string) error {
	if len(hosts) == 0 {
		return nil
	}

	var errs []error
	for _, host := range hosts {
		id, ok := e.domainIDs[host]
		if !ok {
			continue
		}
		if m == nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, ErrNotLoaded))
			continue
		}
		if err := m.Delete(&id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("deleting from %s: %w", name, err))
			continue
		}
		if err := e.retireDomain(host, id); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// retireDomain unpublishes a domain whose id no longer appears on either side,
// freeing the id for reuse. Without this a filter can only ever intern
// maxDomains names over the pod's whole life, however few are live at once.
//
// The order is what makes reuse safe. domain_ids goes first: the snooper mints
// an id only by matching a QNAME there, so removing the name stops new ip_domain
// entries from appearing before the sweep clears the ones already recorded.
// Reusing an id while any of those survived would authorize and attribute a
// stale address as the new domain.
func (e *EgressFilter) retireDomain(host string, id uint32) error {
	allowed, banned := e.domainMaps()
	if domainMapHasID(allowed, id) || domainMapHasID(banned, id) {
		return nil
	}

	key, err := encodeDomainKey(host)
	if err != nil {
		return fmt.Errorf("retiring %q: %w", host, err)
	}
	if e.bpfObjs == nil || e.bpfObjs.DomainIds == nil {
		return fmt.Errorf("domain_ids: %w", ErrNotLoaded)
	}
	if err := e.bpfObjs.DomainIds.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("deleting from domain_ids: %w", err)
	}
	// The kernel entry is gone, so the cached id goes with it: internDomain
	// returns a cached id without republishing the name, which would leave the
	// domain unenforceable for the rest of the pod's life.
	delete(e.domainIDs, host)

	if err := errors.Join(e.sweepIPDomain(id), e.sweepIPEvents(id)); err != nil {
		// the id stays out of circulation, since an entry that still carries it
		// would be attributed to whichever name received it next
		return err
	}
	e.freeDomainIDs = append(e.freeDomainIDs, id)
	return nil
}

func domainMapHasID(m *ebpf.Map, id uint32) bool {
	if m == nil {
		return false
	}
	var val uint8
	return m.Lookup(&id, &val) == nil
}

// sweepIPDomain drops every address the snooper attributed to id. Keys are
// collected before deleting: mutating a hash map mid-iteration is not something
// the iterator promises to survive.
func (e *EgressFilter) sweepIPDomain(id uint32) error {
	if e.bpfObjs == nil || e.bpfObjs.IpDomain == nil {
		return fmt.Errorf("ip_domain: %w", ErrNotLoaded)
	}
	m := e.bpfObjs.IpDomain

	var (
		daddr, got uint32
		stale      []uint32
	)
	it := m.Iterate()
	for it.Next(&daddr, &got) {
		if got == id {
			stale = append(stale, daddr)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("scanning ip_domain: %w", err)
	}

	var errs []error
	for _, d := range stale {
		if err := m.Delete(&d); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("deleting from ip_domain: %w", err))
		}
	}
	return errors.Join(errs...)
}

// sweepIPEvents drops observation counters attributed to id. They carry
// domain_id in the key and only drain on the next read, so leaving them behind
// reports a retired domain's traffic under whichever name receives the id next.
// The counters discarded here are at most one poll interval of a domain no
// policy references any more, which is a better loss than a wrong name.
func (e *EgressFilter) sweepIPEvents(id uint32) error {
	if e.bpfObjs == nil || e.bpfObjs.IpEvents == nil {
		return fmt.Errorf("ip_events: %w", ErrNotLoaded)
	}
	m := e.bpfObjs.IpEvents

	var (
		key   ipEventKernelKey
		count uint32
		stale []ipEventKernelKey
	)
	it := m.Iterate()
	for it.Next(&key, &count) {
		if key.DomainId == id {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("scanning ip_events: %w", err)
	}

	var errs []error
	for _, k := range stale {
		if err := m.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("deleting from ip_events: %w", err))
		}
	}
	if len(stale) > 0 && e.logger != nil {
		e.logger.V(2).Info("discarded egress observations for a retired domain",
			"domainId", id, "counters", len(stale))
	}
	return errors.Join(errs...)
}
