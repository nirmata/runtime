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

// reserveDomainID hands out the id for name, assigning the next one on first
// use. Ids are per-filter, because every pod loads its own map set, and start
// at 1: the kernel writes 0 into ip_event_key.domain_id to mean "no domain
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
	e.nextDomainID++
	e.domainIDs[name] = e.nextDomainID
	return e.nextDomainID, true
}

// internDomain publishes name in domain_ids and returns its id. An id is never
// retired: the snooper's ip_domain entries outlive a policy detaching, so
// handing the same id to a different name would attribute those addresses to
// the wrong domain.
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
		}
	}
	return errors.Join(errs...)
}
