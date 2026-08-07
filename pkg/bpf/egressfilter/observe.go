package egressfilter

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf"
)

// SetObserve turns the OBSERVE (LEARNING_MODE) flag bit on or off.
func (e *EgressFilter) SetObserve(enabled bool) {
	e.SetFlagIdx(OBSERVE, enabled)
}

// IPEventKey identifies one observation counter: a destination address, the
// enforcement decision the kernel program applied to the flow, and the domain
// the address was attributed to.
type IPEventKey struct {
	Addr     netip.Addr
	Decision runtimeevent.KernelDecision
	// Domain is already resolved: the kernel's numeric id is filter-local, so
	// it never leaves this package. Empty when no domain was attributed.
	Domain string
}

// ipEventKernelKey mirrors `struct ip_event_key` in _cprog/maps.h. cilium/ebpf
// rejects a key whose Go layout does not match the loaded map's BTF key.
type ipEventKernelKey struct {
	Daddr    uint32
	Decision uint32
	DomainId uint32
}

// ReadIPEvents reads and resets the ip_events counter map, so each poll reports
// a delta rather than a running total. Entries whose counter is zero are
// omitted.
func (e *EgressFilter) ReadIPEvents() (map[IPEventKey]uint32, error) {
	if e.bpfObjs == nil || e.bpfObjs.IpEvents == nil {
		return nil, ErrNotLoaded
	}
	return readAndResetIPEvents(e.bpfObjs.IpEvents, e.domainNamer())
}

// SeedIPEvent writes one observation entry through the ip_events map handle. It
// exists for the kernel smoke test in test/e2e, which pins the key marshaling
// seam; production counting happens in the BPF program.
func (e *EgressFilter) SeedIPEvent(addr netip.Addr, decision runtimeevent.KernelDecision, count uint32) error {
	if e.bpfObjs == nil || e.bpfObjs.IpEvents == nil {
		return ErrNotLoaded
	}
	daddr, ok := addrKey(addr)
	if !ok {
		return fmt.Errorf("seeding ip_events: %s is not an IPv4 address", addr)
	}
	key := ipEventKernelKey{Daddr: daddr, Decision: uint32(decision)}
	return e.bpfObjs.IpEvents.Put(&key, &count)
}

// domainNamer returns the id-to-name lookup used for one read. Interning is the
// only allocator of these ids, and retiring one sweeps the counters carrying it,
// so a name missing from the inverted table means the counter outlived its
// domain rather than that the table is behind.
func (e *EgressFilter) domainNamer() func(uint32) string {
	names := make(map[uint32]string, len(e.domainIDs))
	for name, id := range e.domainIDs {
		names[id] = name
	}
	return func(id uint32) string {
		if id == 0 {
			return ""
		}
		name, ok := names[id]
		if ok {
			return name
		}
		// An id the intern table cannot name is an attribution gap, not a
		// reason to lose the observation: it stays, reported by address.
		if e.logger != nil {
			e.logger.Info("egress observation names an unknown domain id; reporting it by address",
				"domainId", id)
		}
		return ""
	}
}

func readAndResetIPEvents(m *ebpf.Map, domainOf func(uint32) string) (map[IPEventKey]uint32, error) {
	out := make(map[IPEventKey]uint32)
	keys := make([]ipEventKernelKey, 0, 16)

	var (
		key   ipEventKernelKey
		count uint32
	)
	// Collect first, delete after: deleting during iteration can make the
	// kernel restart the walk and yield duplicates.
	it := m.Iterate()
	for it.Next(&key, &count) {
		keys = append(keys, key)
		if count == 0 {
			continue
		}
		out[eventKey(key, domainOf)] += count
	}
	var errs []error
	if err := it.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterating ip_events: %w", err))
	}

	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("resetting ip_events entry %s: %w", keyAddr(keys[i].Daddr), err))
		}
	}

	return out, errors.Join(errs...)
}

func eventKey(k ipEventKernelKey, domainOf func(uint32) string) IPEventKey {
	return IPEventKey{
		Addr:     keyAddr(k.Daddr),
		Decision: runtimeevent.KernelDecision(k.Decision),
		Domain:   domainOf(k.DomainId),
	}
}
