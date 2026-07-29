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

// IPEventKey identifies one observation counter: a destination address plus
// the enforcement decision the kernel program applied to the flow.
type IPEventKey struct {
	Addr     netip.Addr
	Decision runtimeevent.KernelDecision
}

// ipEventKernelKey mirrors `struct ip_event_key` in _cprog/maps.h. cilium/ebpf
// rejects a key whose Go layout does not match the loaded map's BTF key.
type ipEventKernelKey struct {
	Daddr    uint32
	Decision uint32
}

// ReadIPEvents reads and resets the ip_events counter map, so each poll reports
// a delta rather than a running total. Entries whose counter is zero are
// omitted.
func (e *EgressFilter) ReadIPEvents() (map[IPEventKey]uint32, error) {
	if e.bpfObjs == nil || e.bpfObjs.IpEvents == nil {
		return nil, ErrNotLoaded
	}
	return readAndResetIPEvents(e.bpfObjs.IpEvents)
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

func readAndResetIPEvents(m *ebpf.Map) (map[IPEventKey]uint32, error) {
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
		out[eventKey(key)] += count
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

func eventKey(k ipEventKernelKey) IPEventKey {
	return IPEventKey{
		Addr:     keyAddr(k.Daddr),
		Decision: runtimeevent.KernelDecision(k.Decision),
	}
}
