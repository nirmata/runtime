package egressfilter

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf"
)

// SetObserve turns the OBSERVE (LEARNING_MODE) flag bit on or off. It is a thin
// alias for SetFlagIdx kept for readability at the manager call sites.
func (e *EgressFilter) SetObserve(enabled bool) {
	e.SetFlagIdx(OBSERVE, enabled)
}

// IPEventKey identifies one observation counter: a destination address plus
// the enforcement verdict the kernel program applied to the flow.
type IPEventKey struct {
	Addr    netip.Addr
	Verdict runtimeevent.KernelVerdict
}

// ipEventKernelKey is the kernel layout of `struct ip_event_key` in
// _cprog/maps.h: two naturally-aligned __u32 words, 8 bytes, no padding. It is
// kept separate from the exported IPEventKey so the iterator key's size and
// layout match the loaded map's BTF key exactly (cilium/ebpf rejects a
// mismatch).
type ipEventKernelKey struct {
	Daddr   uint32
	Verdict uint32
}

// ReadIPEvents reads and RESETS the ip_events counter map: it returns the
// (destination, verdict) pairs the program saw since the last read, with the
// number of packets counted for each, and removes the entries so the next poll
// reports a delta rather than a running total.
//
// Entries whose counter is zero are omitted. A read error for one key does not
// abort the sweep: every key is visited and the errors are joined, so a single
// bad entry cannot hide the rest of the observations.
func (e *EgressFilter) ReadIPEvents() (map[IPEventKey]uint32, error) {
	if e.bpfObjs == nil || e.bpfObjs.IpEvents == nil {
		return nil, ErrNotLoaded
	}
	return readAndResetIPEvents(e.bpfObjs.IpEvents)
}

// SeedIPEvent writes one observation entry directly through the ip_events map
// handle. It exists for the kernel smoke test (test/e2e): a Put through the
// handle is rejected by cilium/ebpf unless the Go key layout matches the
// loaded map's BTF key size, which is exactly the marshaling seam the test
// pins. Production counting happens in the BPF program, never here.
func (e *EgressFilter) SeedIPEvent(addr netip.Addr, verdict runtimeevent.KernelVerdict, count uint32) error {
	if e.bpfObjs == nil || e.bpfObjs.IpEvents == nil {
		return ErrNotLoaded
	}
	daddr, ok := addrKey(addr)
	if !ok {
		return fmt.Errorf("seeding ip_events: %s is not an IPv4 address", addr)
	}
	key := ipEventKernelKey{Daddr: daddr, Verdict: uint32(verdict)}
	return e.bpfObjs.IpEvents.Put(&key, &count)
}

// readAndResetIPEvents is split out so the (kernel-only) map plumbing has a
// single implementation and a narrow signature.
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

// eventKey converts the kernel-layout key into the exported form.
func eventKey(k ipEventKernelKey) IPEventKey {
	return IPEventKey{
		Addr:    keyAddr(k.Daddr),
		Verdict: runtimeevent.KernelVerdict(k.Verdict),
	}
}
