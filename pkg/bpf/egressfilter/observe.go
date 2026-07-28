package egressfilter

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// SetObserve turns the OBSERVE (LEARNING_MODE) flag bit on or off. It is a thin
// alias for SetFlagIdx kept for readability at the manager call sites.
func (e *EgressFilter) SetObserve(enabled bool) {
	e.SetFlagIdx(OBSERVE, enabled)
}

// ReadIPEvents reads and RESETS the ip_events counter map: it returns the
// destination addresses the program saw since the last read, with the number of
// packets counted for each, and removes the entries so the next poll reports a
// delta rather than a running total.
//
// Entries whose counter is zero are omitted. A read error for one key does not
// abort the sweep: every key is visited and the errors are joined, so a single
// bad entry cannot hide the rest of the observations.
func (e *EgressFilter) ReadIPEvents() (map[netip.Addr]uint32, error) {
	if e.bpfObjs == nil || e.bpfObjs.IpEvents == nil {
		return nil, ErrNotLoaded
	}
	return readAndResetIPEvents(e.bpfObjs.IpEvents)
}

// readAndResetIPEvents is split out so the (kernel-only) map plumbing has a
// single implementation and a narrow signature.
func readAndResetIPEvents(m *ebpf.Map) (map[netip.Addr]uint32, error) {
	out := make(map[netip.Addr]uint32)
	keys := make([]uint32, 0, 16)

	var (
		key   uint32
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
		addr := keyAddr(key)
		out[addr] += count
	}
	var errs []error
	if err := it.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterating ip_events: %w", err))
	}

	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("resetting ip_events entry %s: %w", keyAddr(keys[i]), err))
		}
	}

	return out, errors.Join(errs...)
}
