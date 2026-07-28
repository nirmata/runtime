package egressmgr

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// CollectObservations drains the per-pod egress observation counters and turns
// them into normalized events.
//
// Only pods with at least one observe-mode policy attached are polled: the
// OBSERVE flag is refcounted, so a pod with an empty observe set is not
// counting. Reads are destructive (the map is reset), hence Count is the delta
// since the previous call.
//
// Honest limits (DESIGN 0.2): the BPF program returns before the observe branch
// while DEFAULT_DENY is set, so flows dropped by a default-deny are not
// observed, and the counters are IPv4-only. A read failure for one pod does not
// abort the sweep: every pod is visited and the errors are joined.
func (e *EgressManager) CollectObservations(ctx context.Context) ([]runtimeevent.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.clock()
	podUids := make([]string, 0, len(e.pods))
	for uid, pa := range e.pods {
		if len(pa.observe) == 0 {
			continue
		}
		podUids = append(podUids, uid)
	}
	// deterministic order: the sink and the tests both benefit, and nothing
	// downstream should depend on Go's map iteration order
	slices.Sort(podUids)

	var (
		out  []runtimeevent.Event
		errs []error
	)
	for _, podUid := range podUids {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		pa := e.pods[podUid]
		counts, err := pa.filter.ReadIPEvents()
		if err != nil {
			errs = append(errs, fmt.Errorf("reading egress observations for pod %s: %w", podUid, err))
			// a partial map read still carries real observations, keep going
		}
		for _, addr := range sortedAddrs(counts) {
			count := counts[addr]
			if count == 0 {
				continue
			}
			out = append(out, runtimeevent.Event{
				Kind:  runtimeevent.KindNet,
				Time:  now,
				Count: count,
				Net:   &runtimeevent.NetFacts{DestIP: addr},
				// the poll source knows the pod but not the cgroup: pre-fill
				// the identity hint so attribution can skip the pid lookup
				Pod: runtimeevent.PodIdentity{UID: podUid, Labels: pa.labels},
			})
		}
	}

	return out, errors.Join(errs...)
}

func sortedAddrs(counts map[netip.Addr]uint32) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(counts))
	for addr := range counts {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
	return addrs
}
