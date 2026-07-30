package egressmgr

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// CollectObservations drains the IPv4 observation counters of every pod with an
// attached policy and turns them into one event per (destination, decision).
// Reads are destructive, so Count is the delta since the previous call.
func (e *EgressManager) CollectObservations(ctx context.Context) ([]runtimeevent.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.clock()
	podUids := make([]string, 0, len(e.pods))
	for uid, pa := range e.pods {
		if len(pa.attachedFilters) == 0 {
			continue
		}
		podUids = append(podUids, uid)
	}
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
		for _, key := range sortedIPEventKeys(counts) {
			count := counts[key]
			if count == 0 {
				continue
			}
			out = append(out, runtimeevent.Event{
				Kind:         runtimeevent.KindNet,
				Time:         now,
				Count:        count,
				KernelDenied: key.Decision == runtimeevent.DecisionDeny,
				Net:          &runtimeevent.NetFacts{DestIP: key.Addr},
				Pod:          runtimeevent.PodIdentity{UID: podUid, Labels: pa.labels},
			})
		}
	}

	return out, errors.Join(errs...)
}

// sortedIPEventKeys orders keys by address, with the decision as a tiebreaker
// (allow before deny), so the emitted event slice is deterministic.
func sortedIPEventKeys(counts map[egressfilter.IPEventKey]uint32) []egressfilter.IPEventKey {
	keys := make([]egressfilter.IPEventKey, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if c := keys[i].Addr.Compare(keys[j].Addr); c != 0 {
			return c < 0
		}
		return keys[i].Decision < keys[j].Decision
	})
	return keys
}
