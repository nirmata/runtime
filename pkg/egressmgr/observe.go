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

// CollectObservations drains the per-pod egress observation counters and turns
// them into normalized events, one per (destination, verdict): the kernel
// counters carry the program's enforcement verdict, so a flow dropped by a
// default-deny is emitted with KernelDenied set rather than lost.
//
// Only pods with at least one observe-mode policy attached are polled: the
// OBSERVE flag is refcounted, so a pod with an empty observe set is not
// counting. Reads are destructive (the map is reset), hence Count is the delta
// since the previous call.
//
// Honest limits (DESIGN 0.2): the counters are IPv4-only. A read failure for
// one pod does not abort the sweep: every pod is visited and the errors are
// joined.
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
		for _, key := range sortedIPEventKeys(counts) {
			count := counts[key]
			if count == 0 {
				continue
			}
			out = append(out, runtimeevent.Event{
				Kind:  runtimeevent.KindNet,
				Time:  now,
				Count: count,
				// the kernel's actual verdict for these occurrences; monitor
				// attributes it to a policy in userspace
				KernelDenied: key.Verdict == runtimeevent.VerdictDeny,
				Net:          &runtimeevent.NetFacts{DestIP: key.Addr},
				// the poll source knows the pod but not the cgroup: pre-fill
				// the identity hint so attribution can skip the pid lookup
				Pod: runtimeevent.PodIdentity{UID: podUid, Labels: pa.labels},
			})
		}
	}

	return out, errors.Join(errs...)
}

// sortedIPEventKeys orders keys by address, with the verdict as a tiebreaker
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
		return keys[i].Verdict < keys[j].Verdict
	})
	return keys
}
