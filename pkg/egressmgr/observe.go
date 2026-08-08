package egressmgr

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/protofilter"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// CollectObservations drains the IPv4 and protocol observation counters of
// every pod with an attached policy and turns them into one event per
// (destination, decision) and (protocol, decision).
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
		if err := e.reportLost(podUid, pa.filter); err != nil {
			errs = append(errs, err)
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
				Net:          &runtimeevent.NetFacts{DestIP: key.Addr, Domain: key.Domain},
				Pod:          runtimeevent.PodIdentity{UID: podUid, Labels: pa.labels},
			})
		}

		protoCounts, err := pa.protoFilter.ReadProtoEvents()
		if err != nil {
			errs = append(errs, fmt.Errorf("reading protocol observations for pod %s: %w", podUid, err))
		}
		for _, key := range sortedProtoEventKeys(protoCounts) {
			count := protoCounts[key]
			if count == 0 {
				continue
			}
			out = append(out, runtimeevent.Event{
				Kind:         runtimeevent.KindProtocol,
				Time:         now,
				Count:        count,
				KernelDenied: key.Decision == runtimeevent.DecisionDeny,
				Protocol:     &runtimeevent.ProtocolFacts{Protocol: key.Protocol, ALPN: key.ALPN},
				Pod:          runtimeevent.PodIdentity{UID: podUid, Labels: pa.labels},
			})
		}
	}

	return out, errors.Join(errs...)
}

// reportLost drains one pod's kernel drop counter. A filter whose objects are
// not loaded has nothing to report and will not acquire any later, so it is not
// worth failing the poll over.
func (e *EgressManager) reportLost(podUid string, filter egressFilter) error {
	lost, err := filter.ReadEventsLost()
	if err != nil {
		if errors.Is(err, egressfilter.ErrNotLoaded) {
			return nil
		}
		return fmt.Errorf("reading lost egress observations for pod %s: %w", podUid, err)
	}
	if lost == 0 {
		return nil
	}
	e.logger.Info("kernel dropped egress observations", "podUid", podUid, "count", lost)
	if e.onLoss != nil {
		e.onLoss(runtimeevent.ReasonCountMapFull, lost)
	}
	return nil
}

// sortedIPEventKeys orders keys by address, then decision (allow before deny),
// then domain, so the emitted event slice is deterministic. Every field of the
// key is compared: one address can be reached under two domains, and leaving
// either out would order those entries arbitrarily.
func sortedIPEventKeys(counts map[egressfilter.IPEventKey]uint32) []egressfilter.IPEventKey {
	keys := make([]egressfilter.IPEventKey, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if c := keys[i].Addr.Compare(keys[j].Addr); c != 0 {
			return c < 0
		}
		if keys[i].Decision != keys[j].Decision {
			return keys[i].Decision < keys[j].Decision
		}
		return keys[i].Domain < keys[j].Domain
	})
	return keys
}

// sortedProtoEventKeys orders keys by protocol token, then ALPN, then decision
// (allow before deny), so the emitted event slice is deterministic.
func sortedProtoEventKeys(counts map[protofilter.ProtoEventKey]uint32) []protofilter.ProtoEventKey {
	keys := make([]protofilter.ProtoEventKey, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Protocol != keys[j].Protocol {
			return keys[i].Protocol < keys[j].Protocol
		}
		if keys[i].ALPN != keys[j].ALPN {
			return keys[i].ALPN < keys[j].ALPN
		}
		return keys[i].Decision < keys[j].Decision
	})
	return keys
}
