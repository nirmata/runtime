package lsmmgr

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// progTypeOrder fixes the drain order of the program types of one attachment, so
// the emitted event slice is reproducible.
var progTypeOrder = []string{lsm.PROG_TYPE_LSM_OPEN, lsm.PROG_TYPE_LSM_EXEC}

// observationKey is the identity of one observed kernel operation: everything a
// count is attributed to, independent of which program counted it.
type observationKey struct {
	cgid     uint64
	progType string
	path     string
	decision runtimeevent.KernelDecision
}

// CollectObservations drains the per-cgroup path counters of every enforcer of
// every attachment and turns them into events. The counters live in a map per
// enforcer, so every program type has to be read: stopping at the first one
// discards what the others saw. The kernel maps are read-and-reset, so Count is
// the number of occurrences since the previous call.
func (l *LsmManager) CollectObservations(ctx context.Context) ([]runtimeevent.Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	var errs []error
	merged := map[observationKey]uint32{}
	podHints := map[uint64]string{}

	for rpUID, la := range l.lsmAttachments {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			return emitObservations(now, merged, podHints), errors.Join(errs...)
		}

		cgids, cgidPods := attachedCgids(la)
		if len(cgids) == 0 {
			continue
		}
		maps.Copy(podHints, cgidPods)

		for _, progType := range progTypeOrder {
			prog, ok := la.progs[progType]
			if !ok {
				continue
			}
			counts, err := prog.enf.ReadEvents(cgids)
			if err != nil {
				if errors.Is(err, lsm.ErrObservationUnavailable) {
					// the loaded program has no observation maps, so every later
					// poll reports the same thing: report it on the policy rather
					// than to the caller
					l.observationUnavailable(rpUID, progType, "observation is unavailable", err)
				} else {
					errs = append(errs, err)
				}
				// counts may still hold what was read before the failure
			}
			if err := l.reportLost(rpUID, progType, prog.enf); err != nil {
				errs = append(errs, err)
			}
			for cgid, paths := range counts {
				for key, count := range paths {
					if key.Path == "" || count == 0 {
						continue
					}
					k := observationKey{cgid: cgid, progType: progType, path: key.Path, decision: key.Decision}
					// every program attached for this cgid saw the same kernel
					// operations, so their counts are P views of one number, not P
					// numbers to add up. max, rather than any single one of them,
					// because a program that attached part-way through the window
					// legitimately saw fewer.
					if count > merged[k] {
						merged[k] = count
					}
				}
			}
		}
	}

	return emitObservations(now, merged, podHints), errors.Join(errs...)
}

// reportLost drains one enforcer's kernel drop counter. A program loaded
// without observation maps reports it on the policy rather than to the caller,
// the same way an unavailable ReadEvents does.
func (l *LsmManager) reportLost(rpUID, progType string, enf lsmEnforcer) error {
	lost, err := enf.ReadEventsLost()
	if err != nil {
		if errors.Is(err, lsm.ErrObservationUnavailable) {
			l.observationUnavailable(rpUID, progType, "observation is unavailable", err)
			return nil
		}
		return err
	}
	if lost == 0 {
		return nil
	}
	l.logger.Info("kernel dropped observations", "uid", rpUID, "progType", progType, "count", lost)
	if l.onLoss != nil {
		l.onLoss(runtimeevent.ReasonCountMapFull, lost)
	}
	return nil
}

func emitObservations(now time.Time, merged map[observationKey]uint32, podHints map[uint64]string) []runtimeevent.Event {
	out := make([]runtimeevent.Event, 0, len(merged))
	for k, count := range merged {
		key := lsm.PathEventKey{Path: k.path, Decision: k.decision}
		out = append(out, newObservation(k.progType, now, k.cgid, podHints[k.cgid], key, count))
	}
	return sortEvents(out)
}

// newObservation builds the event for one observed (path, decision) count.
// Attribution resolves the cgroup id; the pod uid is a hint the manager already
// knows. Monitor attributes the kernel's decision to a policy in userspace.
func newObservation(progType string, now time.Time, cgid uint64, podUID string, key lsm.PathEventKey, count uint32) runtimeevent.Event {
	ev := runtimeevent.Event{
		Time:         now,
		CgroupID:     cgid,
		Count:        count,
		KernelDenied: key.Decision == runtimeevent.DecisionDeny,
		Pod:          runtimeevent.PodIdentity{UID: podUID},
	}
	switch progType {
	case lsm.PROG_TYPE_LSM_EXEC:
		ev.Kind = runtimeevent.KindExec
		ev.Exec = &runtimeevent.ExecFacts{Filename: key.Path}
	default:
		ev.Kind = runtimeevent.KindOpen
		ev.Open = &runtimeevent.OpenFacts{Path: key.Path}
	}
	return ev
}

// attachedCgids returns the cgroup ids of every pod attached to la, plus the
// cgid to pod uid mapping that pre-fills the event's pod hint.
func attachedCgids(la *lsmAttachment) ([]uint64, map[uint64]string) {
	cgids := make([]uint64, 0, len(la.attachedPods))
	cgidPods := make(map[uint64]string, len(la.attachedPods))
	for podUID, pod := range la.attachedPods {
		for _, cgid := range pod.cgids {
			if _, seen := cgidPods[cgid]; seen {
				continue
			}
			cgidPods[cgid] = podUID
			cgids = append(cgids, cgid)
		}
	}
	slices.Sort(cgids)
	return cgids, cgidPods
}

// sortEvents makes the emitted slice deterministic despite the map iteration
// above.
func sortEvents(evs []runtimeevent.Event) []runtimeevent.Event {
	slices.SortStableFunc(evs, func(a, b runtimeevent.Event) int {
		if c := cmp.Compare(a.CgroupID, b.CgroupID); c != 0 {
			return c
		}
		if c := cmp.Compare(string(a.Kind), string(b.Kind)); c != 0 {
			return c
		}
		if c := cmp.Compare(eventPath(a), eventPath(b)); c != 0 {
			return c
		}
		// the same path appears once per decision
		return cmp.Compare(boolToInt(a.KernelDenied), boolToInt(b.KernelDenied))
	})
	return evs
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func eventPath(ev runtimeevent.Event) string {
	switch {
	case ev.Open != nil:
		return ev.Open.Path
	case ev.Exec != nil:
		return ev.Exec.Filename
	default:
		return ""
	}
}
