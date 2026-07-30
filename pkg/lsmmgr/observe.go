package lsmmgr

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// progTypeOrder fixes the drain order of the program types of one attachment, so
// the emitted event slice is reproducible.
var progTypeOrder = []string{lsm.PROG_TYPE_LSM_OPEN, lsm.PROG_TYPE_LSM_EXEC}

// CollectObservations drains the per-cgroup path counters of every enforcer of
// every attachment and turns them into events. The counters live in a map per
// enforcer, so every program type has to be read: stopping at the first one
// discards what the others saw. The kernel maps are read-and-reset, so Count is
// the number of occurrences since the previous call.
func (l *LsmManager) CollectObservations(ctx context.Context) ([]runtimeevent.Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	var (
		out  []runtimeevent.Event
		errs []error
	)

	for rpUID, la := range l.lsmAttachments {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			return sortEvents(out), errors.Join(errs...)
		}

		cgids, cgidPods := attachedCgids(la)
		if len(cgids) == 0 {
			continue
		}

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
			for cgid, paths := range counts {
				for key, count := range paths {
					if key.Path == "" || count == 0 {
						continue
					}
					out = append(out, newObservation(progType, now, cgid, cgidPods[cgid], key, count))
				}
			}
		}
	}

	return sortEvents(out), errors.Join(errs...)
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
