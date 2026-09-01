package openexecmgr

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/nirmata/runtime/pkg/bpf/openexec"
	"github.com/nirmata/runtime/pkg/runtimeevent"
)

// observationKey is the identity of one observed kernel operation: everything a
// count is attributed to, independent of which program counted it.
type observationKey struct {
	cgid     uint64
	progType string
	path     string
	decision runtimeevent.KernelDecision
}

// CollectObservations drains the per-cgroup path counters of every enforcer from open/exec.
// Reading drains events, and hence reported counts represent events since the last drain.
func (l *OpenExecManager) CollectObservations(ctx context.Context) ([]runtimeevent.Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	var errs []error
	merged := map[observationKey]uint32{}
	podHints := map[uint64]string{}

	for progType, prog := range l.programs {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			return emitObservations(now, merged, podHints), errors.Join(errs...)
		}

		counts, err := prog.ReadEvents()
		if err != nil {
			if errors.Is(err, openexec.ErrObservationUnavailable) {
				// the loaded program has no observation maps, so every later poll
				// reports the same thing
				l.logger.V(2).Info("observation is unavailable", "progType", progType)
			} else {
				errs = append(errs, err)
			}
			// counts may still hold what was read before the failure
		}

		for cgid, paths := range counts {
			for key, count := range paths {
				path := key.PathString()
				if path == "" || count == 0 {
					continue
				}
				// the kernel merges every policy's decision before recording, so a
				// count is already cgid-and-path-wide; the program type is the one
				// dimension only this loop knows
				k := observationKey{cgid: cgid, progType: progType, path: path,
					decision: runtimeevent.KernelDecision(key.Decision)}
				merged[k] = count
			}
		}

		if err := l.reportLost(progType, prog); err != nil {
			errs = append(errs, err)
		}
	}

	// build the hints map so that every cgid in the observations can be mapped back to a pod
	for _, la := range l.openExecAttachments {
		cgids, cgidPods := attachedCgids(la)
		if len(cgids) == 0 {
			continue
		}
		maps.Copy(podHints, cgidPods)
	}

	return emitObservations(now, merged, podHints), errors.Join(errs...)
}

// reportLost drains one program's kernel drop counter. A program loaded
// without observation maps is logged rather than reported to the caller, the
// same way an unavailable ReadEvents is.
func (l *OpenExecManager) reportLost(progType string, prog monitoringIface) error {
	lost, err := prog.ReadEventsLost()
	if err != nil {
		if errors.Is(err, openexec.ErrObservationUnavailable) {
			l.logger.V(2).Info("observation is unavailable", "progType", progType)
			return nil
		}
		return err
	}
	if lost == 0 {
		return nil
	}
	l.logger.Info("kernel dropped observations", "progType", progType, "count", lost)
	if l.onLoss != nil {
		l.onLoss(runtimeevent.ReasonCountMapFull, lost)
	}
	return nil
}

func emitObservations(now time.Time, merged map[observationKey]uint32, podHints map[uint64]string) []runtimeevent.Event {
	out := make([]runtimeevent.Event, 0, len(merged))
	for k, count := range merged {
		out = append(out, newObservation(now, k, podHints[k.cgid], count))
	}
	return sortEvents(out)
}

// newObservation builds the event for one observed (path, decision) count.
// Attribution resolves the cgroup id; the pod uid is a hint the manager already
// knows. Monitor attributes the kernel's decision to a policy in userspace.
func newObservation(now time.Time, k observationKey, podUID string, count uint32) runtimeevent.Event {
	ev := runtimeevent.Event{
		Time:         now,
		CgroupID:     k.cgid,
		Count:        count,
		KernelDenied: k.decision == runtimeevent.DecisionDeny,
		Pod:          runtimeevent.PodIdentity{UID: podUID},
	}
	switch k.progType {
	case openexec.PROG_TYPE_LSM_EXEC, openexec.PROG_TYPE_TRACE_EXEC:
		ev.Kind = runtimeevent.KindExec
		ev.Exec = &runtimeevent.ExecFacts{Filename: k.path}
	default:
		ev.Kind = runtimeevent.KindOpen
		ev.Open = &runtimeevent.OpenFacts{Path: k.path}
	}
	return ev
}

// attachedCgids returns the cgroup ids of every pod attached to la, plus the
// cgid to pod uid mapping that pre-fills the event's pod hint.
func attachedCgids(la *openExecAttachment) ([]uint64, map[uint64]string) {
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
