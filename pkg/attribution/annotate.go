package attribution

import (
	"github.com/nirmata/runtime/pkg/runtimeevent"
)

const stageName = "attribution"

func (ix *Index) Name() string { return stageName }

func (ix *Index) Process(ev *runtimeevent.Event) bool { return ix.Annotate(ev) }

// Annotate fills ev.Pod from the index, trying the identities an event can carry
// in order of decreasing reliability: the pod uid hint a poll source pre-filled,
// the cgroup id both bpf engines report, then the pid of a tracepoint event. It
// returns false for an event no pod on this node claims, and counts the miss.
func (ix *Index) Annotate(ev *runtimeevent.Event) bool {
	if ev == nil {
		ix.miss()
		return false
	}

	if id, ok := ix.LookupPodUID(ev.Pod.UID); ok {
		ix.apply(ev, id)
		return true
	}
	if id, ok := ix.Lookup(ev.CgroupID); ok {
		ix.apply(ev, id)
		return true
	}
	if id, ok := ix.LookupPID(ev.PID); ok {
		ix.apply(ev, id)
		return true
	}

	ix.log.V(4).Info("dropping unattributable event", "kind", string(ev.Kind),
		"cgroupId", ev.CgroupID, "pid", ev.PID, "podUid", ev.Pod.UID)
	ix.miss()
	return false
}

// apply overwrites ev.Pod with the indexed identity, keeping the container hints
// the source provided when the index has none: a pod uid or pid match knows the
// pod but not necessarily the container.
func (ix *Index) apply(ev *runtimeevent.Event, id runtimeevent.PodIdentity) {
	if id.Container == "" {
		id.Container = ev.Pod.Container
	}
	if id.ContainerID == "" {
		id.ContainerID = ev.Pod.ContainerID
	}
	ev.Pod = id
}

func (ix *Index) miss() {
	if ix.metrics != nil {
		ix.metrics.AttributionMisses.Inc()
	}
}
