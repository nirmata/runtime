package attribution

import (
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// stageName is the collector stage name reported for attribution.
const stageName = "attribution"

// Name implements collector.Stage.
func (ix *Index) Name() string { return stageName }

// Process implements collector.Stage by delegating to Annotate.
func (ix *Index) Process(ev *runtimeevent.Event) bool { return ix.Annotate(ev) }

// Annotate fills ev.Pod from the index, trying the identities an event can
// carry in order of decreasing reliability:
//
//  1. ev.Pod.UID, pre-filled as a hint by poll sources that know the pod but
//     not the cgroup;
//  2. ev.CgroupID, the key both BPF engines report;
//  3. ev.PID, for tracepoint-sourced events.
//
// It returns false when the event cannot be attributed to a pod known to this
// node -- host-namespace traffic, a pod that has already been deleted, or a
// racing container start -- and counts the miss in
// metrics.AttributionMisses. Unattributable events are dropped rather than
// reported against an unknown workload.
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

// apply overwrites ev.Pod with the indexed identity, keeping the container
// hints the source already provided when the index has none (a pod-UID or
// PID match knows the pod but not necessarily the container).
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
