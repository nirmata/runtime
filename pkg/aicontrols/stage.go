package aicontrols

import (
	"net/netip"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// Name implements collector.Stage.
func (r *EndpointResolver) Name() string { return StageName }

// Process implements collector.Stage: it stamps runtimeevent.NetFacts.Governed
// on network-bearing events and never drops anything (it always returns true).
//
// The bit is set only when all of the following hold, and left nil otherwise:
//
//   - the integration is configured (Enabled) — otherwise "ungoverned" would
//     be indistinguishable from "no AIControls in this cluster";
//   - the endpoint set has been populated at least once (Ready) — otherwise a
//     restart would report the whole cluster as bypassing the proxy;
//   - the event carries a usable destination address (ev.Net with a valid,
//     routable DestIP).
//
// Loopback destinations stay unknown: the AIControls sidecar topology
// redirects traffic to a proxy in the pod's own network namespace, so a
// loopback flow may well be governed by an address that is not in the
// Service's endpoint set.
//
// Process performs a map lookup only. It never resolves DNS and never makes an
// HTTP or API call — see the package doc's hard constraint.
func (r *EndpointResolver) Process(ev *runtimeevent.Event) bool {
	if ev == nil {
		return true
	}
	if !r.enabled || !r.ready.Load() {
		return true
	}

	switch ev.Kind {
	case runtimeevent.KindNet, runtimeevent.KindTLS, runtimeevent.KindHTTP:
	default:
		return true
	}
	if ev.Net == nil {
		return true
	}

	ip := canonical(ev.Net.DestIP)
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() {
		return true
	}

	governed := r.set.Load().hasAddr(ip)
	ev.Net.Governed = &governed

	if !governed {
		r.log.V(4).Info("flow did not transit the aicontrols proxy",
			"kind", string(ev.Kind), "podUid", ev.Pod.UID,
			"destIp", ip.String(), "destPort", ev.Net.DestPort)
	}
	return true
}

// GovernedFor reports the governed verdict for a destination address without
// mutating an event: (value, known). It is the same decision Process makes and
// exists for callers that hold an address rather than an Event.
func (r *EndpointResolver) GovernedFor(ip netip.Addr) (bool, bool) {
	if !r.enabled || !r.ready.Load() {
		return false, false
	}
	c := canonical(ip)
	if !c.IsValid() || c.IsUnspecified() || c.IsLoopback() {
		return false, false
	}
	return r.set.Load().hasAddr(c), true
}
