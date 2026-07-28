// Package aicontrols answers one question about every observed flow: did it go
// through the AIControls governance proxy, or around it?
//
// AIControls sees only traffic that was configured to reach it (HTTP_PROXY, a
// provider base-URL override, or a sidecar NAT redirect) by a client that
// trusts its CA. That makes it structurally unable to audit its own bypass: a
// flow that skipped the proxy is exactly the flow missing from its audit log.
// kyverno-runtime sees every flow from every cgroup, so it can supply the bit
// AIControls cannot: runtimeevent.NetFacts.Governed.
//
// # Hard constraint
//
// AIControls is never contacted on the event path. The proxy's addresses are
// pulled from the Kubernetes API on an interval into an atomically published
// set; per-event work is a single map lookup. No DNS resolution, no HTTP call,
// and no API request happens inside Process.
//
// # Silence is never safety
//
// Governed is a *bool where nil means "unknown". The resolver leaves it nil
// unless the integration is explicitly configured (Config.ServiceName) AND the
// endpoint set has been populated at least once. Reporting a flow as
// ungoverned when the truth is "we do not know" would manufacture findings, so
// every uncertain case stays nil.
//
// TODO(#66): reconcile.go — periodic,
// batched comparison of the AIControls audit log (N calls for a
// ServiceAccount) against observed provider connections (M flows from the pods
// backing it), where M > N quantifies bypass. Deliberately out of this PR; it
// is batch work in userspace and must never become an event-path lookup.
package aicontrols

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Environment variables read by ConfigFromEnv. The chart plumbs these through
// values.yaml (task B11).
const (
	EnvNamespace = "AICONTROLS_NAMESPACE"
	EnvService   = "AICONTROLS_SERVICE"
	EnvRefresh   = "AICONTROLS_REFRESH"
)

// DefaultRefresh is the endpoint-set refresh interval used when Config.Refresh
// is not set.
const DefaultRefresh = 30 * time.Second

// StageName is the collector stage name, also used as the metrics/drop label.
const StageName = "aicontrols"

// Config selects the AIControls Service whose addresses define "governed".
type Config struct {
	// Namespace holds the AIControls Service. Required when ServiceName is
	// set; an empty Namespace disables the resolver rather than guessing.
	Namespace string
	// ServiceName is the AIControls proxy Service. Empty disables the
	// resolver entirely and Governed stays nil on every event.
	ServiceName string
	// Refresh is how often the Service and its EndpointSlices are re-listed
	// (default DefaultRefresh).
	Refresh time.Duration
}

// ConfigFromEnv reads Config from AICONTROLS_NAMESPACE, AICONTROLS_SERVICE and
// AICONTROLS_REFRESH. A malformed refresh duration is reported as an error
// rather than silently replaced by the default.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		Namespace:   os.Getenv(EnvNamespace),
		ServiceName: os.Getenv(EnvService),
	}
	if raw := os.Getenv(EnvRefresh); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return cfg, fmt.Errorf("parsing %s=%q: %w", EnvRefresh, raw, err)
		}
		cfg.Refresh = d
	}
	return cfg, nil
}

// endpointSet is the immutable snapshot published to readers. It is replaced
// wholesale on every refresh, never mutated in place, so the event path needs
// no lock.
type endpointSet struct {
	addrs     map[netip.Addr]struct{}
	addrPorts map[netip.AddrPort]struct{}
}

func (s *endpointSet) hasAddr(ip netip.Addr) bool {
	if s == nil {
		return false
	}
	_, ok := s.addrs[ip]
	return ok
}

func (s *endpointSet) hasAddrPort(ap netip.AddrPort) bool {
	if s == nil {
		return false
	}
	_, ok := s.addrPorts[ap]
	return ok
}

// EndpointResolver maintains the set of AIControls proxy addresses and
// implements collector.Stage to stamp the governed bit onto events.
type EndpointResolver struct {
	k8s kubernetes.Interface
	cfg Config
	log logr.Logger

	// enabled is decided once at construction: configuration, not liveness.
	enabled bool

	set   atomic.Pointer[endpointSet]
	ready atomic.Bool

	// refreshes counts successful refreshes; tests read it, and it makes a
	// stalled poller visible in debug logs.
	refreshes atomic.Int64

	// after is the interval seam so Run is testable without sleeping.
	after func(time.Duration) <-chan time.Time
}

// NewEndpointResolver builds a resolver. It never contacts the API server; the
// first list happens in Run. A resolver with an empty Config.ServiceName (or a
// service name without a namespace) is disabled: Run returns immediately and
// Process leaves every event untouched.
func NewEndpointResolver(k8s kubernetes.Interface, cfg Config, log logr.Logger) *EndpointResolver {
	if cfg.Refresh <= 0 {
		cfg.Refresh = DefaultRefresh
	}

	r := &EndpointResolver{
		k8s:   k8s,
		cfg:   cfg,
		log:   log,
		after: time.After,
	}

	switch {
	case cfg.ServiceName == "":
		log.V(2).Info("aicontrols integration not configured; governed bit stays unknown",
			"env", EnvService)
	case cfg.Namespace == "":
		log.V(0).Info("aicontrols service configured without a namespace; resolver disabled and the governed bit stays unknown",
			"service", cfg.ServiceName, "env", EnvNamespace)
	case k8s == nil:
		log.V(0).Info("aicontrols resolver has no kubernetes client; resolver disabled and the governed bit stays unknown",
			"namespace", cfg.Namespace, "service", cfg.ServiceName)
	default:
		r.enabled = true
	}

	return r
}

// Enabled reports whether the integration is configured. When it is false the
// governed bit is never set, because "not governed" and "not configured" must
// never be conflated.
func (r *EndpointResolver) Enabled() bool { return r.enabled }

// Ready reports whether the endpoint set has been populated at least once.
// Until then Process leaves Governed nil even when Enabled.
func (r *EndpointResolver) Ready() bool { return r.ready.Load() }

// Refreshes returns the number of successful endpoint-set refreshes.
func (r *EndpointResolver) Refreshes() int64 { return r.refreshes.Load() }

// Addrs returns the current proxy address set, sorted for stable output.
// Intended for status/inventory reporting and tests.
func (r *EndpointResolver) Addrs() []netip.Addr {
	set := r.set.Load()
	if set == nil || len(set.addrs) == 0 {
		return nil
	}
	out := make([]netip.Addr, 0, len(set.addrs))
	for a := range set.addrs {
		out = append(out, a)
	}
	sortAddrs(out)
	return out
}

// IsProxyAddr reports whether ip is one of the AIControls Service's addresses
// (ClusterIPs, external/load-balancer IPs, or a backing endpoint IP). It is a
// pure map lookup: safe and cheap on the event path.
func (r *EndpointResolver) IsProxyAddr(ip netip.Addr) bool {
	return r.set.Load().hasAddr(canonical(ip))
}

// IsProxyAddrPort is the stricter form, matching address and port. Ports come
// from the Service's ClusterIP ports and from the EndpointSlice ports.
func (r *EndpointResolver) IsProxyAddrPort(ap netip.AddrPort) bool {
	return r.set.Load().hasAddrPort(netip.AddrPortFrom(canonical(ap.Addr()), ap.Port()))
}

// Run refreshes the endpoint set immediately and then every Config.Refresh
// until ctx is done. It returns nil on cancellation (and immediately, without
// contacting the API server, when the resolver is disabled).
//
// A failed refresh keeps the previous set: wiping it would turn an API blip
// into a burst of "ungoverned" findings.
func (r *EndpointResolver) Run(ctx context.Context) error {
	if !r.enabled {
		return nil
	}

	r.log.V(2).Info("starting aicontrols endpoint resolver",
		"namespace", r.cfg.Namespace, "service", r.cfg.ServiceName, "refresh", r.cfg.Refresh)

	for {
		if err := r.refresh(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			r.log.V(0).Info("refreshing aicontrols endpoints failed; keeping the previous endpoint set",
				"namespace", r.cfg.Namespace, "service", r.cfg.ServiceName,
				"ready", r.Ready(), "reason", err.Error())
		}

		select {
		case <-ctx.Done():
			r.log.V(2).Info("aicontrols endpoint resolver stopped", "refreshes", r.Refreshes())
			return nil
		case <-r.after(r.cfg.Refresh):
		}
	}
}

// refresh lists the Service and its EndpointSlices and publishes a new set.
func (r *EndpointResolver) refresh(ctx context.Context) error {
	svc, err := r.k8s.CoreV1().Services(r.cfg.Namespace).Get(ctx, r.cfg.ServiceName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting service %s/%s: %w", r.cfg.Namespace, r.cfg.ServiceName, err)
	}

	slices, err := r.k8s.DiscoveryV1().EndpointSlices(r.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + r.cfg.ServiceName,
	})
	if err != nil {
		return fmt.Errorf("listing endpointslices for service %s/%s: %w",
			r.cfg.Namespace, r.cfg.ServiceName, err)
	}

	set := buildSet(svc, slices.Items, r.cfg.ServiceName)
	r.set.Store(set)
	r.ready.Store(true)
	r.refreshes.Add(1)

	r.log.V(2).Info("refreshed aicontrols endpoint set",
		"namespace", r.cfg.Namespace, "service", r.cfg.ServiceName,
		"addrs", len(set.addrs), "addrPorts", len(set.addrPorts))
	if len(set.addrs) == 0 {
		r.log.V(0).Info("aicontrols service resolved to no addresses; flows cannot be classified as governed",
			"namespace", r.cfg.Namespace, "service", r.cfg.ServiceName)
	}
	return nil
}

// buildSet derives the address set from a Service and its EndpointSlices.
// Unparseable and "None"/empty addresses are skipped, never indexed blindly.
func buildSet(svc *corev1.Service, slices []discoveryv1.EndpointSlice, serviceName string) *endpointSet {
	set := &endpointSet{
		addrs:     map[netip.Addr]struct{}{},
		addrPorts: map[netip.AddrPort]struct{}{},
	}

	var svcAddrs []netip.Addr
	if svc != nil {
		for _, raw := range svc.Spec.ClusterIPs {
			svcAddrs = appendAddr(svcAddrs, raw)
		}
		svcAddrs = appendAddr(svcAddrs, svc.Spec.ClusterIP)
		for _, raw := range svc.Spec.ExternalIPs {
			svcAddrs = appendAddr(svcAddrs, raw)
		}
		// Workloads may point HTTPS_PROXY at a load-balancer address.
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			svcAddrs = appendAddr(svcAddrs, ing.IP)
		}
	}

	var svcPorts []uint16
	if svc != nil {
		for _, p := range svc.Spec.Ports {
			if port, ok := toPort(int64(p.Port)); ok {
				svcPorts = append(svcPorts, port)
			}
		}
	}
	set.add(svcAddrs, svcPorts)

	for i := range slices {
		es := &slices[i]
		// Defensive: the label selector is applied server-side, but a fake
		// or a mislabeled slice must not widen the set.
		if es.Labels[discoveryv1.LabelServiceName] != serviceName {
			continue
		}

		var ports []uint16
		for _, p := range es.Ports {
			if p.Port == nil {
				continue
			}
			if port, ok := toPort(int64(*p.Port)); ok {
				ports = append(ports, port)
			}
		}

		for _, ep := range es.Endpoints {
			// Terminating endpoints still receive established traffic, so
			// they stay in the set; only explicitly not-ready-and-not-
			// serving endpoints would be excluded, and excluding them
			// risks false "ungoverned" verdicts. Keep everything.
			var addrs []netip.Addr
			for _, raw := range ep.Addresses {
				addrs = appendAddr(addrs, raw)
			}
			set.add(addrs, ports)
		}
	}

	return set
}

func (s *endpointSet) add(addrs []netip.Addr, ports []uint16) {
	for _, a := range addrs {
		s.addrs[a] = struct{}{}
		for _, p := range ports {
			s.addrPorts[netip.AddrPortFrom(a, p)] = struct{}{}
		}
	}
}

// appendAddr parses raw and appends it when it is a usable unicast address.
func appendAddr(dst []netip.Addr, raw string) []netip.Addr {
	if raw == "" || raw == corev1.ClusterIPNone {
		return dst
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return dst
	}
	addr = canonical(addr)
	if !addr.IsValid() || addr.IsUnspecified() {
		return dst
	}
	return append(dst, addr)
}

// canonical normalizes an address for set membership: IPv4-in-IPv6 forms are
// unmapped and the zone is dropped, so 10.96.0.1 and ::ffff:10.96.0.1 compare
// equal.
func canonical(a netip.Addr) netip.Addr {
	return a.Unmap().WithZone("")
}

func toPort(p int64) (uint16, bool) {
	if p <= 0 || p > 65535 {
		return 0, false
	}
	return uint16(p), true
}

// sortAddrs orders addresses deterministically (Compare is total over Addr).
func sortAddrs(in []netip.Addr) {
	slices.SortFunc(in, func(a, b netip.Addr) int { return a.Compare(b) })
}
