package compiler

// ServiceResolver turns a cluster Service DNS name into destination addresses.
// It is satisfied by pkg/services, which backs it with API server informers, so
// a Service target resolves from watched cache state rather than from DNS.
type ServiceResolver interface {
	// ResolveService returns the addresses for one Service, in the value
	// grammar ParseNetworkValue accepts.
	//
	// found is false when the Service is absent from cache. That is reported
	// separately from an empty address list so an unresolved name and a Service
	// with no ready endpoints stay distinguishable: the first is a policy
	// naming something nonexistent, the second is a policy whose target is
	// scaled to zero.
	ResolveService(namespace, name string) (addrs []string, found bool)

	// ResolveEndpoint returns the addresses of the one endpoint of a Service
	// whose DNS hostname is hostname, for a per-endpoint record such as
	// "web-0.web.default.svc.cluster.local".
	//
	// found follows ResolveService: false when no endpoint of that Service
	// carries the hostname, which covers both a missing Service and a replica
	// that is not running.
	ResolveEndpoint(namespace, service, hostname string) (addrs []string, found bool)
}
