package compiler

import "github.com/nirmata/kyverno-runtime/api/v1alpha1"

// ServiceResolver turns a policy's Service reference into destination addresses.
// It is satisfied by pkg/services, which backs it with API server informers, so
// a reference resolves from watched cache state rather than from DNS.
type ServiceResolver interface {
	// ResolveService returns the addresses for one reference, in the value
	// grammar ParseNetworkValue accepts.
	//
	// found is false when the Service is absent from cache. That is reported
	// separately from an empty address list so an unresolved reference and a
	// Service with no ready endpoints stay distinguishable: the first is a
	// policy that names something nonexistent, the second is a policy whose
	// target is scaled to zero.
	ResolveService(ref v1alpha1.ServiceReference) (addrs []string, found bool)
}
