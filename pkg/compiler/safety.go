package compiler

import (
	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Policy modes. The mode axis is: enforce (block in the kernel) and monitor
// (observe + emit findings, never block).
const (
	ModeEnforce = "enforce"
	ModeMonitor = "monitor"
)

// IsObserveMode reports whether the mode only observes behavior and never
// programs deny/allow entries into the kernel.
func IsObserveMode(mode string) bool {
	return mode == ModeMonitor
}

// validateNetworkBehavior validates the hardcoded allow/deny values of a
// network behavior against ParseNetworkValue, reporting each offender as
// field.Invalid at the exact value's field path.
//
// Note that the accepted CIDR prefix width is narrower at program time:
// egressfilter.ParseTargets expands only prefixes >= /24 and reports the rest
// as rejected targets (surfaced as a policy condition). Admission-time
// validation stays deliberately permissive here so it never rejects a value
// the runtime would accept.
func validateNetworkBehavior(path *field.Path, b *v1alpha1.Behavior) field.ErrorList {
	if b == nil {
		return nil
	}
	var errs field.ErrorList
	check := func(path *field.Path, values []string) {
		for i, v := range values {
			if _, err := ParseNetworkValue(v); err != nil {
				errs = append(errs, field.Invalid(path.Index(i), v, err.Error()))
			}
		}
	}
	if b.Allow != nil {
		check(path.Child("allow").Child("values"), b.Allow.Values)
	}
	if b.Deny != nil {
		check(path.Child("deny").Child("values"), b.Deny.Values)
	}
	return errs
}

// validateDNSBehavior validates a dns behavior's hardcoded allow/deny values
// against ParseDNSValue, and rejects the behavior outright in enforce mode.
//
// Blocking egress by name is a network behavior: a domain value there is
// programmed into the domain maps and enforced against the addresses the answer
// snooping associates with it. A dns behavior answers the other question, which
// names a policy could not have listed in advance — so it observes, and an
// author who wrote enforce is pointed at the behavior that enforces rather than
// left with a policy that silently reports.
//
// RuntimePolicySpec carries the same rule so the API server refuses the object
// outright; this is the backstop for a cluster whose CRD predates it, and the two
// messages are meant to read identically.
func validateDNSBehavior(path *field.Path, b *v1alpha1.Behavior, mode string) field.ErrorList {
	if b == nil {
		return nil
	}
	var errs field.ErrorList
	if mode == ModeEnforce {
		errs = append(errs, field.Invalid(path, mode, `a dns behavior reports the names a workload resolves, it does not block them: set spec.mode to "`+ModeMonitor+`", or express the destinations you want blocked as a network behavior, which enforces domain values`))
	}
	check := func(path *field.Path, values []string) {
		for i, v := range values {
			if _, err := ParseDNSValue(v); err != nil {
				errs = append(errs, field.Invalid(path.Index(i), v, err.Error()))
			}
		}
	}
	if b.Allow != nil {
		check(path.Child("allow").Child("values"), b.Allow.Values)
	}
	if b.Deny != nil {
		check(path.Child("deny").Child("values"), b.Deny.Values)
	}
	return errs
}
