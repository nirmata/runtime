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
