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

// The accepted CIDR prefix width is narrower at program time:
// egressfilter.ParseTargets expands only prefixes >= /24 and reports the rest
// as rejected targets. Admission stays deliberately permissive so it never
// rejects a value the runtime would accept.
func networkValueErr(v string) error {
	_, err := ParseNetworkValue(v)
	return err
}

// Exec and open are programmed into the same kernel maps, so both are held to
// this one schema, and lsm.PathKeys applies it unchanged: a value accepted here
// is a value the kernel maps can hold.
func pathValueErr(v string) error {
	_, err := ParsePathValue(v)
	return err
}

// validateBehavior reports every allow or deny value parse rejects, as a
// field.Invalid at that value's own index.
func validateBehavior(path *field.Path, b *v1alpha1.Behavior, parse func(string) error) field.ErrorList {
	if b == nil {
		return nil
	}
	var errs field.ErrorList
	if b.Allow != nil {
		errs = append(errs, invalidValues(path.Child("allow", "values"), b.Allow.Values, parse)...)
	}
	if b.Deny != nil {
		errs = append(errs, invalidValues(path.Child("deny", "values"), b.Deny.Values, parse)...)
	}
	return errs
}

func invalidValues(path *field.Path, values []string, parse func(string) error) field.ErrorList {
	var errs field.ErrorList
	for i, v := range values {
		if err := parse(v); err != nil {
			errs = append(errs, field.Invalid(path.Index(i), v, err.Error()))
		}
	}
	return errs
}

// validateProtocolBehavior validates the hardcoded allow/deny values of a
// protocol behavior against ParseProtocolValue, reporting each offender as
// field.Invalid at the exact value's field path. Every value the grammar
// accepts is programmable, so there is no narrower program-time check.
func validateProtocolBehavior(path *field.Path, b *v1alpha1.Behavior) field.ErrorList {
	if b == nil {
		return nil
	}
	var errs field.ErrorList
	check := func(path *field.Path, values []string) {
		for i, v := range values {
			if _, err := ParseProtocolValue(v); err != nil {
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
