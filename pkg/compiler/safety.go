package compiler

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Policy modes. The mode axis is: enforce (block in the kernel) and monitor
// (observe + emit findings, never block).
const (
	ModeEnforce = "enforce"
	ModeMonitor = "monitor"

	// StarTarget is the default-deny sentinel accepted in a behavior's deny
	// values: it means "everything not explicitly allowed".
	StarTarget = "*"
)

// IsObserveMode reports whether the mode only observes behavior and never
// programs deny/allow entries into the kernel.
func IsObserveMode(mode string) bool {
	return mode == ModeMonitor
}

// ValidateNetworkValues validates the hardcoded values of a network behavior.
// A value must be an IPv4 literal, an IPv4 CIDR, or the "*" default-deny
// sentinel. It returns one error per invalid value, in input order, and nil
// when every value is supported.
//
// Note that the accepted CIDR prefix width is narrower at program time:
// egressfilter.ParseTargets expands only prefixes >= /24 and reports the rest
// as rejected targets (surfaced as a policy condition). Admission-time
// validation stays deliberately permissive here so it never rejects a value
// the runtime would accept.
func ValidateNetworkValues(values []string) []error {
	var errs []error
	for i, v := range values {
		if err := validateNetworkValue(v); err != nil {
			errs = append(errs, fmt.Errorf("values[%d]: %w", i, err))
		}
	}
	return errs
}

// validateNetworkBehavior validates the hardcoded allow/deny values of a
// network behavior, reporting each offender at its own field path.
func validateNetworkBehavior(path *field.Path, b *v1alpha1.Behavior) field.ErrorList {
	var errs field.ErrorList
	if b == nil {
		return errs
	}
	if b.Allow != nil {
		errs = append(errs, networkValueErrors(path.Child("allow").Child("values"), b.Allow.Values)...)
	}
	if b.Deny != nil {
		errs = append(errs, networkValueErrors(path.Child("deny").Child("values"), b.Deny.Values)...)
	}
	return errs
}

// networkValueErrors is the field-path-aware form of ValidateNetworkValues,
// used by Compile so a bad literal is reported as field.Invalid on the exact
// value that caused it.
func networkValueErrors(path *field.Path, values []string) field.ErrorList {
	var errs field.ErrorList
	for i, v := range values {
		if err := validateNetworkValue(v); err != nil {
			errs = append(errs, field.Invalid(path.Index(i), v, err.Error()))
		}
	}
	return errs
}

// validateNetworkValue mirrors egressfilter's normalization (surrounding
// whitespace, quotes and brackets are trimmed) so admission and program time
// agree on what a value is.
func validateNetworkValue(raw string) error {
	cleaned := normalizeNetworkValue(raw)
	if cleaned == StarTarget {
		return nil
	}
	if cleaned == "" {
		return fmt.Errorf("empty network target")
	}
	if strings.Contains(cleaned, "/") {
		prefix, err := netip.ParsePrefix(cleaned)
		if err != nil {
			return fmt.Errorf("not an IPv4 CIDR: %q", raw)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("IPv6 CIDR is not supported: %q", raw)
		}
		return nil
	}
	if addr, err := netip.ParseAddr(cleaned); err == nil {
		// Is4In6 is accepted because egressfilter normalizes via To4().
		if !addr.Is4() && !addr.Is4In6() {
			return fmt.Errorf("IPv6 address is not supported: %q", raw)
		}
		return nil
	}
	return fmt.Errorf("not an IPv4 address, IPv4 CIDR or %q: %q", StarTarget, raw)
}

func normalizeNetworkValue(raw string) string {
	return strings.Trim(raw, " \t\"'[]")
}
