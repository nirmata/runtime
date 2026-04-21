package baseline

import (
	"sort"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

// MergedBehaviors represents the effective set of allowed behaviors after merging
// all sources (inline allow + refs + observed).
type MergedBehaviors struct {
	Exec    []string
	Open    []string
	Network []string
	DNS     []string
}

// NewMergedBehaviors returns an empty MergedBehaviors struct.
func NewMergedBehaviors() *MergedBehaviors {
	return &MergedBehaviors{
		Exec:    []string{},
		Open:    []string{},
		Network: []string{},
		DNS:     []string{},
	}
}

// DenyRules represents explicitly denied behaviors.
type DenyRules struct {
	Exec    map[string]bool
	Open    map[string]bool
	Network map[string]bool
	DNS     map[string]bool
}

// NewDenyRules returns an empty DenyRules struct with initialized maps.
func NewDenyRules() *DenyRules {
	return &DenyRules{
		Exec:    make(map[string]bool),
		Open:    make(map[string]bool),
		Network: make(map[string]bool),
		DNS:     make(map[string]bool),
	}
}

// MergeBehaviors computes the effective allow set by merging:
// 1. Explicit deny rules (always block)
// 2. Inline allow rules (spec.allow)
// 3. Shared defaults from refs (first ref wins on conflict)
// 4. Observed behaviors (auto-learned)
//
// Parameters:
// - rb: the RuntimeBehavior resource for the workload
// - sharedDefaults: map of name -> RuntimeBehavior for shared default references
//
// Returns:
// - merged: the effective merged allow set
// - denied: the set of explicitly denied behaviors
func MergeBehaviors(rb *v1alpha1.RuntimeBehavior, sharedDefaults map[string]*v1alpha1.RuntimeBehavior) (*MergedBehaviors, *DenyRules) {
	merged := NewMergedBehaviors()
	denied := NewDenyRules()

	if rb == nil {
		return merged, denied
	}

	// Step 1: Add explicit deny rules (highest priority — always blocks)
	if rb.Spec.Allow != nil && rb.Spec.Allow.Deny != nil {
		for _, item := range rb.Spec.Allow.Deny.Exec {
			denied.Exec[item] = true
		}
		for _, item := range rb.Spec.Allow.Deny.Open {
			denied.Open[item] = true
		}
		for _, item := range rb.Spec.Allow.Deny.Network {
			denied.Network[item] = true
		}
		for _, item := range rb.Spec.Allow.Deny.DNS {
			denied.DNS[item] = true
		}
	}

	// Step 2: Add inline allow rules
	if rb.Spec.Allow != nil {
		merged.Exec = append(merged.Exec, rb.Spec.Allow.Exec...)
		merged.Open = append(merged.Open, rb.Spec.Allow.Open...)
		merged.Network = append(merged.Network, rb.Spec.Allow.Network...)
		merged.DNS = append(merged.DNS, rb.Spec.Allow.DNS...)
	}

	// Step 3: Add shared defaults from refs (in order; first wins on conflict)
	if rb.Spec.Allow != nil && len(rb.Spec.Allow.Refs) > 0 {
		for _, ref := range rb.Spec.Allow.Refs {
			if shared, exists := sharedDefaults[ref.Name]; exists {
				if shared.Spec.Allow != nil {
					// Add only if not already present (first ref wins)
					for _, item := range shared.Spec.Allow.Exec {
						if !contains(merged.Exec, item) {
							merged.Exec = append(merged.Exec, item)
						}
					}
					for _, item := range shared.Spec.Allow.Open {
						if !contains(merged.Open, item) {
							merged.Open = append(merged.Open, item)
						}
					}
					for _, item := range shared.Spec.Allow.Network {
						if !contains(merged.Network, item) {
							merged.Network = append(merged.Network, item)
						}
					}
					for _, item := range shared.Spec.Allow.DNS {
						if !contains(merged.DNS, item) {
							merged.DNS = append(merged.DNS, item)
						}
					}
				}
			}
		}
	}

	// Step 4: Add observed behaviors (lowest priority — fills remaining gaps)
	if rb.Status.Observed != nil {
		for _, item := range rb.Status.Observed.Exec {
			if !contains(merged.Exec, item) {
				merged.Exec = append(merged.Exec, item)
			}
		}
		for _, item := range rb.Status.Observed.Open {
			if !contains(merged.Open, item) {
				merged.Open = append(merged.Open, item)
			}
		}
		for _, item := range rb.Status.Observed.Network {
			if !contains(merged.Network, item) {
				merged.Network = append(merged.Network, item)
			}
		}
		for _, item := range rb.Status.Observed.DNS {
			if !contains(merged.DNS, item) {
				merged.DNS = append(merged.DNS, item)
			}
		}
	}

	// Sort for consistent ordering
	sort.Strings(merged.Exec)
	sort.Strings(merged.Open)
	sort.Strings(merged.Network)
	sort.Strings(merged.DNS)

	return merged, denied
}

// IsAllowed checks if a behavior is in the allow set and not in the deny set.
func IsAllowed(behavior string, allowed []string, denied map[string]bool) bool {
	if denied[behavior] {
		return false
	}
	return contains(allowed, behavior)
}

// contains checks if a string slice contains an item.
func contains(items []string, item string) bool {
	for _, i := range items {
		if i == item {
			return true
		}
	}
	return false
}
