package baseline

import (
	"testing"

	"github.com/stretchr/testify/require"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

func TestMergeBehaviors_InlineAllowRules(t *testing.T) {
	rb := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec:    []string{"/bin/sh", "/bin/bash"},
				Open:    []string{"/var/log/app.log"},
				Network: []string{"10.0.0.0/8"},
				DNS:     []string{"example.com"},
			},
		},
	}

	merged, denied := MergeBehaviors(rb, nil)

	require.Equal(t, []string{"/bin/bash", "/bin/sh"}, merged.Exec) // sorted
	require.Equal(t, []string{"/var/log/app.log"}, merged.Open)
	require.Equal(t, []string{"10.0.0.0/8"}, merged.Network)
	require.Equal(t, []string{"example.com"}, merged.DNS)
	require.Empty(t, denied.Exec)
}

func TestMergeBehaviors_WithDenyRules(t *testing.T) {
	rb := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/bin/sh", "/bin/bash", "/usr/bin/python"},
				Open: []string{"/etc/passwd", "/etc/shadow"},
				Deny: &v1alpha1.DenyRules{
					Exec: []string{"/bin/bash"},
					Open: []string{"/etc/shadow"},
				},
			},
		},
	}

	merged, denied := MergeBehaviors(rb, nil)

	require.Equal(t, []string{"/bin/bash", "/bin/sh", "/usr/bin/python"}, merged.Exec)
	require.Equal(t, []string{"/etc/passwd", "/etc/shadow"}, merged.Open)
	require.True(t, denied.Exec["/bin/bash"])
	require.True(t, denied.Open["/etc/shadow"])
	require.False(t, denied.Exec["/bin/sh"])
}

func TestMergeBehaviors_WithSharedDefaults(t *testing.T) {
	sharedDefault := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec:    []string{"/bin/sh", "/bin/ls"},
				Network: []string{"8.8.8.8"},
			},
		},
	}

	rb := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/bin/bash"},
				Refs: []v1alpha1.BehaviorReference{{Name: "shared-default"}},
			},
		},
	}

	merged, _ := MergeBehaviors(rb, map[string]*v1alpha1.RuntimeBehavior{
		"shared-default": sharedDefault,
	})

	// Inline wins, then shared defaults (no duplicates)
	require.Equal(t, []string{"/bin/bash", "/bin/ls", "/bin/sh"}, merged.Exec)
	require.Equal(t, []string{"8.8.8.8"}, merged.Network)
}

func TestMergeBehaviors_FirstRefWinsConflict(t *testing.T) {
	// "First ref wins" means overlapping entries from multiple refs only add once
	ref1 := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				DNS: []string{"primary.example.com", "shared.example.com"},
			},
		},
	}
	ref2 := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				DNS: []string{"secondary.example.com", "shared.example.com"},
			},
		},
	}

	rb := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Refs: []v1alpha1.BehaviorReference{
					{Name: "ref1"},
					{Name: "ref2"},
				},
			},
		},
	}

	merged, _ := MergeBehaviors(rb, map[string]*v1alpha1.RuntimeBehavior{
		"ref1": ref1,
		"ref2": ref2,
	})

	// First ref (ref1) takes both its entries, then ref2 adds only non-duplicates
	require.Equal(t, []string{"primary.example.com", "secondary.example.com", "shared.example.com"}, merged.DNS)
}

func TestMergeBehaviors_WithObservedBehaviors(t *testing.T) {
	rb := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/bin/sh"},
			},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{
			Observed: &v1alpha1.ObservedBehaviors{
				Exec: []string{"/bin/sh", "/bin/cat", "/usr/bin/grep"},
				Open: []string{"/var/log/app.log"},
			},
		},
	}

	merged, _ := MergeBehaviors(rb, nil)

	// Observed fills gaps but doesn't duplicate
	require.Equal(t, []string{"/bin/cat", "/bin/sh", "/usr/bin/grep"}, merged.Exec)
	require.Equal(t, []string{"/var/log/app.log"}, merged.Open)
}

func TestMergeBehaviors_AllPriorityLevels(t *testing.T) {
	// Test full merge: deny > inline > refs > observed
	sharedDefault := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/bin/ls", "/bin/cat"},
			},
		},
	}

	rb := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/bin/sh"},
				Deny: &v1alpha1.DenyRules{
					Exec: []string{"/bin/cat"},
				},
				Refs: []v1alpha1.BehaviorReference{{Name: "shared"}},
			},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{
			Observed: &v1alpha1.ObservedBehaviors{
				Exec: []string{"/bin/sh", "/bin/cat", "/usr/bin/grep"},
			},
		},
	}

	merged, denied := MergeBehaviors(rb, map[string]*v1alpha1.RuntimeBehavior{
		"shared": sharedDefault,
	})

	// Inline (/bin/sh) + refs (/bin/ls, /bin/cat) + observed (/usr/bin/grep)
	require.Equal(t, []string{"/bin/cat", "/bin/ls", "/bin/sh", "/usr/bin/grep"}, merged.Exec)
	require.True(t, denied.Exec["/bin/cat"]) // Denied even though allowed
}

func TestMergeBehaviors_NilRuntimeBehavior(t *testing.T) {
	merged, denied := MergeBehaviors(nil, nil)

	require.NotNil(t, merged)
	require.NotNil(t, denied)
	require.Empty(t, merged.Exec)
	require.Empty(t, merged.Open)
	require.Empty(t, merged.Network)
	require.Empty(t, merged.DNS)
	require.Empty(t, denied.Exec)
}

func TestMergeBehaviors_MissingRef(t *testing.T) {
	// If a ref doesn't exist in sharedDefaults, it's silently ignored
	rb := &v1alpha1.RuntimeBehavior{
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Allow: &v1alpha1.AllowRules{
				Exec: []string{"/bin/sh"},
				Refs: []v1alpha1.BehaviorReference{{Name: "nonexistent"}},
			},
		},
	}

	merged, _ := MergeBehaviors(rb, map[string]*v1alpha1.RuntimeBehavior{})

	require.Equal(t, []string{"/bin/sh"}, merged.Exec)
}

func TestIsAllowed_AllowedBehavior(t *testing.T) {
	allowed := []string{"/bin/sh", "/bin/bash"}
	denied := map[string]bool{}

	require.True(t, IsAllowed("/bin/sh", allowed, denied))
	require.False(t, IsAllowed("/bin/cat", allowed, denied))
}

func TestIsAllowed_DeniedBehavior(t *testing.T) {
	allowed := []string{"/bin/sh", "/bin/bash"}
	denied := map[string]bool{"/bin/bash": true}

	require.True(t, IsAllowed("/bin/sh", allowed, denied))
	require.False(t, IsAllowed("/bin/bash", allowed, denied)) // Denied takes precedence
}

func TestIsAllowed_EmptyLists(t *testing.T) {
	require.False(t, IsAllowed("/bin/sh", []string{}, map[string]bool{}))
}

func TestNewMergedBehaviors(t *testing.T) {
	merged := NewMergedBehaviors()

	require.NotNil(t, merged)
	require.Empty(t, merged.Exec)
	require.Empty(t, merged.Open)
	require.Empty(t, merged.Network)
	require.Empty(t, merged.DNS)
}

func TestNewDenyRules(t *testing.T) {
	denied := NewDenyRules()

	require.NotNil(t, denied)
	require.NotNil(t, denied.Exec)
	require.NotNil(t, denied.Open)
	require.NotNil(t, denied.Network)
	require.NotNil(t, denied.DNS)
	require.Empty(t, denied.Exec)
}
