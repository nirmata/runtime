package baseline

import (
	"testing"

	"github.com/stretchr/testify/require"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

func TestCompactObserved_NormalizesAndCaps(t *testing.T) {
	observed := &v1alpha1.ObservedBehaviors{
		Open: []string{
			"/var/lib/app/1234/cache",
			"/var/lib/app/5678/cache",
			"/var/lib/app/0123456789abcdef0123456789abcdef/data",
			"/etc/hosts",
		},
		DNS:  []string{"Example.COM.", "example.com"},
		Exec: []string{"/bin/sh", "/bin/sh", " "},
	}

	cfg := DefaultCompactionConfig()
	cfg.MaxOpen = 1

	result := CompactObserved(observed, cfg)

	require.True(t, result.OpenOverflow)
	require.False(t, result.ExecOverflow)
	require.False(t, result.DNSOverflow)
	require.Len(t, observed.Open, 1)
	require.Contains(t, observed.Open, DefaultOverflowMarker)
	require.Equal(t, []string{"example.com"}, observed.DNS)
	require.Equal(t, []string{"/bin/sh"}, observed.Exec)
}

func TestCompactObserved_ZeroCapsSkipOverflow(t *testing.T) {
	observed := &v1alpha1.ObservedBehaviors{
		Exec: []string{"a", "b", "c"},
	}

	cfg := DefaultCompactionConfig()
	cfg.MaxExec = 0

	result := CompactObserved(observed, cfg)

	require.False(t, result.ExecOverflow)
	require.Equal(t, []string{"a", "b", "c"}, observed.Exec)
}
