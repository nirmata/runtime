package baseline

import (
	"regexp"
	"sort"
	"strings"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

const DefaultOverflowMarker = "__overflow__"

var (
	numericPathSegment = regexp.MustCompile(`/\d+`)
	hexPathSegment     = regexp.MustCompile(`/[a-fA-F0-9]{8,}`)
)

// CompactionConfig controls baseline compaction and cardinality caps.
type CompactionConfig struct {
	MaxExec         int
	MaxOpen         int
	MaxNetwork      int
	MaxDNS          int
	OverflowMarker  string
	NormalizePaths  bool
	NormalizeDomain bool
}

// DefaultCompactionConfig returns conservative caps for observed baseline state.
func DefaultCompactionConfig() CompactionConfig {
	return CompactionConfig{
		MaxExec:         256,
		MaxOpen:         256,
		MaxNetwork:      256,
		MaxDNS:          256,
		OverflowMarker:  DefaultOverflowMarker,
		NormalizePaths:  true,
		NormalizeDomain: true,
	}
}

// CompactionResult summarizes cap/overflow outcomes by dimension.
type CompactionResult struct {
	ExecOverflow    bool
	OpenOverflow    bool
	NetworkOverflow bool
	DNSOverflow     bool
}

func (r CompactionResult) AnyOverflow() bool {
	return r.ExecOverflow || r.OpenOverflow || r.NetworkOverflow || r.DNSOverflow
}

// CompactObserved normalizes and caps observed RuntimeBehavior values in-place.
func CompactObserved(observed *v1alpha1.ObservedBehaviors, cfg CompactionConfig) CompactionResult {
	if observed == nil {
		return CompactionResult{}
	}
	if strings.TrimSpace(cfg.OverflowMarker) == "" {
		cfg.OverflowMarker = DefaultOverflowMarker
	}

	result := CompactionResult{}
	observed.Exec, result.ExecOverflow = compactSlice(observed.Exec, cfg.MaxExec, cfg.OverflowMarker, nil)
	observed.Open, result.OpenOverflow = compactSlice(observed.Open, cfg.MaxOpen, cfg.OverflowMarker, func(v string) string {
		if !cfg.NormalizePaths {
			return v
		}
		return normalizePath(v)
	})
	observed.Network, result.NetworkOverflow = compactSlice(observed.Network, cfg.MaxNetwork, cfg.OverflowMarker, normalizeNetwork)
	observed.DNS, result.DNSOverflow = compactSlice(observed.DNS, cfg.MaxDNS, cfg.OverflowMarker, func(v string) string {
		if !cfg.NormalizeDomain {
			return v
		}
		return normalizeDomain(v)
	})

	return result
}

func compactSlice(values []string, max int, overflowMarker string, normalize func(string) string) ([]string, bool) {
	if len(values) == 0 {
		return nil, false
	}
	set := make(map[string]struct{}, len(values))
	for _, item := range values {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if normalize != nil {
			v = strings.TrimSpace(normalize(v))
		}
		if v == "" {
			continue
		}
		set[v] = struct{}{}
	}

	if len(set) == 0 {
		return nil, false
	}

	normalized := make([]string, 0, len(set))
	for v := range set {
		normalized = append(normalized, v)
	}
	sort.Strings(normalized)

	if max <= 0 || len(normalized) <= max {
		return normalized, false
	}

	capped := append([]string{}, normalized[:max]...)
	if overflowMarker != "" {
		if capped[len(capped)-1] != overflowMarker {
			capped[len(capped)-1] = overflowMarker
		}
	}
	return capped, true
}

func normalizePath(path string) string {
	v := strings.TrimSpace(path)
	if v == "" {
		return ""
	}
	v = numericPathSegment.ReplaceAllString(v, "/{id}")
	v = hexPathSegment.ReplaceAllString(v, "/{hex}")
	return v
}

func normalizeNetwork(value string) string {
	return strings.TrimSpace(value)
}

func normalizeDomain(domain string) string {
	v := strings.TrimSpace(strings.TrimSuffix(domain, "."))
	return strings.ToLower(v)
}
