package datasource

import (
	"slices"
	"strings"
)

// NormalizeEventTypes returns unique, lower-cased event types sorted for stable requests.
func NormalizeEventTypes(eventTypes []string) []string {
	if len(eventTypes) == 0 {
		return nil
	}

	unique := make(map[string]struct{}, len(eventTypes))
	out := make([]string, 0, len(eventTypes))
	for _, eventType := range eventTypes {
		trimmed := strings.ToLower(strings.TrimSpace(eventType))
		if trimmed == "" {
			continue
		}
		if _, ok := unique[trimmed]; ok {
			continue
		}
		unique[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	slices.Sort(out)
	return out
}
