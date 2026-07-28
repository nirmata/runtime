package runtimeevent

import "strings"

// Redacted is the fixed replacement for every secret header value. There is
// deliberately no way to change it and no way to recover the original.
const Redacted = "REDACTED"

// secretHeaderNames are the (already lowercased) header names whose values
// never enter the event plane. Package-private on purpose: there is no
// exported knob to add, remove, or disable entries.
var secretHeaderNames = map[string]struct{}{
	"authorization":        {},
	"proxy-authorization":  {},
	"x-api-key":            {},
	"api-key":              {},
	"x-goog-api-key":       {},
	"cookie":               {},
	"set-cookie":           {},
	"x-amz-security-token": {},
}

// isSecretHeader reports whether values of the named header must be redacted.
// The name is matched case-insensitively.
func isSecretHeader(name string) bool {
	_, ok := secretHeaderNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// redactHeaders returns a new map with lowercased, space-trimmed keys and the
// values of every secret header replaced by Redacted. The input map is never
// mutated and secret values are never copied into the result.
//
// This is the single ingress chokepoint: it is called by NewHTTPFacts, which
// is the only constructor of HTTPFacts.
func redactHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		if isSecretHeader(key) {
			out[key] = Redacted
			continue
		}
		out[key] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
