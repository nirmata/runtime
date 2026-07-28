package runtimeevent

import (
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// secretValue is the canary: it must never appear in anything derived from
// HTTPFacts.
const secretValue = "Bearer sk-canary-XYZ-do-not-leak"

// allSecretHeaders returns the sorted list of header names the package treats
// as secret. It is derived from the package table on purpose: adding a name to
// secretHeaderNames automatically extends the redaction tests below.
func allSecretHeaders() []string {
	out := make([]string, 0, len(secretHeaderNames))
	for k := range secretHeaderNames {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestRedactHeaders_RedactsEverySecretHeader(t *testing.T) {
	for _, name := range allSecretHeaders() {
		for _, spelling := range []string{name, strings.ToUpper(name), mixedCase(name), " " + name + " "} {
			t.Run(name+"/"+spelling, func(t *testing.T) {
				got := redactHeaders(map[string]string{
					spelling:       secretValue,
					"Content-Type": "application/json",
				})
				want := map[string]string{
					strings.ToLower(strings.TrimSpace(spelling)): Redacted,
					"content-type": "application/json",
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("redactHeaders (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestRedactHeaders_LowercasesKeysAndKeepsNonSecretValues(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]string
		want map[string]string
	}{
		{name: "nil", in: nil, want: nil},
		{name: "empty", in: map[string]string{}, want: nil},
		{name: "blank key dropped", in: map[string]string{"  ": "x"}, want: nil},
		{
			name: "mixed",
			in: map[string]string{
				"Accept":         "text/event-stream",
				"MCP-Session-Id": "abc123",
				"AUTHORIZATION":  secretValue,
			},
			want: map[string]string{
				"accept":         "text/event-stream",
				"mcp-session-id": "abc123",
				"authorization":  Redacted,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, redactHeaders(tc.in)); diff != "" {
				t.Errorf("redactHeaders (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRedactHeaders_DoesNotMutateInput(t *testing.T) {
	in := map[string]string{"Authorization": secretValue}
	_ = redactHeaders(in)
	if got := in["Authorization"]; got != secretValue {
		t.Errorf("input mutated: got %q, want %q", got, secretValue)
	}
}

func TestNewHTTPFacts_SecretValuesAreUnrecoverable(t *testing.T) {
	headers := map[string]string{"Content-Type": "application/json"}
	for _, name := range allSecretHeaders() {
		headers[mixedCase(name)] = secretValue
	}
	h := NewHTTPFacts("POST", "/v1/messages", "API.Anthropic.com", headers,
		[]byte(`{"model":"claude","messages":[{"content":"hi"}]}`))

	for _, name := range allSecretHeaders() {
		for _, spelling := range []string{name, strings.ToUpper(name), mixedCase(name)} {
			if got := h.Header(spelling); got != Redacted {
				t.Errorf("Header(%q) = %q, want %q", spelling, got, Redacted)
			}
		}
		if got := h.Headers()[name]; got != Redacted {
			t.Errorf("Headers()[%q] = %q, want %q", name, got, Redacted)
		}
	}
	// Nothing reachable from the facts (accessors or JSON) may contain the
	// secret value.
	if err := assertNoCanary(h); err != nil {
		t.Error(err)
	}
}

func mixedCase(s string) string {
	b := []byte(s)
	for i := range b {
		if i%2 == 0 {
			b[i] = strings.ToUpper(string(b[i]))[0]
		}
	}
	return string(b)
}
