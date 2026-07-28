package runtimeevent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// httpFactsCmp lets tests diff HTTPFacts even though every field is
// unexported. Tests live in-package precisely so the chokepoint's internal
// state can be asserted.
var httpFactsCmp = cmp.AllowUnexported(HTTPFacts{})

// assertNoCanary verifies that the canary secret value is not reachable from
// the facts through any accessor or through JSON.
func assertNoCanary(h *HTTPFacts) error {
	b, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("marshalling facts: %w", err)
	}
	reachable := []string{string(b), h.Method(), h.Path(), h.Host(), h.BodyPreview()}
	for k, v := range h.Headers() {
		reachable = append(reachable, k, v)
	}
	for _, s := range reachable {
		if strings.Contains(s, "sk-canary") || strings.Contains(s, secretValue) {
			return fmt.Errorf("secret value reachable in %q", s)
		}
	}
	return nil
}

func TestNewHTTPFacts_NormalizesFields(t *testing.T) {
	tests := []struct {
		name               string
		method, path, host string
		headers            map[string]string
		body               []byte
		want               *HTTPFacts
	}{
		{
			name:   "lowercases host and trims method",
			method: " POST ",
			path:   "/v1/chat/completions",
			host:   "  API.OpenAI.COM ",
			want: &HTTPFacts{
				method: "POST",
				path:   "/v1/chat/completions",
				host:   "api.openai.com",
			},
		},
		{
			name:    "empty headers normalize to nil",
			method:  "GET",
			path:    "/.well-known/agent.json",
			host:    "agent.example",
			headers: map[string]string{},
			want: &HTTPFacts{
				method: "GET",
				path:   "/.well-known/agent.json",
				host:   "agent.example",
			},
		},
		{
			name:    "secret header redacted, others lowercased",
			method:  "POST",
			path:    "/mcp",
			host:    "mcp.example",
			headers: map[string]string{"Accept": "text/event-stream", "X-Api-Key": secretValue},
			body:    []byte(`{"jsonrpc":"2.0","method":"tools/list"}`),
			want: &HTTPFacts{
				method:      "POST",
				path:        "/mcp",
				host:        "mcp.example",
				headers:     map[string]string{"accept": "text/event-stream", "x-api-key": Redacted},
				bodyPreview: `{"jsonrpc":"2.0","method":"tools/list"}`,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NewHTTPFacts(tc.method, tc.path, tc.host, tc.headers, tc.body)
			if diff := cmp.Diff(tc.want, got, httpFactsCmp); diff != "" {
				t.Errorf("NewHTTPFacts (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewHTTPFacts_TruncatesBodyToMaxBodyPreview(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		wantLen int
		wantPfx string
	}{
		{name: "nil body", body: nil, wantLen: 0},
		{name: "empty body", body: []byte{}, wantLen: 0},
		{name: "under cap", body: []byte(strings.Repeat("a", MaxBodyPreview-1)), wantLen: MaxBodyPreview - 1},
		{name: "exactly cap", body: []byte(strings.Repeat("b", MaxBodyPreview)), wantLen: MaxBodyPreview},
		{name: "over cap", body: []byte(strings.Repeat("c", MaxBodyPreview*4)), wantLen: MaxBodyPreview, wantPfx: "ccc"},
		{
			// 3-byte runes: 512 is not a multiple of 3, so the cut splits a
			// rune; the partial sequence must be dropped (510 bytes kept).
			name:    "over cap splitting a multibyte rune",
			body:    []byte(strings.Repeat("あ", 400)),
			wantLen: 510,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHTTPFacts("POST", "/", "h", nil, tc.body)
			if got := len(h.BodyPreview()); got != tc.wantLen {
				t.Errorf("len(BodyPreview()) = %d, want %d", got, tc.wantLen)
			}
			if len(h.BodyPreview()) > MaxBodyPreview {
				t.Errorf("BodyPreview() exceeds MaxBodyPreview (%d bytes)", len(h.BodyPreview()))
			}
			if tc.wantPfx != "" && !strings.HasPrefix(h.BodyPreview(), tc.wantPfx) {
				t.Errorf("BodyPreview() prefix = %q, want prefix %q", h.BodyPreview(), tc.wantPfx)
			}
		})
	}
}

func TestHTTPFacts_HeadersReturnsCopy(t *testing.T) {
	h := NewHTTPFacts("POST", "/", "h", map[string]string{"Accept": "application/json"}, nil)
	got := h.Headers()
	got["accept"] = "mutated"
	got["injected"] = "x"
	if v := h.Header("Accept"); v != "application/json" {
		t.Errorf("Header(Accept) = %q after mutating the copy, want %q", v, "application/json")
	}
	if v := h.Header("injected"); v != "" {
		t.Errorf("Header(injected) = %q, want empty", v)
	}
}

func TestHTTPFacts_NilReceiverAccessorsAreSafe(t *testing.T) {
	var h *HTTPFacts
	if h.Method() != "" || h.Path() != "" || h.Host() != "" || h.BodyPreview() != "" ||
		h.Header("authorization") != "" || h.Headers() != nil {
		t.Error("nil *HTTPFacts accessors returned non-zero values")
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshalling nil facts: %v", err)
	}
	if string(b) != "null" {
		t.Errorf("json.Marshal(nil facts) = %s, want null", b)
	}
}

func TestHTTPFacts_JSONRoundTripPreservesRedactedFacts(t *testing.T) {
	want := NewHTTPFacts("POST", "/v1/messages", "api.anthropic.com",
		map[string]string{"Authorization": secretValue, "Content-Type": "application/json"},
		[]byte(`{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}`))

	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var got HTTPFacts
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	if diff := cmp.Diff(want, &got, httpFactsCmp); diff != "" {
		t.Errorf("round trip (-want +got):\n%s", diff)
	}
}

// TestHTTPFacts_UnmarshalJSONReRedacts is the fixture-smuggling test: a
// hand-written JSON document carrying live credentials and an oversized body
// must come back redacted and truncated, because UnmarshalJSON routes through
// NewHTTPFacts.
func TestHTTPFacts_UnmarshalJSONReRedacts(t *testing.T) {
	for _, name := range allSecretHeaders() {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"method": "POST",
				"path":   "/v1/messages",
				"host":   "API.Anthropic.COM",
				"headers": map[string]string{
					mixedCase(name): secretValue,
					"Content-Type":  "application/json",
				},
				"bodyPreview": strings.Repeat("z", MaxBodyPreview*2),
			})
			if err != nil {
				t.Fatalf("building fixture: %v", err)
			}

			var got HTTPFacts
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshalling fixture: %v", err)
			}
			if v := got.Header(name); v != Redacted {
				t.Errorf("Header(%q) = %q after unmarshal, want %q", name, v, Redacted)
			}
			if got.Host() != "api.anthropic.com" {
				t.Errorf("Host() = %q, want lowercased", got.Host())
			}
			if l := len(got.BodyPreview()); l != MaxBodyPreview {
				t.Errorf("len(BodyPreview()) = %d, want %d", l, MaxBodyPreview)
			}
			if err := assertNoCanary(&got); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestHTTPFacts_UnmarshalJSONRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "not an object", in: `["nope"]`},
		{name: "wrong header type", in: `{"headers":{"accept":1}}`},
		{name: "truncated", in: `{"method":`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var h HTTPFacts
			if err := json.Unmarshal([]byte(tc.in), &h); err == nil {
				t.Errorf("json.Unmarshal(%s) = nil error, want error", tc.in)
			}
		})
	}
}

// TestHTTPFacts_NoConstructorBypass documents the structural guarantee: a
// zero-value HTTPFacts built without the constructor carries no data at all,
// so the only populated instances in the program came from NewHTTPFacts.
func TestHTTPFacts_NoConstructorBypass(t *testing.T) {
	var h HTTPFacts
	if diff := cmp.Diff(&HTTPFacts{}, &h, httpFactsCmp); diff != "" {
		t.Errorf("zero value (-want +got):\n%s", diff)
	}
	if h.Method() != "" || h.Headers() != nil || h.BodyPreview() != "" {
		t.Error("zero-value HTTPFacts is not empty")
	}
}
