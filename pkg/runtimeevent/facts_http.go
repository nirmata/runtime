package runtimeevent

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// MaxBodyPreview is the hard cap, in bytes, on the request body kept for
// classification. Non-configurable.
const MaxBodyPreview = 512

// HTTPFacts describes an observed plaintext HTTP request.
//
// All fields are unexported and NewHTTPFacts is the only constructor, which
// makes redaction structurally unavoidable: no caller (including a
// hand-written JSON fixture, see UnmarshalJSON) can place an unredacted
// secret header value inside an HTTPFacts.
type HTTPFacts struct {
	method, path, host string
	headers            map[string]string // lowercased keys, secret values already REDACTED
	bodyPreview        string            // <= MaxBodyPreview bytes
}

// NewHTTPFacts is the ONLY way to build HTTPFacts. It lowercases header keys,
// replaces the values of secret headers with Redacted, and truncates body to
// MaxBodyPreview. Non-configurable.
func NewHTTPFacts(method, path, host string, headers map[string]string, body []byte) *HTTPFacts {
	return &HTTPFacts{
		method:      strings.TrimSpace(method),
		path:        path,
		host:        strings.ToLower(strings.TrimSpace(host)),
		headers:     redactHeaders(headers),
		bodyPreview: truncateBody(body),
	}
}

// truncateBody caps body at MaxBodyPreview bytes. When the cut lands in the
// middle of a multi-byte UTF-8 sequence, the partial sequence is dropped so
// text bodies stay valid UTF-8 (and therefore survive a JSON round-trip byte
// for byte). Bodies that were not valid UTF-8 to begin with are passed
// through unchanged.
func truncateBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if len(body) <= MaxBodyPreview {
		return string(body)
	}
	body = body[:MaxBodyPreview]
	// Walk back at most UTFMax-1 bytes looking for a lead byte whose sequence
	// the cut left incomplete.
	for i := 1; i < utf8.UTFMax && i <= len(body); i++ {
		p := len(body) - i
		b := body[p]
		if b < utf8.RuneSelf || b&0xC0 == 0x80 {
			continue // ASCII or continuation byte: keep looking back
		}
		if leadRuneLen(b) > i {
			body = body[:p] // sequence starting at p is truncated
		}
		break
	}
	return string(body)
}

// leadRuneLen returns the encoded length declared by a UTF-8 lead byte.
func leadRuneLen(b byte) int {
	switch {
	case b&0xE0 == 0xC0:
		return 2
	case b&0xF0 == 0xE0:
		return 3
	case b&0xF8 == 0xF0:
		return 4
	}
	return 1
}

// Method returns the request method (e.g. "POST").
func (h *HTTPFacts) Method() string {
	if h == nil {
		return ""
	}
	return h.method
}

// Path returns the request target path.
func (h *HTTPFacts) Path() string {
	if h == nil {
		return ""
	}
	return h.path
}

// Host returns the lowercased Host header / authority.
func (h *HTTPFacts) Host() string {
	if h == nil {
		return ""
	}
	return h.host
}

// Header returns the (redacted) value of the named header. The lookup is
// case-insensitive. Secret headers always return Redacted when present.
func (h *HTTPFacts) Header(name string) string {
	if h == nil || h.headers == nil {
		return ""
	}
	return h.headers[strings.ToLower(strings.TrimSpace(name))]
}

// Headers returns a copy of the redacted header map (lowercased keys), so
// callers cannot mutate the facts.
func (h *HTTPFacts) Headers() map[string]string {
	if h == nil || len(h.headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(h.headers))
	for k, v := range h.headers {
		out[k] = v
	}
	return out
}

// BodyPreview returns at most MaxBodyPreview bytes of the request body.
func (h *HTTPFacts) BodyPreview() string {
	if h == nil {
		return ""
	}
	return h.bodyPreview
}

// httpFactsJSON is the wire shape of HTTPFacts.
type httpFactsJSON struct {
	Method      string            `json:"method,omitempty"`
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyPreview string            `json:"bodyPreview,omitempty"`
}

// MarshalJSON emits {"method","path","host","headers","bodyPreview"}. Only
// already-redacted state exists to emit.
func (h *HTTPFacts) MarshalJSON() ([]byte, error) {
	if h == nil {
		return []byte("null"), nil
	}
	return json.Marshal(httpFactsJSON{
		Method:      h.method,
		Path:        h.path,
		Host:        h.host,
		Headers:     h.headers,
		BodyPreview: h.bodyPreview,
	})
}

// UnmarshalJSON routes through NewHTTPFacts, so a hand-written fixture cannot
// smuggle an unredacted secret header value or an oversized body into the
// event plane.
func (h *HTTPFacts) UnmarshalJSON(b []byte) error {
	var raw httpFactsJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*h = *NewHTTPFacts(raw.Method, raw.Path, raw.Host, raw.Headers, []byte(raw.BodyPreview))
	return nil
}
