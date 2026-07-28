package ai

import "strings"

// SniffLimit is the default number of body bytes the classifier scans for a
// JSON-RPC method or a model name. It is deliberately smaller than
// runtimeevent.MaxBodyPreview: the keys of interest are the leading members of
// every real JSON-RPC or inference request, and a small window bounds both
// cost and blast radius.
const SniffLimit = 256

// MaxMethodLen bounds an accepted JSON-RPC method name. Real names are short
// ("notifications/roots/list_changed" is 32 bytes); anything longer is not a
// method and must not become evidence.
const MaxMethodLen = 64

// MaxModelLen bounds an accepted model identifier.
const MaxModelLen = 64

// SniffJSONRPCMethod extracts the "method" member of a JSON-RPC request from
// the first limit bytes of body.
//
// It is a bounded SNIFF, never a parse: it does not unmarshal, does not copy
// the body (it slices), does not decode escapes, requires the key to sit where
// an object member can start, and returns false unless it finds a complete,
// charset-validated, length-bounded method name inside the window. A method
// past the limit is simply not found — silence here is a missed detection,
// never a leak and never an unbounded read.
//
// limit <= 0 or limit > len(body) means "scan the whole (already capped) body".
func SniffJSONRPCMethod(body string, limit int) (string, bool) {
	return sniffStringMember(body, "method", limit, ValidMethodName)
}

// SniffModel extracts the "model" member of an inference request body under
// the same bounded rules as SniffJSONRPCMethod. The value is charset- and
// length-validated, which is what stops prompt text from ever reaching
// AIFacts.Model.
func SniffModel(body string, limit int) (string, bool) {
	return sniffStringMember(body, "model", limit, ValidModelName)
}

// sniffStringMember looks for `"<key>" : "<value>"` inside the first limit
// bytes of body and returns the value when it satisfies valid.
//
// Every occurrence of the key within the window is considered, so a decoy
// earlier in the body cannot mask a real member; the loop is bounded by the
// window length and allocates nothing.
func sniffStringMember(body, key string, limit int, valid func(string) bool) (string, bool) {
	if limit <= 0 || limit > len(body) {
		limit = len(body)
	}
	s := body[:limit]
	if !looksLikeJSONObject(s) {
		return "", false
	}

	quoted := `"` + key + `"`
	for off := 0; off < len(s); {
		i := strings.Index(s[off:], quoted)
		if i < 0 {
			return "", false
		}
		i += off
		off = i + len(quoted)

		if !memberStart(s, i) {
			continue // the key sits inside some other string value
		}
		j := skipJSONSpace(s, off)
		if j >= len(s) || s[j] != ':' {
			continue
		}
		j = skipJSONSpace(s, j+1)
		if j >= len(s) || s[j] != '"' {
			continue
		}
		j++

		end := j
		for end < len(s) && s[end] != '"' {
			if s[end] == '\\' {
				// A method or model name has no reason to carry an escape;
				// refusing to decode beats reconstructing chosen bytes.
				end = len(s)
				break
			}
			end++
		}
		if end >= len(s) {
			return "", false // unterminated inside the window
		}
		if v := s[j:end]; valid(v) {
			return v, true
		}
	}
	return "", false
}

// memberStart reports whether the quote at index i can begin an object member
// key: the previous non-whitespace byte must be '{' or ','.
func memberStart(s string, i int) bool {
	for i--; i >= 0; i-- {
		if isJSONSpace(s[i]) {
			continue
		}
		return s[i] == '{' || s[i] == ','
	}
	return false
}

// looksLikeJSONObject reports whether s starts a JSON object.
func looksLikeJSONObject(s string) bool {
	i := skipJSONSpace(s, 0)
	return i < len(s) && s[i] == '{'
}

// ValidMethodName reports whether m is shaped like a JSON-RPC method name:
// 1..MaxMethodLen bytes drawn from letters, digits, '_', '.', '/' and '-'.
// This is what keeps arbitrary body bytes out of AIFacts.JSONRPCMethod and out
// of evidence tokens.
func ValidMethodName(m string) bool {
	return validIdent(m, MaxMethodLen, "_./-")
}

// ValidModelName reports whether m is shaped like a model identifier
// ("gpt-4o-2024-08-06", "anthropic.claude-3-5-sonnet-20241022-v2:0",
// "meta-llama/Llama-3-8B-Instruct", "ft:gpt-4o:acme::abc123").
func ValidModelName(m string) bool {
	return validIdent(m, MaxModelLen, "_./-:@+")
}

func validIdent(s string, max int, extra string) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte(extra, c) >= 0:
		default:
			return false
		}
	}
	return true
}

// skipJSONSpace returns the first index at or after i that is not JSON
// whitespace.
func skipJSONSpace(s string, i int) int {
	for i < len(s) && isJSONSpace(s[i]) {
		i++
	}
	return i
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
