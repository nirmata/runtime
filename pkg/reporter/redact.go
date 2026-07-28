package reporter

import (
	"regexp"
	"strings"
)

// Redacted replaces every credential- or payload-shaped substring found in a
// value on its way into a Report. It is a constant: there is no knob, flag,
// or option that changes or disables it.
const Redacted = "REDACTED"

// maxPropertyRunes bounds every property value written to a Report. Report
// objects live in etcd; an unbounded value is both a leak risk and a
// resource-exhaustion risk.
const maxPropertyRunes = 256

// truncationSuffix marks a value that sanitize shortened.
const truncationSuffix = "..."

// secretPatterns match credential-shaped substrings. This list is a minimum
// (DESIGN §2.7) — entries may only ever be ADDED.
//
// The last two entries are payload-shaped rather than credential-shaped: a
// Finding has no body field, so a chat payload can only reach a property via
// a producer splicing it into a message. Scrubbing the shape here means even
// that mistake cannot leak a prompt.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+\S+`),                                                         // Authorization: Bearer <token>
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{8,}`),                                                     // OpenAI / Anthropic style keys
	regexp.MustCompile(`AKIA[0-9A-Z]{12,}`),                                                        // AWS access key id
	regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),                                                     // GitHub personal access token
	regexp.MustCompile(`xox[baprs]-\S+`),                                                           // Slack tokens
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]*)?`),            // JWT (header.payload[.signature])
	regexp.MustCompile(`(?is)"messages"\s*:\s*\[[^]]*\]?`),                                         // LLM chat body
	regexp.MustCompile(`(?is)"(content|prompt|input|completion|system)"\s*:\s*"(?:\\.|[^"\\])*"?`), // prompt payloads
}

// sanitize is applied to EVERY property value emitted into a Report. It
// scrubs credential- and payload-shaped substrings, strips control
// characters, and bounds the result to maxPropertyRunes.
func sanitize(v string) string {
	if v == "" {
		return ""
	}

	// C-style buffers from the kernel arrive NUL-padded.
	if i := strings.IndexByte(v, 0); i >= 0 {
		v = v[:i]
	}

	for _, re := range secretPatterns {
		v = re.ReplaceAllString(v, Redacted)
	}

	v = stripControl(v)
	v = strings.TrimSpace(v)

	return truncateRunes(v, maxPropertyRunes)
}

// stripControl removes control characters, which have no place in a report
// property and can be used to hide content from a terminal reader.
func stripControl(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			// Keep nothing: tabs and newlines are noise in a property value.
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncateRunes bounds v to max runes, marking the cut.
func truncateRunes(v string, max int) string {
	runes := []rune(v)
	if len(runes) <= max {
		return v
	}
	if max <= len(truncationSuffix) {
		return string(runes[:max])
	}
	return string(runes[:max-len(truncationSuffix)]) + truncationSuffix
}

// maxEvidenceTokens bounds how many evidence tokens a single result carries.
const maxEvidenceTokens = 16

// evidenceToken is the only accepted evidence shape: a lowercase prefix, a
// colon, then printable ASCII.
var evidenceToken = regexp.MustCompile(`^[a-z0-9.-]+:[\x20-\x7e]*$`)

// headerEvidencePrefix marks evidence naming an HTTP header. Such tokens are
// cut at the header name so no header value can ride along.
const headerEvidencePrefix = "header:"

// sanitizeEvidence keeps only well-shaped evidence tokens: a token whose
// prefix is "header:" is truncated at the header NAME (no '=' and no value),
// every other token's value is cut at the first whitespace (see tokenValue),
// every token is then sanitized, and the list is bounded and deduplicated
// while preserving order.
//
// Evidence is the only slice-of-string the Finding boundary exposes, so it is
// the one place a producer could smuggle free text into a Report. These three
// rules are what make that impossible.
func sanitizeEvidence(tokens []string) []string {
	if len(tokens) == 0 {
		return nil
	}

	out := make([]string, 0, len(tokens))
	seen := make(map[string]struct{}, len(tokens))

	for _, raw := range tokens {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		if !evidenceToken.MatchString(tok) {
			// Not a token: drop it rather than guess what it holds.
			continue
		}
		prefix, value, _ := strings.Cut(tok, ":")
		if prefix+":" == headerEvidencePrefix {
			value = headerName(value)
		} else {
			value = tokenValue(value)
		}
		tok = sanitize(prefix + ":" + value)
		if tok == "" {
			continue
		}
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
		if len(out) == maxEvidenceTokens {
			break
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// tokenValue keeps the single word an evidence value is supposed to be. Every
// token an evidence producer may emit names a host, a path, a port, a package,
// or a shape — none of which contain whitespace — so anything after the first
// space is free-form text that has no business in a Report.
func tokenValue(value string) string {
	if cut := strings.IndexAny(value, " \t"); cut >= 0 {
		value = value[:cut]
	}
	return value
}

// headerName keeps only the header name portion of a "header:" evidence
// token, cutting at the first character that could introduce a value.
func headerName(rest string) string {
	cut := strings.IndexAny(rest, "=: \t\"'")
	if cut >= 0 {
		rest = rest[:cut]
	}
	return strings.ToLower(strings.TrimSpace(rest))
}
