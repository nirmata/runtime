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
