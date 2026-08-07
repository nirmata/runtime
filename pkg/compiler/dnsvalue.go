package compiler

import (
	"errors"
	"fmt"
	"strings"
)

// MaxDNSNameLen is the longest dotted name a dns value may carry.
//
// It is derived from the kernel's question-name key rather than from the DNS
// limit: the wire form of a dotted name is two bytes longer than the name (every
// dot becomes a length prefix, plus a leading prefix and a trailing root byte),
// so a 128-byte key holds 126 characters. Admitting the 253 characters DNS
// permits would accept names the observer can never produce, and a policy naming
// one would match nothing while looking correct.
const MaxDNSNameLen = 126

// Sentinel errors returned by ParseDNSValue, terse for the same reason the
// network ones are: callers surface them inside their own vocabulary.
var (
	// ErrEmptyDNSValue reports a value that is empty after trimming.
	ErrEmptyDNSValue = errors.New("empty dns name")
	// ErrWildcardPositionDNSValue reports a wildcard that is not the whole
	// leftmost label: "a.*.b", "a.b.*", "ap*.b", or a bare "*." with no suffix.
	ErrWildcardPositionDNSValue = errors.New(`a wildcard is only supported as the leftmost label: use "*.example.com", an exact name, or "*" to report every name`)
	// ErrNotAHostnameDNSValue reports anything else that is not a name: a single
	// label, a malformed label, a numeric last label, an address, a URL.
	ErrNotAHostnameDNSValue = errors.New(`not a hostname, a "*.<hostname>" wildcard or "*"`)
	// ErrTooLongDNSValue reports a value too long to be matched.
	ErrTooLongDNSValue = fmt.Errorf("dns name is longer than %d characters", MaxDNSNameLen)
	// ErrNULDNSValue reports an embedded NUL, which would truncate the name
	// somewhere between here and the comparison that has to match it.
	ErrNULDNSValue = errors.New("dns name contains a NUL byte")
)

// DNSValue is the parsed form of one dns behavior value. Star is the
// StarTarget sentinel; otherwise Name holds the name and Wildcard reports
// whether it was authored as "*.<Name>", matching any subdomain of Name rather
// than Name itself.
type DNSValue struct {
	Star     bool
	Name     string
	Wildcard bool
}

// ParseDNSValue parses one policy-authored dns behavior value: the StarTarget
// sentinel, an exact hostname, or a left-wildcard "*.<hostname>".
//
// A wildcard is accepted here and rejected by ParseNetworkValue, which is the
// one narrowing point between the two: a dns value is only ever compared
// against an observed question name, while a network target has to be resolved
// to addresses and programmed into a kernel map, and no finite set of addresses
// corresponds to a wildcard. Both schemas agree on what a hostname is, in
// validHostname.
//
// Name is lowercased because observed names arrive lowercased, and a
// case-sensitive comparison against a mixed-case policy value would never
// match instead of failing visibly.
func ParseDNSValue(raw string) (DNSValue, error) {
	cleaned := cleanValue(raw)

	switch {
	case cleaned == "":
		return DNSValue{}, ErrEmptyDNSValue
	case cleaned == StarTarget:
		return DNSValue{Star: true}, nil
	case strings.Contains(cleaned, "\x00"):
		return DNSValue{}, ErrNULDNSValue
	case len(cleaned) > MaxDNSNameLen:
		return DNSValue{}, ErrTooLongDNSValue
	}

	name, wildcard := strings.CutPrefix(normalizeName(cleaned), "*.")
	if strings.Contains(name, "*") {
		return DNSValue{}, ErrWildcardPositionDNSValue
	}
	if !validHostname(name) {
		return DNSValue{}, ErrNotAHostnameDNSValue
	}
	return DNSValue{Name: name, Wildcard: wildcard}, nil
}
