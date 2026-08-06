// Package reporter writes kyverno-runtime findings to namespaced OpenReports
// Report resources.
//
// It is the redaction chokepoint of the event plane: this package makes
// leaks structurally impossible on the way out:
//
//  1. Finding is a CLOSED struct — typed scalar fields only. There is no
//     header map, no body field, and no free-form properties passthrough, so
//     an unredacted payload is not even representable at the boundary.
//  2. buildResult emits a FIXED key set into ReportResult.Properties, and
//     every emitted value passes through sanitize (see redact.go).
//  3. PodIdentity.Labels are deliberately never emitted: arbitrary
//     user-controlled key/values have no place in a Report.
//
// None of this is configurable — there is no option, flag, or field that
// disables or weakens it (DESIGN §4).
package reporter

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// Finding is a CLOSED struct: typed scalar fields only. There is no headers
// map, no body field, no free-form properties passthrough. This is the
// redaction boundary: what is not representable cannot leak.
type Finding struct {
	PolicyName string
	PolicyUID  string
	Behavior   string // "network"|"open"|"exec"
	Severity   string // info|low|medium|high|critical (default medium)
	Result     string // "fail"|"warn" (monitor findings are "fail")
	// Enforced is true when the kernel actually denied the operation (an
	// enforce-mode policy's maps blocked it); false for monitor mode's
	// "would have been denied" counterfactual findings.
	Enforced  bool
	Message   string
	Pod       runtimeevent.PodIdentity
	Net       *NetSummary
	Process   *ProcessSummary
	Timestamp time.Time
}

// NetSummary summarizes the destination of a network finding.
type NetSummary struct {
	DestIP   string
	DestHost string
}

// ProcessSummary summarizes the process of an exec/open finding.
type ProcessSummary struct {
	Comm string
	Argv string
}

// Severity values accepted by OpenReports.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// DefaultSeverity is used when a finding carries no (or an unknown) severity.
const DefaultSeverity = SeverityMedium

var knownSeverities = map[string]struct{}{
	SeverityInfo:     {},
	SeverityLow:      {},
	SeverityMedium:   {},
	SeverityHigh:     {},
	SeverityCritical: {},
}

// Result values emitted by this package. Monitor findings are "fail"; "warn"
// is available for advisory findings. No other OpenReports result value is
// ever produced by kyverno-runtime.
const (
	ResultFail = "fail"
	ResultWarn = "warn"
)

// normalizeSeverity lowercases and validates sev, falling back to
// DefaultSeverity for empty or unrecognized input.
func normalizeSeverity(sev string) string {
	s := strings.ToLower(strings.TrimSpace(sev))
	if _, ok := knownSeverities[s]; ok {
		return s
	}
	return DefaultSeverity
}

// normalizeResult maps res onto the two result values this package emits.
func normalizeResult(res string) string {
	if strings.ToLower(strings.TrimSpace(res)) == ResultWarn {
		return ResultWarn
	}
	return ResultFail
}

// Fingerprint identifies a finding across flushes so repeats merge into one
// Report result with a count instead of growing the report unboundedly.
//
// It deliberately excludes the message, timestamp, and every free-text field:
// two occurrences of the same policy hitting the same destination from the
// same pod are the same finding.
func (f Finding) Fingerprint() string {
	var destHost, destIP string
	if f.Net != nil {
		destHost, destIP = f.Net.DestHost, f.Net.DestIP
	}
	var comm string
	if f.Process != nil {
		comm = f.Process.Comm
	}

	raw := strings.Join([]string{
		f.PolicyUID,
		f.Pod.UID,
		f.Behavior,
		destHost,
		destIP,
		comm,
	}, "|")

	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
