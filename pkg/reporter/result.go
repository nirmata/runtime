package reporter

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// Source identifies kyverno-runtime as the engine that owns the reports it
// writes, both at the Report and the ReportResult level.
const Source = "kyverno-runtime"

// Category groups every result kyverno-runtime emits.
const Category = "Runtime Security"

// AnnotationTruncatedResults is set to "true" on a Report whose results were
// capped at Options.MaxResultsPerReport. Silence must never read as safety:
// an operator can always tell that findings were dropped.
const AnnotationTruncatedResults = "runtime.nirmata.io/truncated-results"

// Labels applied to every Report this package writes.
const (
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelNode      = "runtime.nirmata.io/node"
)

// Property keys. This is the COMPLETE, fixed key set: buildResult writes no
// other key, and there is no API for a caller to add one (DESIGN §4).
const (
	propFingerprint    = "fingerprint"
	propCount          = "count"
	propFirstTimestamp = "firstTimestamp"
	propLastTimestamp  = "lastTimestamp"
	propBehavior       = "behavior"
	propTarget         = "target"
	propEnforced       = "enforced"
	propNode           = "node"
	propContainer      = "container"
	propOwner          = "owner"
	propServiceAccount = "serviceAccount"
	propDestIP         = "destIP"
	propDestHost       = "destHost"
	propDNSName        = "dnsName"
	propComm           = "comm"
	propArgv           = "argv"
)

// pending is one deduplicated finding awaiting the next flush.
type pending struct {
	finding Finding
	count   int
	first   time.Time
	last    time.Time
}

// merge folds a repeat occurrence of the same fingerprint into p. The newest
// finding wins for the descriptive fields so a report always shows the most
// recent message and severity for a fingerprint.
func (p *pending) merge(f Finding, at time.Time) {
	p.finding = f
	p.count++
	if at.Before(p.first) {
		p.first = at
	}
	if at.After(p.last) {
		p.last = at
	}
}

// buildResult renders one deduplicated finding as an OpenReports result.
//
// Every value it emits goes through sanitize, and it
// emits only the fixed key set declared above. PodIdentity.Labels are never
// emitted: arbitrary user-controlled key/values do not belong in a Report.
func buildResult(p *pending) openreportsv1alpha1.ReportResult {
	f := p.finding

	props := map[string]string{
		propFingerprint:    f.Fingerprint(),
		propCount:          strconv.Itoa(p.count),
		propFirstTimestamp: formatTime(p.first),
		propLastTimestamp:  formatTime(p.last),
		// always emitted: "was denied" (true) vs "would have been denied"
		// (false) is the difference a report consumer acts on
		propEnforced: strconv.FormatBool(f.Enforced),
	}
	put := func(key, value string) {
		if v := sanitize(value); v != "" {
			props[key] = v
		}
	}

	put(propBehavior, f.Behavior)
	put(propTarget, f.Target)
	put(propNode, f.Pod.NodeName)
	put(propContainer, f.Pod.Container)
	put(propServiceAccount, f.Pod.ServiceAccount)
	if f.Pod.OwnerKind != "" && f.Pod.OwnerName != "" {
		put(propOwner, f.Pod.OwnerKind+"/"+f.Pod.OwnerName)
	}

	if f.Net != nil {
		put(propDestIP, f.Net.DestIP)
		put(propDestHost, f.Net.DestHost)
	}
	if f.DNS != nil {
		put(propDNSName, f.DNS.QName)
	}
	if f.Process != nil {
		put(propComm, f.Process.Comm)
		put(propArgv, f.Process.Argv)
	}

	return openreportsv1alpha1.ReportResult{
		Source:      Source,
		Policy:      sanitize(f.PolicyName),
		Rule:        sanitize(f.Behavior),
		Category:    Category,
		Severity:    openreportsv1alpha1.ResultSeverity(normalizeSeverity(f.Severity)),
		Result:      openreportsv1alpha1.Result(normalizeResult(f.Result)),
		Scored:      true,
		Timestamp:   metav1.Timestamp{Seconds: p.last.Unix()},
		Description: sanitize(f.Message),
		Subjects:    []corev1.ObjectReference{podReference(f.Pod)},
		Properties:  props,
	}
}

// podReference names the subject pod. Name and namespace are sanitized like
// every other emitted value; the UID is a generated identifier.
func podReference(id runtimeevent.PodIdentity) corev1.ObjectReference {
	return corev1.ObjectReference{
		APIVersion: "v1",
		Kind:       "Pod",
		Namespace:  sanitize(id.Namespace),
		Name:       sanitize(id.Name),
		UID:        k8stypes.UID(sanitize(id.UID)),
	}
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// applyResults merges incoming results into the existing ones by fingerprint
// and caps the result at max.
//
// changed reports whether the Report needs an API write at all: when the
// report is already at capacity and every incoming result is a duplicate
// count increment, the write is skipped to spare the API server (the
// pre-f806f25 contract).
func applyResults(existing, incoming []openreportsv1alpha1.ReportResult, max int) (results []openreportsv1alpha1.ReportResult, summary openreportsv1alpha1.ReportSummary, truncated, changed bool) {
	merged := make([]openreportsv1alpha1.ReportResult, len(existing))
	copy(merged, existing)

	index := make(map[string]int, len(merged))
	for i, res := range merged {
		if fp := res.Properties[propFingerprint]; fp != "" {
			index[fp] = i
		}
	}

	addedNew := false
	for _, cand := range incoming {
		fp := cand.Properties[propFingerprint]
		if fp == "" {
			// Unreachable via buildResult; treated as distinct rather than
			// silently dropped.
			merged = append(merged, cand)
			addedNew = true
			continue
		}
		i, found := index[fp]
		if !found {
			index[fp] = len(merged)
			merged = append(merged, cand)
			addedNew = true
			continue
		}
		merged[i] = mergeResult(merged[i], cand)
	}

	atCapacity := len(existing) >= max
	if atCapacity && !addedNew {
		return existing, summarize(existing), len(existing) > max, false
	}

	bounded, truncated := truncateResults(merged, max)
	summary = summarize(bounded)
	changed = addedNew || !resultsEqual(existing, bounded)
	return bounded, summary, truncated, changed
}

// mergeResult folds a freshly built result for an already-known fingerprint
// into the stored one. next is the base (newest message/severity wins); only
// the accumulated count and the earliest firstTimestamp survive from prev.
func mergeResult(prev, next openreportsv1alpha1.ReportResult) openreportsv1alpha1.ReportResult {
	out := *next.DeepCopy()
	if out.Properties == nil {
		out.Properties = map[string]string{}
	}
	out.Properties[propCount] = strconv.Itoa(parseCount(prev.Properties[propCount]) + parseCount(next.Properties[propCount]))
	out.Properties[propFirstTimestamp] = earliest(prev.Properties[propFirstTimestamp], next.Properties[propFirstTimestamp])
	out.Properties[propLastTimestamp] = latest(prev.Properties[propLastTimestamp], next.Properties[propLastTimestamp])
	return out
}

func parseCount(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// earliest/latest compare RFC3339 stamps, falling back to the non-empty one.
func earliest(a, b string) string {
	ta, aok := parseTime(a)
	tb, bok := parseTime(b)
	switch {
	case !aok:
		return b
	case !bok:
		return a
	case tb.Before(ta):
		return b
	default:
		return a
	}
}

func latest(a, b string) string {
	ta, aok := parseTime(a)
	tb, bok := parseTime(b)
	switch {
	case !aok:
		return b
	case !bok:
		return a
	case tb.After(ta):
		return b
	default:
		return a
	}
}

func parseTime(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// truncateResults keeps the max most recently seen results, newest first by
// lastTimestamp with the fingerprint as a deterministic tie-break.
func truncateResults(results []openreportsv1alpha1.ReportResult, max int) ([]openreportsv1alpha1.ReportResult, bool) {
	if max <= 0 || len(results) <= max {
		return results, false
	}
	sorted := make([]openreportsv1alpha1.ReportResult, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool {
		li, lj := sorted[i].Properties[propLastTimestamp], sorted[j].Properties[propLastTimestamp]
		if li != lj {
			return li > lj
		}
		return sorted[i].Properties[propFingerprint] < sorted[j].Properties[propFingerprint]
	})
	return sorted[:max], true
}

// summarize recomputes the report's status tallies from its results.
func summarize(results []openreportsv1alpha1.ReportResult) openreportsv1alpha1.ReportSummary {
	var summary openreportsv1alpha1.ReportSummary
	for _, res := range results {
		switch strings.ToLower(string(res.Result)) {
		case "pass":
			summary.Pass++
		case ResultWarn:
			summary.Warn++
		case "skip":
			summary.Skip++
		case "error":
			summary.Error++
		default:
			summary.Fail++
		}
	}
	return summary
}

func resultsEqual(a, b []openreportsv1alpha1.ReportResult) bool {
	return reflect.DeepEqual(a, b)
}
