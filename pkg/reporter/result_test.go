package reporter

import (
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// allowedPropertyKeys is the COMPLETE set of property keys buildResult may
// emit. A new key must be added here consciously — the point of the closed
// Finding struct is that this set never grows by accident (DESIGN §4).
var allowedPropertyKeys = map[string]struct{}{
	propFingerprint: {}, propCount: {}, propFirstTimestamp: {}, propLastTimestamp: {},
	propBehavior: {}, propTarget: {}, propEnforced: {}, propNode: {}, propContainer: {}, propOwner: {}, propServiceAccount: {},
	propDestIP: {}, propDestHost: {}, propDNSName: {},
	propComm: {}, propArgv: {},
}

func TestBuildResultEmitsOnlyTheFixedKeySet(t *testing.T) {
	f := baseFinding()
	f.Target = "api.example.com"
	f.Pod.OwnerKind = "Deployment"
	f.Pod.OwnerName = "app"
	f.Pod.ServiceAccount = "app-sa"
	f.Pod.Labels = map[string]string{"team": "platform", "secret-label": "do-not-emit"}
	f.Process = &ProcessSummary{Comm: "curl", Argv: "curl -sS https://example.com"}

	first := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)
	last := time.Date(2026, 7, 27, 9, 5, 0, 0, time.UTC)
	res := buildResult(&pending{finding: f, count: 3, first: first, last: last})

	for key := range res.Properties {
		if _, ok := allowedPropertyKeys[key]; !ok {
			t.Errorf("buildResult emitted unexpected property key %q", key)
		}
	}

	// Pod labels are user-controlled free-form data and are never emitted.
	for key, value := range res.Properties {
		for lk, lv := range f.Pod.Labels {
			if value == lv || key == lk {
				t.Errorf("pod label %q=%q leaked into property %q", lk, lv, key)
			}
		}
	}

	want := map[string]string{
		propFingerprint:    f.Fingerprint(),
		propCount:          "3",
		propFirstTimestamp: "2026-07-27T09:00:00Z",
		propLastTimestamp:  "2026-07-27T09:05:00Z",
		propBehavior:       "network",
		propTarget:         "api.example.com",
		propEnforced:       "false",
		propNode:           "node-a",
		propContainer:      "app",
		propOwner:          "Deployment/app",
		propServiceAccount: "app-sa",
		propDestIP:         "1.2.3.4",
		propDestHost:       "api.example.com",
		propComm:           "curl",
		propArgv:           "curl -sS https://example.com",
	}
	if diff := cmp.Diff(want, res.Properties); diff != "" {
		t.Errorf("buildResult properties (-want +got):\n%s", diff)
	}

	if res.Source != Source || res.Category != Category || !res.Scored {
		t.Errorf("buildResult metadata = source %q category %q scored %v", res.Source, res.Category, res.Scored)
	}
	if res.Result != openreportsv1alpha1.Result(ResultFail) {
		t.Errorf("buildResult result = %q, want %q", res.Result, ResultFail)
	}
	if res.Severity != "" {
		t.Errorf("buildResult severity = %q, want unset: nothing in Finding can populate it", res.Severity)
	}
	if res.Timestamp.Seconds != last.Unix() {
		t.Errorf("buildResult timestamp = %d, want %d", res.Timestamp.Seconds, last.Unix())
	}
	wantSubject := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: "default", Name: "app-1", UID: "pod-uid-1"}
	if diff := cmp.Diff([]corev1.ObjectReference{wantSubject}, res.Subjects); diff != "" {
		t.Errorf("buildResult subjects (-want +got):\n%s", diff)
	}
}

func TestBuildResultOmitsAbsentSummaries(t *testing.T) {
	f := baseFinding()
	f.Net = nil
	f.Pod.NodeName = ""
	f.Pod.Container = ""
	at := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)

	res := buildResult(&pending{finding: f, count: 1, first: at, last: at})

	for _, key := range []string{propDestIP, propDestHost, propComm,
		propTarget, propNode, propContainer, propOwner} {
		if _, ok := res.Properties[key]; ok {
			t.Errorf("property %q emitted for an absent field", key)
		}
	}
}

// The enforced property distinguishes a kernel deny ("was denied") from
// monitor mode's counterfactual ("would have been denied") and is emitted for
// every result, never omitted.
func TestBuildResultEmitsEnforced(t *testing.T) {
	at := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)
	for _, enforced := range []bool{false, true} {
		f := baseFinding()
		f.Enforced = enforced
		res := buildResult(&pending{finding: f, count: 1, first: at, last: at})
		if got, want := res.Properties[propEnforced], strconv.FormatBool(enforced); got != want {
			t.Errorf("enforced property = %q, want %q", got, want)
		}
	}
}

// resultFor is a compact helper for building applyResults inputs.
func resultFor(fingerprint string, count int, first, last string) openreportsv1alpha1.ReportResult {
	return openreportsv1alpha1.ReportResult{
		Source: Source,
		Policy: "p",
		Result: openreportsv1alpha1.Result(ResultFail),
		Properties: map[string]string{
			propFingerprint:    fingerprint,
			propCount:          strconv.Itoa(count),
			propFirstTimestamp: first,
			propLastTimestamp:  last,
		},
	}
}

func TestApplyResultsMergesByFingerprint(t *testing.T) {
	existing := []openreportsv1alpha1.ReportResult{
		resultFor("fp-a", 2, "2026-07-27T09:00:00Z", "2026-07-27T09:10:00Z"),
	}
	incoming := []openreportsv1alpha1.ReportResult{
		resultFor("fp-a", 3, "2026-07-27T08:00:00Z", "2026-07-27T09:30:00Z"),
		resultFor("fp-b", 1, "2026-07-27T09:20:00Z", "2026-07-27T09:20:00Z"),
	}

	got, summary, truncated, changed := applyResults(existing, incoming, 10)

	if !changed {
		t.Fatal("applyResults reported no change after adding a new fingerprint")
	}
	if truncated {
		t.Error("applyResults truncated below the cap")
	}
	if len(got) != 2 {
		t.Fatalf("applyResults returned %d results, want 2", len(got))
	}

	merged := got[0].Properties
	want := map[string]string{
		propFingerprint:    "fp-a",
		propCount:          "5",                    // 2 existing + 3 incoming
		propFirstTimestamp: "2026-07-27T08:00:00Z", // earliest wins
		propLastTimestamp:  "2026-07-27T09:30:00Z", // latest wins
	}
	if diff := cmp.Diff(want, merged); diff != "" {
		t.Errorf("merged properties (-want +got):\n%s", diff)
	}
	if summary.Fail != 2 {
		t.Errorf("summary.Fail = %d, want 2", summary.Fail)
	}
}

func TestApplyResultsCapsAndReportsTruncation(t *testing.T) {
	// Five distinct fingerprints, cap of 3: the three most recently seen win.
	incoming := []openreportsv1alpha1.ReportResult{
		resultFor("fp-1", 1, "2026-07-27T09:01:00Z", "2026-07-27T09:01:00Z"),
		resultFor("fp-2", 1, "2026-07-27T09:02:00Z", "2026-07-27T09:02:00Z"),
		resultFor("fp-3", 1, "2026-07-27T09:03:00Z", "2026-07-27T09:03:00Z"),
		resultFor("fp-4", 1, "2026-07-27T09:04:00Z", "2026-07-27T09:04:00Z"),
		resultFor("fp-5", 1, "2026-07-27T09:05:00Z", "2026-07-27T09:05:00Z"),
	}

	got, summary, truncated, changed := applyResults(nil, incoming, 3)

	if !truncated {
		t.Error("applyResults did not report truncation above the cap")
	}
	if !changed {
		t.Error("applyResults reported no change while adding results")
	}
	if len(got) != 3 {
		t.Fatalf("applyResults kept %d results, want 3", len(got))
	}
	if summary.Fail != 3 {
		t.Errorf("summary.Fail = %d, want 3 (summary counts kept results only)", summary.Fail)
	}

	kept := make([]string, 0, len(got))
	for _, res := range got {
		kept = append(kept, res.Properties[propFingerprint])
	}
	sort.Strings(kept)
	if diff := cmp.Diff([]string{"fp-3", "fp-4", "fp-5"}, kept); diff != "" {
		t.Errorf("kept the wrong results (-want +got):\n%s", diff)
	}
}

func TestApplyResultsSkipsNoOpUpdate(t *testing.T) {
	existing := []openreportsv1alpha1.ReportResult{
		resultFor("fp-a", 1, "2026-07-27T09:00:00Z", "2026-07-27T09:00:00Z"),
		resultFor("fp-b", 1, "2026-07-27T09:00:00Z", "2026-07-27T09:00:00Z"),
	}

	tests := []struct {
		name        string
		incoming    []openreportsv1alpha1.ReportResult
		max         int
		wantChanged bool
	}{
		{
			name:        "nothing incoming",
			incoming:    nil,
			max:         10,
			wantChanged: false,
		},
		{
			name:        "at capacity with duplicate fingerprints only",
			incoming:    []openreportsv1alpha1.ReportResult{resultFor("fp-a", 1, "2026-07-27T09:30:00Z", "2026-07-27T09:30:00Z")},
			max:         2,
			wantChanged: false,
		},
		{
			name:        "below capacity with duplicate fingerprints",
			incoming:    []openreportsv1alpha1.ReportResult{resultFor("fp-a", 1, "2026-07-27T09:30:00Z", "2026-07-27T09:30:00Z")},
			max:         10,
			wantChanged: true,
		},
		{
			name:        "at capacity with a new fingerprint",
			incoming:    []openreportsv1alpha1.ReportResult{resultFor("fp-c", 1, "2026-07-27T09:30:00Z", "2026-07-27T09:30:00Z")},
			max:         2,
			wantChanged: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _, changed := applyResults(existing, tc.incoming, tc.max)
			if changed != tc.wantChanged {
				t.Errorf("applyResults changed = %v, want %v", changed, tc.wantChanged)
			}
			if !changed {
				if diff := cmp.Diff(existing, got); diff != "" {
					t.Errorf("unchanged results must be returned verbatim (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestMergingClearsLegacySeverityOnExistingResult covers a ReportResult
// written before Severity was removed: applyResults must clear it even when
// the entry is only touched via a duplicate-count merge, and even when
// nothing in that flush's incoming batch matches its fingerprint at all —
// otherwise an upgraded cluster keeps a stale severity forever.
func TestMergingClearsLegacySeverityOnExistingResult(t *testing.T) {
	legacy := func(fingerprint string, count int, first, last string) openreportsv1alpha1.ReportResult {
		r := resultFor(fingerprint, count, first, last)
		r.Severity = "medium"
		return r
	}

	t.Run("at capacity with only a duplicate fingerprint", func(t *testing.T) {
		existing := []openreportsv1alpha1.ReportResult{
			legacy("fp-a", 1, "2026-07-27T09:00:00Z", "2026-07-27T09:00:00Z"),
		}
		incoming := []openreportsv1alpha1.ReportResult{
			resultFor("fp-a", 1, "2026-07-27T09:30:00Z", "2026-07-27T09:30:00Z"),
		}

		got, _, _, changed := applyResults(existing, incoming, 1)

		if !changed {
			t.Fatal("applyResults reported no change while clearing a legacy severity")
		}
		if len(got) != 1 || got[0].Severity != "" {
			t.Fatalf("Severity = %q, want cleared", got[0].Severity)
		}
	})

	t.Run("entry not present in this flush's incoming batch", func(t *testing.T) {
		existing := []openreportsv1alpha1.ReportResult{
			legacy("fp-a", 1, "2026-07-27T09:00:00Z", "2026-07-27T09:00:00Z"),
		}
		incoming := []openreportsv1alpha1.ReportResult{
			resultFor("fp-b", 1, "2026-07-27T09:30:00Z", "2026-07-27T09:30:00Z"),
		}

		got, _, _, changed := applyResults(existing, incoming, 10)

		if !changed {
			t.Fatal("applyResults reported no change while clearing a legacy severity")
		}
		var fpA *openreportsv1alpha1.ReportResult
		for i := range got {
			if got[i].Properties[propFingerprint] == "fp-a" {
				fpA = &got[i]
			}
		}
		if fpA == nil {
			t.Fatal("fp-a missing from applyResults output")
		}
		if fpA.Severity != "" {
			t.Errorf("Severity = %q, want cleared", fpA.Severity)
		}
	})

	t.Run("no legacy severity keeps the no-op skip at capacity", func(t *testing.T) {
		existing := []openreportsv1alpha1.ReportResult{
			resultFor("fp-a", 1, "2026-07-27T09:00:00Z", "2026-07-27T09:00:00Z"),
		}
		incoming := []openreportsv1alpha1.ReportResult{
			resultFor("fp-a", 1, "2026-07-27T09:30:00Z", "2026-07-27T09:30:00Z"),
		}

		_, _, _, changed := applyResults(existing, incoming, 1)

		if changed {
			t.Error("applyResults reported a change with nothing new and no legacy severity to clear")
		}
	})
}

func TestSummarizeCountsByResult(t *testing.T) {
	results := []openreportsv1alpha1.ReportResult{
		{Result: "fail"}, {Result: "fail"}, {Result: "warn"},
		{Result: "pass"}, {Result: "skip"}, {Result: "error"}, {Result: ""},
	}
	want := openreportsv1alpha1.ReportSummary{Pass: 1, Fail: 3, Warn: 1, Skip: 1, Error: 1}
	if diff := cmp.Diff(want, summarize(results)); diff != "" {
		t.Errorf("summarize (-want +got):\n%s", diff)
	}
}

func TestParseCountDefaultsToOne(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{{"", 1}, {"0", 1}, {"-4", 1}, {"nope", 1}, {"7", 7}, {" 12 ", 12}} {
		if got := parseCount(tc.in); got != tc.want {
			t.Errorf("parseCount(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestBuildResultEmitsTheObservedDNSName(t *testing.T) {
	f := baseFinding()
	f.Behavior = "dns"
	f.Net = nil
	f.Result = ResultWarn
	f.DNS = &DNSSummary{QName: "api.openai.com"}

	res := buildResult(&pending{finding: f, count: 1, first: f.Timestamp, last: f.Timestamp})

	if got := res.Properties[propDNSName]; got != "api.openai.com" {
		t.Errorf("%s = %q, want %q", propDNSName, got, "api.openai.com")
	}
	if got := res.Properties[propEnforced]; got != "false" {
		t.Errorf("%s = %q, want \"false\"", propEnforced, got)
	}
	if got := string(res.Result); got != ResultWarn {
		t.Errorf("result = %q, want %q", got, ResultWarn)
	}
}
