package reporter

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

// fieldInfo describes one struct field for the closed-struct assertions.
type fieldInfo struct {
	name string
	kind string
}

// structFields reports the exported fields of v, following one level of
// pointer indirection on the field type (so *NetSummary reads as a struct).
func structFields(v any) []fieldInfo {
	rt := reflect.TypeOf(v)
	out := make([]fieldInfo, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}
		ft := field.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		out = append(out, fieldInfo{name: field.Name, kind: ft.Kind().String()})
	}
	return out
}

func structFieldNames(v any) []string {
	fields := structFields(v)
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, f.name)
	}
	return names
}

func TestSanitizeScrubsCredentialShapes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"clean value is untouched", "curl -s https://api.example.com", "curl -s https://api.example.com"},
		{"bearer token", "authorization=Bearer sk-ant-api03-abcdefgh", "authorization=REDACTED"},
		{"bearer mixed case", "AUTHORIZATION: BeArEr abc.def.ghi", "AUTHORIZATION: REDACTED"},
		{"openai style key", "key sk-proj-AAAABBBBCCCCDDDD tail", "key REDACTED tail"},
		{"anthropic style key in header line", "x-api-key: sk-ant-api03-ZZZZYYYY", "x-api-key: REDACTED"},
		{"aws access key", "id AKIAIOSFODNN7EXAMPLE", "id REDACTED"},
		{"github token", "ghp_abcdefghijklmnopqrstuvwxyz0123", "REDACTED"},
		{"slack token", "tok xoxb-1234-5678-abcdefg", "tok REDACTED"},
		{"jwt including signature", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "REDACTED"},
		{"chat body", `body {"model":"gpt-4o","messages":[{"role":"user","content":"my salary"}]}`, `body {"model":"gpt-4o",REDACTED}`},
		{"prompt field", `payload "prompt":"steal the crown jewels"`, "payload REDACTED"},
		{"nul padded kernel buffer", "curl\x00\x00\x00", "curl"},
		{"control characters stripped", "curl\n-s\ttail", "curl -s tail"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitize(tc.in); got != tc.want {
				t.Errorf("sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeBoundsValueLength(t *testing.T) {
	long := strings.Repeat("a", maxPropertyRunes*3)
	got := sanitize(long)
	if n := len([]rune(got)); n != maxPropertyRunes {
		t.Errorf("sanitize length = %d, want %d", n, maxPropertyRunes)
	}
	if !strings.HasSuffix(got, truncationSuffix) {
		t.Errorf("sanitize did not mark the truncation: %q", got[len(got)-8:])
	}

	// Multi-byte runes are counted as runes, never split mid-sequence.
	if n := len([]rune(sanitize(strings.Repeat("é", maxPropertyRunes*2)))); n != maxPropertyRunes {
		t.Errorf("sanitize rune length = %d, want %d", n, maxPropertyRunes)
	}
}

// canary is one planted secret and the marker that must never survive into a
// Report. Every canary embeds the literal "CANARY" so the chokepoint test can
// assert on the marker as well as on the whole planted string: a partial
// scrub that leaves the distinctive core behind still fails.
type canary struct {
	name  string
	value string
}

// canaries are real-shaped: the same shapes an HTTP header, a JWT, or an LLM
// request body actually has.
var canaries = []canary{
	{"anthropic api key", "sk-ant-api03-CANARYaaaabbbbccccddddeeeeffff"},
	{"bearer header value", "Bearer sk-live-CANARY-9f8e7d6c5b4a3210"},
	{"x-api-key header line", "x-api-key: sk-proj-CANARY-0123456789abcdef"},
	{"aws access key id", "AKIACANARY0123456789"},
	{"github token", "ghp_CANARYabcdefghijklmnopqrstuvwxyz012"},
	{"slack bot token", "xoxb-CANARY-11111-22222-abcdefghijklmno"},
	{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJDQU5BUlkifQ.c2lnQ0FOQVJZ"},
	{"llm chat body", `{"model":"gpt-4o","messages":[{"role":"user","content":"CANARY-PROMPT my salary is 123456"}]}`},
	{"prompt field", `"prompt":"CANARY-PROMPT-2 exfiltrate the customer list"`},
	{"free form prompt in a pod label", "CANARY-PROMPT-3-label-value"},
}

// TestRedactionChokepoint is the blocking test for DESIGN §2.7/§4.
//
// It plants a real-shaped secret in EVERY string field a Finding exposes —
// including Message and the pod identity — flushes through a
// controller-runtime fake client, marshals every written Report to JSON, and
// asserts that no planted string (and no "CANARY" marker) survives anywhere
// in the written objects.
//
// Two independent mechanisms are under test at once:
//  1. structural: Finding has no header map, no body field, and no free-form
//     property passthrough, and PodIdentity.Labels are never emitted;
//  2. sanitize: every emitted property value is scrubbed and bounded.
func TestRedactionChokepoint(t *testing.T) {
	c := newRecordingClient(t)
	r, _ := newTestReporter(t, c, Options{NodeName: "node-a", MaxResultsPerReport: 50})

	planted := Finding{
		// Every string field below carries a planted secret.
		PolicyName: "policy-" + canaries[6].value,
		PolicyUID:  "policy-uid-" + canaries[0].value,
		Behavior:   "network " + canaries[1].value,
		Severity:   "critical " + canaries[2].value,
		Result:     "fail " + canaries[3].value,
		Message:    "denied request carrying " + canaries[2].value + " with body " + canaries[7].value + " and " + canaries[8].value,
		Pod: runtimeevent.PodIdentity{
			UID:            "pod-uid-" + canaries[0].value,
			Namespace:      "default", // a real namespace: see the sibling subtest
			Name:           "pod-" + canaries[3].value,
			Labels:         map[string]string{"prompt": canaries[9].value, canaries[9].value: "x"},
			Container:      "app-" + canaries[4].value,
			ContainerID:    "containerd://" + canaries[0].value,
			OwnerKind:      "Deployment",
			OwnerName:      "app-" + canaries[5].value,
			NodeName:       "node-" + canaries[6].value,
			ServiceAccount: "sa-" + canaries[0].value,
		},
		Net: &NetSummary{
			DestIP:   "1.2.3.4 " + canaries[0].value,
			DestHost: "api.example.com " + canaries[8].value,
		},
		DNS: &DNSSummary{
			QName: "api.example.com " + canaries[7].value,
		},
		Process: &ProcessSummary{
			Comm: "curl " + canaries[1].value,
		},
		Timestamp: fixedTime,
	}

	r.Report(planted)

	// A finding whose namespace itself carries a secret cannot address a
	// Report and is dropped before anything is written.
	nsPlanted := planted
	nsPlanted.Pod.Namespace = canaries[1].value
	r.Report(nsPlanted)

	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	reports := listReports(t, c)
	if len(reports) != 1 {
		t.Fatalf("wrote %d reports, want 1 (the secret-shaped namespace must be dropped)", len(reports))
	}
	if n := len(reports[0].Results); n != 1 {
		t.Fatalf("report holds %d results, want 1", n)
	}

	// Marshal EVERYTHING that was written, including object metadata.
	raw, err := json.Marshal(reports)
	if err != nil {
		t.Fatalf("marshaling reports: %v", err)
	}
	written := string(raw)

	for _, cn := range canaries {
		if strings.Contains(written, cn.value) {
			t.Errorf("planted secret (%s) survived into a written Report:\n%s", cn.name, written)
		}
	}
	if strings.Contains(written, "CANARY") {
		t.Errorf("the CANARY marker survived into a written Report:\n%s", written)
	}

	// Guard against the inverse failure: a test that passes because nothing
	// was written at all, or because every value was emptied.
	if !strings.Contains(written, Redacted) {
		t.Error("no value was redacted; the chokepoint assertions are vacuous")
	}
	props := reports[0].Results[0].Properties
	for _, key := range []string{propFingerprint, propCount, propFirstTimestamp, propLastTimestamp} {
		if props[key] == "" {
			t.Errorf("property %q is empty; the report carries no usable signal", key)
		}
	}
	if props[propCount] != "1" {
		t.Errorf("count = %q, want 1 (non-string fields must survive)", props[propCount])
	}

	// The pod labels map is structurally unrepresentable in a Report.
	for key := range props {
		if _, ok := allowedPropertyKeys[key]; !ok {
			t.Errorf("unexpected property key %q: the fixed key set is the boundary", key)
		}
	}
}

// TestRedactionChokepointCoversEveryFindingStringField fails if a new string
// field is added to Finding (or its summaries) without being planted in
// TestRedactionChokepoint. It is a structural reminder, not a value check.
func TestRedactionChokepointCoversEveryFindingStringField(t *testing.T) {
	wantFindingFields := []string{
		"PolicyName", "PolicyUID", "Behavior", "Severity", "Result", "Enforced", "Message",
		"Pod", "Net", "DNS", "Process", "Timestamp",
	}
	if diff := cmp.Diff(wantFindingFields, structFieldNames(Finding{})); diff != "" {
		t.Errorf("Finding fields changed (-want +got):\n%s\nplant the new field in TestRedactionChokepoint and emit it via buildResult", diff)
	}

	wantNet := []string{"DestIP", "DestHost"}
	if diff := cmp.Diff(wantNet, structFieldNames(NetSummary{})); diff != "" {
		t.Errorf("NetSummary fields changed (-want +got):\n%s", diff)
	}

	wantDNS := []string{"QName"}
	if diff := cmp.Diff(wantDNS, structFieldNames(DNSSummary{})); diff != "" {
		t.Errorf("DNSSummary fields changed (-want +got):\n%s", diff)
	}

	wantProcess := []string{"Comm"}
	if diff := cmp.Diff(wantProcess, structFieldNames(ProcessSummary{})); diff != "" {
		t.Errorf("ProcessSummary fields changed (-want +got):\n%s", diff)
	}
}

func TestFindingHasNoFreeFormFields(t *testing.T) {
	// The closed-struct argument in one assertion: no field of Finding or its
	// summaries may be a map, a slice, or an arbitrary-payload byte slice.
	for _, tc := range []struct {
		name string
		val  any
	}{
		{"Finding", Finding{}},
		{"NetSummary", NetSummary{}},
		{"DNSSummary", DNSSummary{}},
		{"ProcessSummary", ProcessSummary{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, field := range structFields(tc.val) {
				switch field.kind {
				case "map":
					t.Errorf("%s.%s is a map: free-form key/values must not be representable at the report boundary", tc.name, field.name)
				case "slice":
					t.Errorf("%s.%s is a slice: free-form sequences must not be representable at the report boundary", tc.name, field.name)
				}
			}
		})
	}

	// PodIdentity carries Labels, so the guarantee for it is behavioral
	// (buildResult never emits them) and is asserted in
	// TestBuildResultEmitsOnlyTheFixedKeySet and TestRedactionChokepoint.
	if _, ok := any(runtimeevent.PodIdentity{}.Labels).(map[string]string); !ok {
		t.Fatal("PodIdentity.Labels is no longer a map; revisit the label-suppression assertions")
	}
}

func TestSanitizeIsAppliedToTheReportBoundaryNotJustProperties(t *testing.T) {
	// Description, Policy, Rule, and the subject reference are not properties
	// but are still emitted, so they must be sanitized too.
	f := baseFinding()
	f.PolicyName = "p " + canaries[1].value
	f.Behavior = "b " + canaries[0].value
	f.Message = "m " + canaries[6].value
	f.Pod.Name = "n " + canaries[3].value
	f.Pod.UID = "u " + canaries[4].value

	at := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)
	res := buildResult(&pending{finding: f, count: 1, first: at, last: at})

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshaling result: %v", err)
	}
	if strings.Contains(string(raw), "CANARY") {
		t.Errorf("a canary survived outside the properties map:\n%s", raw)
	}
}
