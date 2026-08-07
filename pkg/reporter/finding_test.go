package reporter

import (
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// baseFinding is the reference finding the fingerprint tables mutate.
func baseFinding() Finding {
	return Finding{
		PolicyName: "block-egress",
		PolicyUID:  "policy-uid-1",
		Behavior:   "network",
		Severity:   SeverityHigh,
		Result:     ResultFail,
		Message:    "egress to 1.2.3.4 denied",
		Pod: runtimeevent.PodIdentity{
			UID:       "pod-uid-1",
			Namespace: "default",
			Name:      "app-1",
			Container: "app",
			NodeName:  "node-a",
		},
		Net:       &NetSummary{DestIP: "1.2.3.4", DestHost: "api.example.com"},
		Timestamp: time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC),
	}
}

func TestFingerprintIsStable(t *testing.T) {
	f := baseFinding()
	want := f.Fingerprint()

	if got := f.Fingerprint(); got != want {
		t.Errorf("Fingerprint() is not deterministic: %q then %q", want, got)
	}
	if len(want) != 64 {
		t.Errorf("Fingerprint() length = %d, want 64 hex chars", len(want))
	}

	// Fields that must NOT participate: two occurrences of the same policy
	// hitting the same destination from the same pod are one finding.
	for _, tc := range []struct {
		name  string
		mutat func(*Finding)
	}{
		{"message", func(f *Finding) { f.Message = "totally different message" }},
		{"timestamp", func(f *Finding) { f.Timestamp = f.Timestamp.Add(time.Hour) }},
		{"severity", func(f *Finding) { f.Severity = SeverityLow }},
		{"result", func(f *Finding) { f.Result = ResultWarn }},
		{"policyName", func(f *Finding) { f.PolicyName = "renamed" }},
		{"podName", func(f *Finding) { f.Pod.Name = "app-2" }},
	} {
		t.Run("ignores_"+tc.name, func(t *testing.T) {
			mutated := baseFinding()
			tc.mutat(&mutated)
			if got := mutated.Fingerprint(); got != want {
				t.Errorf("Fingerprint() changed after mutating %s: %q != %q", tc.name, got, want)
			}
		})
	}
}

func TestFingerprintIsUniquePerIdentity(t *testing.T) {
	tests := []struct {
		name  string
		mutat func(*Finding)
	}{
		{"policyUID", func(f *Finding) { f.PolicyUID = "policy-uid-2" }},
		{"podUID", func(f *Finding) { f.Pod.UID = "pod-uid-2" }},
		{"behavior", func(f *Finding) { f.Behavior = "exec" }},
		{"netDestIP", func(f *Finding) { f.Net.DestIP = "5.6.7.8" }},
		{"netDestHost", func(f *Finding) { f.Net.DestHost = "api.other.com" }},
		{"netAbsent", func(f *Finding) { f.Net = nil }},
		{"processComm", func(f *Finding) { f.Process = &ProcessSummary{Comm: "curl"} }},
		{"dnsQName", func(f *Finding) { f.DNS = &DNSSummary{QName: "api.openai.com"} }},
	}

	base := baseFinding().Fingerprint()
	seen := map[string]string{base: "base"}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFinding()
			tc.mutat(&f)
			got := f.Fingerprint()
			if got == base {
				t.Errorf("Fingerprint() unchanged after mutating identity field %s", tc.name)
			}
			if other, dup := seen[got]; dup {
				t.Errorf("Fingerprint() collides between %s and %s", tc.name, other)
			}
			seen[got] = tc.name
		})
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", DefaultSeverity},
		{"medium", SeverityMedium},
		{"  HIGH  ", SeverityHigh},
		{"Critical", SeverityCritical},
		{"info", SeverityInfo},
		{"low", SeverityLow},
		{"catastrophic", DefaultSeverity},
		{"Bearer sk-ant-secret", DefaultSeverity},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeSeverity(tc.in); got != tc.want {
				t.Errorf("normalizeSeverity(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeResult(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ResultFail},
		{"fail", ResultFail},
		{"WARN", ResultWarn},
		{" warn ", ResultWarn},
		{"pass", ResultFail},
		{"anything", ResultFail},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeResult(tc.in); got != tc.want {
				t.Errorf("normalizeResult(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
