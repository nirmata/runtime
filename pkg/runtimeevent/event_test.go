package runtimeevent

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var (
	addrCmp  = cmp.Comparer(func(a, b netip.Addr) bool { return a == b })
	eventCmp = []cmp.Option{httpFactsCmp, addrCmp}
)

func ptrTo[T any](v T) *T { return &v }

var fixedTime = time.Date(2026, 7, 27, 12, 34, 56, 123456789, time.UTC)

func testPod() PodIdentity {
	return PodIdentity{
		UID:            "pod-uid-1",
		Namespace:      "team-a",
		Name:           "agent-7f9c",
		Labels:         map[string]string{"app": "agent", "tier": "backend"},
		Container:      "agent",
		ContainerID:    "containerd://abc123",
		OwnerKind:      "Deployment",
		OwnerName:      "agent",
		NodeName:       "node-1",
		ServiceAccount: "agent-sa",
	}
}

func TestEvent_JSONRoundTripForEveryKind(t *testing.T) {
	tests := []struct {
		name string
		ev   Event
	}{
		{
			name: string(KindNet),
			ev: Event{
				Kind: KindNet, Time: fixedTime, CgroupID: 4242, PID: 9, Comm: "python3", Count: 7,
				Net: &NetFacts{
					DestIP:   netip.MustParseAddr("160.79.104.10"),
					DestPort: 443,
					Protocol: "tcp",
					Governed: ptrTo(true),
				},
				Pod: testPod(),
			},
		},
		{
			name: string(KindDNS),
			ev: Event{
				Kind: KindDNS, Time: fixedTime, CgroupID: 1,
				DNS: &DNSFacts{QName: "api.anthropic.com", QType: 1},
				Pod: testPod(),
			},
		},
		{
			name: string(KindTLS),
			ev: Event{
				Kind: KindTLS, Time: fixedTime, PID: 1234, Comm: "curl",
				TLS: &TLSFacts{SNI: "api.openai.com", ALPN: []string{"h2", "http/1.1"}, JA4: "t13d1516h2_8daaf6152771_e5627efa2ab1"},
				Pod: testPod(),
			},
		},
		{
			name: string(KindHTTP),
			ev: Event{
				Kind: KindHTTP, Time: fixedTime, Denied: true,
				HTTP: NewHTTPFacts("POST", "/v1/messages", "api.anthropic.com",
					map[string]string{"Authorization": secretValue, "Content-Type": "application/json"},
					[]byte(`{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}`)),
				Pod: testPod(),
			},
		},
		{
			name: string(KindExec),
			ev: Event{
				Kind: KindExec, Time: fixedTime, Comm: "npx",
				Exec: &ExecFacts{Filename: "/usr/bin/npx", Argv: []string{"npx", "-y", "@modelcontextprotocol/server-filesystem"}, PPID: 42},
				Pod:  testPod(),
			},
		},
		{
			name: string(KindOpen),
			ev: Event{
				Kind: KindOpen, Time: fixedTime, Count: 3,
				Open: &OpenFacts{Path: "/etc/shadow"},
				Pod:  testPod(),
			},
		},
		{
			name: "zero value",
			ev:   Event{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.ev)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			var got Event
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshalling %s: %v", b, err)
			}
			if diff := cmp.Diff(tc.ev, got, eventCmp...); diff != "" {
				t.Errorf("round trip (-want +got):\n%s", diff)
			}
			// A second pass must be byte-stable.
			b2, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("re-marshalling: %v", err)
			}
			if string(b) != string(b2) {
				t.Errorf("marshal not stable:\n first: %s\nsecond: %s", b, b2)
			}
		})
	}
}

func TestEvent_KindDiscriminatorMarshalsAsString(t *testing.T) {
	for _, k := range []Kind{KindNet, KindDNS, KindTLS, KindHTTP, KindExec, KindOpen} {
		b, err := json.Marshal(Event{Kind: k})
		if err != nil {
			t.Fatalf("marshalling kind %q: %v", k, err)
		}
		if want := `"kind":"` + string(k) + `"`; !strings.Contains(string(b), want) {
			t.Errorf("marshal(%q) = %s, want it to contain %s", k, b, want)
		}
	}
}

// TestEvent_UnmarshalReRedactsHTTPFixture guards the fixture path used by the
// synthetic source: secrets in an events.json cannot reach the pipeline.
func TestEvent_UnmarshalReRedactsHTTPFixture(t *testing.T) {
	const fixture = `{
      "kind": "http",
      "time": "2026-07-27T12:34:56Z",
      "http": {
        "method": "POST",
        "path": "/v1/messages",
        "host": "api.anthropic.com",
        "headers": {"Authorization": "Bearer sk-canary-XYZ-do-not-leak", "X-API-KEY": "canary-KEY-123"},
        "bodyPreview": "{\"model\":\"claude\"}"
      }
    }`
	var ev Event
	if err := json.Unmarshal([]byte(fixture), &ev); err != nil {
		t.Fatalf("unmarshalling fixture: %v", err)
	}
	if ev.HTTP == nil {
		t.Fatal("HTTP facts not populated")
	}
	for _, name := range []string{"authorization", "x-api-key"} {
		if got := ev.HTTP.Header(name); got != Redacted {
			t.Errorf("Header(%q) = %q, want %q", name, got, Redacted)
		}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	for _, canary := range []string{"sk-canary", "canary-KEY-123"} {
		if strings.Contains(string(b), canary) {
			t.Errorf("canary %q survived into %s", canary, b)
		}
	}
}
