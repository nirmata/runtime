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
	eventCmp = []cmp.Option{addrCmp}
)

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
					DestIP: netip.MustParseAddr("160.79.104.10"),
				},
				Pod: testPod(),
			},
		},
		{
			name: string(KindExec),
			ev: Event{
				Kind: KindExec, Time: fixedTime, Comm: "npx",
				Exec: &ExecFacts{Filename: "/usr/bin/npx"},
				Pod:  testPod(),
			},
		},
		{
			name: string(KindOpen),
			ev: Event{
				Kind: KindOpen, Time: fixedTime, Count: 3, KernelDenied: true, WouldDeny: true,
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
	for _, k := range []Kind{KindNet, KindExec, KindOpen} {
		b, err := json.Marshal(Event{Kind: k})
		if err != nil {
			t.Fatalf("marshalling kind %q: %v", k, err)
		}
		if want := `"kind":"` + string(k) + `"`; !strings.Contains(string(b), want) {
			t.Errorf("marshal(%q) = %s, want it to contain %s", k, b, want)
		}
	}
}
