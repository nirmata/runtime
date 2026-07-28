package inventory

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var baseTime = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

// fakeClock hands out a fixed time unless advanced.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func boolPtr(b bool) *bool { return &b }

// aiEvent builds a minimal classified event attributed to an owner workload.
func aiEvent(ns, ownerKind, ownerName string, facts *runtimeevent.AIFacts) runtimeevent.Event {
	return runtimeevent.Event{
		Kind: runtimeevent.KindTLS,
		Pod: runtimeevent.PodIdentity{
			UID:       "pod-uid",
			Namespace: ns,
			Name:      "pod-1",
			OwnerKind: ownerKind,
			OwnerName: ownerName,
		},
		TLS: &runtimeevent.TLSFacts{SNI: "api.openai.com"},
		AI:  facts,
	}
}

func newTestRollup(t *testing.T, clock *fakeClock) *Rollup {
	t.Helper()
	return New(logr.Discard(), WithClock(clock.Now))
}

// TestRecordAggregatesAndDeduplicates folds several events for the same
// workload and asserts the class/provider/model/endpointKind/transport sets are
// deduplicated and the counters accumulate.
func TestRecordAggregatesAndDeduplicates(t *testing.T) {
	clock := newFakeClock(baseTime)
	r := newTestRollup(t, clock)

	for _, facts := range []*runtimeevent.AIFacts{
		{Class: runtimeevent.AIClassLLM, Provider: "openai", EndpointKind: "chat.completions", Transport: "https", Model: "gpt-4o"},
		{Class: runtimeevent.AIClassLLM, Provider: "openai", EndpointKind: "chat.completions", Transport: "https", Model: "gpt-4o"},
		{Class: runtimeevent.AIClassLLM, Provider: "anthropic", EndpointKind: "messages", Transport: "https", Model: "claude-sonnet"},
		{Class: runtimeevent.AIClassMCP, Provider: "", EndpointKind: "mcp.streamable-http", Transport: "http"},
	} {
		r.Record(aiEvent("default", "Deployment", "agent", facts))
		clock.Advance(time.Minute)
	}

	got := r.Snapshot()
	want := []v1alpha1.AIWorkloadInventory{{
		Namespace:     "default",
		Kind:          "Deployment",
		Name:          "agent",
		Classes:       []string{"llm", "mcp"},
		Providers:     []string{"anthropic", "openai"},
		EndpointKinds: []string{"chat.completions", "mcp.streamable-http", "messages"},
		Models:        []string{"claude-sonnet", "gpt-4o"},
		Transports:    []string{"http", "https"},
		EventCount:    4,
		FirstSeen:     metav1.NewTime(baseTime),
		LastSeen:      metav1.NewTime(baseTime.Add(3 * time.Minute)),
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Snapshot() (-want +got):\n%s", diff)
	}
}

// TestRecordFirstAndLastSeenUseTheClock covers both timestamp sources: the
// event's own Time when set, and the injected clock when it is zero (including
// an out-of-order arrival, which must not move firstSeen forward).
func TestRecordFirstAndLastSeenUseTheClock(t *testing.T) {
	clock := newFakeClock(baseTime.Add(time.Hour))
	r := newTestRollup(t, clock)

	// clock-sourced (Time zero)
	r.Record(aiEvent("ns", "Pod", "p", &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM}))

	// an event that happened earlier than anything seen so far
	early := aiEvent("ns", "Pod", "p", &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM})
	early.Time = baseTime
	r.Record(early)

	// and a later one
	late := aiEvent("ns", "Pod", "p", &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM})
	late.Time = baseTime.Add(3 * time.Hour)
	r.Record(late)

	got := r.Snapshot()
	if len(got) != 1 {
		t.Fatalf("Snapshot() returned %d workloads, want 1", len(got))
	}
	if want := metav1.NewTime(baseTime); !got[0].FirstSeen.Equal(&want) {
		t.Errorf("FirstSeen = %v, want %v", got[0].FirstSeen, want)
	}
	if want := metav1.NewTime(baseTime.Add(3 * time.Hour)); !got[0].LastSeen.Equal(&want) {
		t.Errorf("LastSeen = %v, want %v", got[0].LastSeen, want)
	}
}

// TestRecordCountsUngovernedOnlyWhenGovernedIsFalse pins the three-state
// governed bit: nil means unknown and must never be counted as a bypass.
func TestRecordCountsUngovernedOnlyWhenGovernedIsFalse(t *testing.T) {
	tests := []struct {
		name           string
		governed       *bool
		count          uint32
		wantEvents     int64
		wantUngoverned int64
	}{
		{name: "governed true", governed: boolPtr(true), wantEvents: 1},
		{name: "governed false", governed: boolPtr(false), wantEvents: 1, wantUngoverned: 1},
		{name: "governed unknown", governed: nil, wantEvents: 1},
		{name: "aggregated count false", governed: boolPtr(false), count: 7, wantEvents: 7, wantUngoverned: 7},
		{name: "aggregated count true", governed: boolPtr(true), count: 7, wantEvents: 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock(baseTime)
			r := newTestRollup(t, clock)

			ev := aiEvent("ns", "Deployment", "agent", &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM, Provider: "openai"})
			ev.Kind = runtimeevent.KindNet
			ev.TLS = nil
			ev.Count = tc.count
			ev.Net = &runtimeevent.NetFacts{
				DestIP:   netip.MustParseAddr("104.18.7.192"),
				DestPort: 443,
				Governed: tc.governed,
			}
			r.Record(ev)

			got := r.Snapshot()
			if len(got) != 1 {
				t.Fatalf("Snapshot() returned %d workloads, want 1", len(got))
			}
			if got[0].EventCount != tc.wantEvents {
				t.Errorf("EventCount = %d, want %d", got[0].EventCount, tc.wantEvents)
			}
			if got[0].UngovernedCount != tc.wantUngoverned {
				t.Errorf("UngovernedCount = %d, want %d", got[0].UngovernedCount, tc.wantUngoverned)
			}
		})
	}
}

// TestRecordIgnoresUnclassifiedAndUnattributed keeps non-AI traffic and events
// with no usable workload identity out of the inventory.
func TestRecordIgnoresUnclassifiedAndUnattributed(t *testing.T) {
	facts := &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM, Provider: "openai"}

	tests := []struct {
		name string
		ev   runtimeevent.Event
	}{
		{
			name: "no AI facts",
			ev:   aiEvent("ns", "Deployment", "agent", nil),
		},
		{
			name: "no namespace",
			ev:   aiEvent("", "Deployment", "agent", facts),
		},
		{
			name: "no owner and no pod name",
			ev: runtimeevent.Event{
				Kind: runtimeevent.KindDNS,
				Pod:  runtimeevent.PodIdentity{Namespace: "ns"},
				DNS:  &runtimeevent.DNSFacts{QName: "api.openai.com"},
				AI:   facts,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRollup(t, newFakeClock(baseTime))
			r.Record(tc.ev)
			if got := r.Snapshot(); len(got) != 0 {
				t.Errorf("Snapshot() = %+v, want empty", got)
			}
		})
	}
}

// TestRecordKeyForBarePodFallsBackToPodIdentity asserts the Kind/Name of an
// unowned pod is the pod itself.
func TestRecordKeyForBarePodFallsBackToPodIdentity(t *testing.T) {
	r := newTestRollup(t, newFakeClock(baseTime))

	ev := aiEvent("ns", "", "", &runtimeevent.AIFacts{Class: runtimeevent.AIClassA2A})
	r.Record(ev)

	got := r.Snapshot()
	if len(got) != 1 {
		t.Fatalf("Snapshot() returned %d workloads, want 1", len(got))
	}
	if got[0].Kind != "Pod" || got[0].Name != "pod-1" {
		t.Errorf("workload identity = %s/%s, want Pod/pod-1", got[0].Kind, got[0].Name)
	}
}

// TestSnapshotIsSortedAndStable records the same observations in a scrambled
// order and asserts the output ordering is deterministic and repeat calls are
// identical.
func TestSnapshotIsSortedAndStable(t *testing.T) {
	clock := newFakeClock(baseTime)
	r := newTestRollup(t, clock)

	type wl struct{ ns, kind, name string }
	// deliberately unsorted insertion order
	inserted := []wl{
		{"zeta", "Deployment", "a"},
		{"alpha", "StatefulSet", "b"},
		{"alpha", "Deployment", "z"},
		{"alpha", "Deployment", "a"},
		{"beta", "Pod", "solo"},
	}
	for _, w := range inserted {
		ev := aiEvent(w.ns, w.kind, w.name, &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM, Provider: "openai"})
		r.Record(ev)
	}

	want := []WorkloadKey{
		{"alpha", "Deployment", "a"},
		{"alpha", "Deployment", "z"},
		{"alpha", "StatefulSet", "b"},
		{"beta", "Pod", "solo"},
		{"zeta", "Deployment", "a"},
	}

	first := r.Snapshot()
	var gotKeys []WorkloadKey
	for _, w := range first {
		gotKeys = append(gotKeys, WorkloadKey{w.Namespace, w.Kind, w.Name})
	}
	if diff := cmp.Diff(want, gotKeys); diff != "" {
		t.Errorf("Snapshot() ordering (-want +got):\n%s", diff)
	}

	second := r.Snapshot()
	if diff := cmp.Diff(first, second); diff != "" {
		t.Errorf("two Snapshot() calls differ (-first +second):\n%s", diff)
	}
	// the returned slices must not alias the accumulator's state
	if len(second) > 0 && len(second[0].Providers) > 0 {
		second[0].Providers[0] = "mutated"
		if third := r.Snapshot(); third[0].Providers[0] != "openai" {
			t.Errorf("Snapshot() aliases internal state: got %q", third[0].Providers[0])
		}
	}
}

// TestSnapshotTruncatesTimestampsToSeconds keeps sub-second precision out of the
// API object, so a JSON round trip does not make an unchanged shard look dirty.
func TestSnapshotTruncatesTimestampsToSeconds(t *testing.T) {
	r := newTestRollup(t, newFakeClock(baseTime.Add(500*time.Millisecond)))
	r.Record(aiEvent("ns", "Pod", "p", &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM}))

	got := r.Snapshot()[0]
	if got.FirstSeen.Nanosecond() != 0 || got.LastSeen.Nanosecond() != 0 {
		t.Errorf("timestamps keep sub-second precision: firstSeen=%v lastSeen=%v", got.FirstSeen, got.LastSeen)
	}
}

// TestRecordBoundsSetSizeAndValueLength keeps a workload that emits unbounded
// attacker-influenced model names from growing the singleton without limit.
func TestRecordBoundsSetSizeAndValueLength(t *testing.T) {
	r := newTestRollup(t, newFakeClock(baseTime))

	for i := 0; i < maxSetEntries*2; i++ {
		r.Record(aiEvent("ns", "Deployment", "agent", &runtimeevent.AIFacts{
			Class: runtimeevent.AIClassLLM,
			Model: fmt.Sprintf("model-%d", i),
		}))
	}
	long := string(make([]byte, maxValueLen+50))
	r.Record(aiEvent("ns", "Deployment", "agent", &runtimeevent.AIFacts{
		Class:        runtimeevent.AIClassLLM,
		EndpointKind: long,
	}))

	got := r.Snapshot()[0]
	if len(got.Models) != maxSetEntries {
		t.Errorf("Models has %d entries, want the cap of %d", len(got.Models), maxSetEntries)
	}
	for _, ek := range got.EndpointKinds {
		if len(ek) > maxValueLen {
			t.Errorf("endpoint kind of %d bytes survived, want <= %d", len(ek), maxValueLen)
		}
	}
	// every event still counts, even when its values were dropped
	if want := int64(maxSetEntries*2 + 1); got.EventCount != want {
		t.Errorf("EventCount = %d, want %d", got.EventCount, want)
	}
}

// TestDroppedReportsTheCollectorCounter is the coverage-incomplete signal:
// without a wired counter the rollup reports 0, with one it reports the
// collector's live value (proposal §2.9).
func TestDroppedReportsTheCollectorCounter(t *testing.T) {
	unwired := New(logr.Discard())
	if got := unwired.Dropped(); got != 0 {
		t.Errorf("Dropped() without a counter = %d, want 0", got)
	}

	var drops int64
	wired := New(logr.Discard(), WithDroppedCounter(func() int64 { return drops }))
	drops = 42
	if got := wired.Dropped(); got != 42 {
		t.Errorf("Dropped() = %d, want 42", got)
	}
}

// TestProvidersDeduplicatesAcrossWorkloads covers the headline provider list.
func TestProvidersDeduplicatesAcrossWorkloads(t *testing.T) {
	r := newTestRollup(t, newFakeClock(baseTime))
	r.Record(aiEvent("a", "Deployment", "one", &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM, Provider: "openai"}))
	r.Record(aiEvent("b", "Deployment", "two", &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM, Provider: "openai"}))
	r.Record(aiEvent("b", "Deployment", "two", &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM, Provider: "anthropic"}))

	if diff := cmp.Diff([]string{"anthropic", "openai"}, r.Providers()); diff != "" {
		t.Errorf("Providers() (-want +got):\n%s", diff)
	}
}

// TestRollupIsRaceFreeUnderConcurrentRecordAndSnapshot exercises the lock; it is
// meaningful only under -race, which CI runs.
func TestRollupIsRaceFreeUnderConcurrentRecordAndSnapshot(t *testing.T) {
	r := newTestRollup(t, newFakeClock(baseTime))

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				r.Record(aiEvent("ns", "Deployment", fmt.Sprintf("agent-%d", i),
					&runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM, Provider: "openai"}))
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = r.Snapshot()
				_ = r.Providers()
			}
		}()
	}
	wg.Wait()

	if got := len(r.Snapshot()); got != 4 {
		t.Errorf("Snapshot() returned %d workloads, want 4", got)
	}
}
