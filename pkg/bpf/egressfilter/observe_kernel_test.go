package egressfilter

import (
	"net/netip"
	"os"
	"testing"

	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
)

// TestReadIPEventsRoundTripsTheKernelKey pins the Go<->BTF key layout against a
// loaded map: cilium/ebpf rejects a Put or Iterate whose Go key size does not
// match the map's BTF key, so this is the seam a key-struct marshaling bug
// hides in. It cannot prove packet-driven counting — no packet traverses the
// program here; that needs the kind-based egress lane.
func TestReadIPEventsRoundTripsTheKernelKey(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}

	logger := logr.Discard()
	f, err := New(&logger)
	if err != nil {
		t.Fatalf("loading egressblock objects: %+v", err)
	}

	f.SetObserve(true)

	addr := netip.MustParseAddr("192.0.2.55")
	daddr, ok := addrKey(addr)
	if !ok {
		t.Fatalf("addrKey(%s) rejected an IPv4 address", addr)
	}
	seeded := ipEventKernelKey{Daddr: daddr, Decision: uint32(runtimeevent.DecisionDeny)}
	count := uint32(4)
	if err := f.bpfObjs.IpEvents.Put(&seeded, &count); err != nil {
		t.Fatalf("seeding a synthetic deny observation: %v", err)
	}

	events, err := f.ReadIPEvents()
	if err != nil {
		t.Fatalf("reading back the seeded observation: %v", err)
	}
	key := IPEventKey{Addr: addr, Decision: runtimeevent.DecisionDeny}
	if got := events[key]; got != count {
		t.Errorf("ReadIPEvents()[%v] = %d, want %d (full map: %v)", key, got, count, events)
	}

	// the read resets: the entry must not be reported twice
	again, err := f.ReadIPEvents()
	if err != nil {
		t.Fatalf("second ReadIPEvents: %v", err)
	}
	if got, ok := again[key]; ok {
		t.Errorf("seeded entry survived the destructive read with count %d", got)
	}
}
