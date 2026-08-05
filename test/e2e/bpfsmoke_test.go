package e2e_test

import (
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/go-logr/logr"
)

// requireBPFCapableHost skips unless we are root on Linux. Loading any BPF
// program needs CAP_BPF (or root) plus a Linux kernel; there is nothing
// meaningful to assert otherwise.
func requireBPFCapableHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("BPF program load requires linux, running on %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("BPF program load requires root/CAP_BPF; re-run under sudo")
	}
}

// TestBPFEgressMapsRoundTrip programs the egress maps through the same calls
// egressmgr makes and reads them back. Verifier acceptance is TestBPFVerify's
// job; what this adds is that the loaded maps are usable from Go.
func TestBPFEgressMapsRoundTrip(t *testing.T) {
	requireBPFCapableHost(t)

	logger := logr.Discard()
	f, err := egressfilter.New(&logger)
	if err != nil {
		// %+v renders *ebpf.VerifierError's full log, which is the whole point
		// of this test.
		t.Fatalf("loading egressblock objects: %+v", err)
	}

	// Load alone does not prove the maps are usable. Program one allow and one
	// deny target and read the flag back: this is the same path egressmgr takes.
	rejected, err := f.AddIps(&compiler.AllowDenyPair{
		Allow: []string{"10.0.0.1"},
		Deny:  []string{"10.0.0.2", "10.0.1.0/24"},
	})
	if err != nil {
		t.Fatalf("programming egress maps: %v", err)
	}
	if len(rejected) != 0 {
		t.Errorf("unexpected rejected targets for IPv4/CIDR-24 input: %v", rejected)
	}

	f.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
	on, err := f.FlagIdx(egressfilter.DEFAULT_DENY)
	if err != nil {
		t.Fatalf("reading DEFAULT_DENY flag: %v", err)
	}
	if !on {
		t.Error("DEFAULT_DENY flag did not stick after SetFlagIdx(true)")
	}

	f.SetFlagIdx(egressfilter.OBSERVE, true)
	if _, err := f.ReadIPEvents(); err != nil {
		t.Errorf("reading ip_events with OBSERVE set: %v", err)
	}

	// The observation round trip pins the Go<->BTF key layout: a synthetic
	// (addr, DecisionDeny) entry is written through the map handle and must
	// come back from ReadIPEvents with the decision intact. cilium/ebpf rejects
	// a Put or Iterate whose Go key size does not match the loaded map's BTF
	// key, so this is exactly the seam a key-struct marshaling bug hides in.
	// It cannot prove packet-driven counting — no packet traverses the
	// program here; that needs the kind-based egress lane.
	seedAddr := netip.MustParseAddr("192.0.2.55")
	if err := f.SeedIPEvent(seedAddr, runtimeevent.DecisionDeny, 4); err != nil {
		t.Fatalf("seeding a synthetic deny observation: %v", err)
	}
	events, err := f.ReadIPEvents()
	if err != nil {
		t.Fatalf("reading back the seeded observation: %v", err)
	}
	key := egressfilter.IPEventKey{Addr: seedAddr, Decision: runtimeevent.DecisionDeny}
	if got := events[key]; got != 4 {
		t.Errorf("ReadIPEvents()[%v] = %d, want 4 (full map: %v)", key, got, events)
	}
	// the read resets: the entry must not be reported twice
	again, err := f.ReadIPEvents()
	if err != nil {
		t.Fatalf("second ReadIPEvents: %v", err)
	}
	if got, ok := again[key]; ok {
		t.Errorf("seeded entry survived the destructive read with count %d", got)
	}

	if _, err := f.DeleteIps(&compiler.AllowDenyPair{Allow: []string{"10.0.0.1"}}); err != nil {
		t.Errorf("removing an allow target: %v", err)
	}
}

// TestBPFLsmAttaches programs targets into both LSM programs and attaches each
// to its hook, which is the assertion neither the map writes nor a bare load
// makes. A BPF_PROG_TYPE_LSM program cannot be loaded at all unless the kernel
// was booted with BPF-LSM active, so this skips by default and only hard-fails
// when the caller declares the host is supposed to support it.
func TestBPFLsmAttaches(t *testing.T) {
	required := os.Getenv("NIRMATA_RUNTIME_REQUIRE_BPF_LSM") == "1"

	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		if required {
			t.Fatalf("NIRMATA_RUNTIME_REQUIRE_BPF_LSM=1 but host is %s and euid %d (need linux + root)",
				runtime.GOOS, os.Geteuid())
		}
		requireBPFCapableHost(t)
	}

	enabled, err := utils.BpfLSMEnabled()
	switch {
	case err != nil && required:
		t.Fatalf("NIRMATA_RUNTIME_REQUIRE_BPF_LSM=1 but /sys/kernel/security/lsm is unreadable: %v", err)
	case err != nil:
		t.Skipf("cannot determine active LSMs: %v", err)
	case !enabled && required:
		t.Fatal("NIRMATA_RUNTIME_REQUIRE_BPF_LSM=1 but 'bpf' is not in /sys/kernel/security/lsm; " +
			"the kernel must be booted with lsm=...,bpf")
	case !enabled:
		t.Skip("kernel not booted with BPF-LSM ('bpf' absent from /sys/kernel/security/lsm); " +
			"the kernel must be booted with lsm=...,bpf -- hosted GitHub runners cannot satisfy this")
	}

	for _, target := range []string{lsm.PROG_TYPE_LSM_OPEN, lsm.PROG_TYPE_LSM_EXEC} {
		t.Run(target, func(t *testing.T) {
			logger := logr.Discard()
			enf, err := lsm.NewForAttachTarget(&logger, target)
			if err != nil {
				t.Fatalf("loading lsm objects for %q: %+v", target, err)
			}
			defer func() {
				if err := enf.Close(); err != nil {
					t.Errorf("closing enforcer: %v", err)
				}
			}()

			rejected, err := enf.AddTargets(&compiler.AllowDenyPair{Deny: []string{"/etc/shadow"}})
			if err != nil {
				t.Errorf("programming deny targets: %v", err)
			}
			if len(rejected) != 0 {
				t.Errorf("programming deny targets rejected %v", rejected)
			}
			if err := enf.SetDefaultDeny(false); err != nil {
				t.Errorf("clearing default deny: %v", err)
			}
			// Attaching proves the kernel accepted the program for this hook,
			// which is the assertion the map writes alone do not make.
			link, err := enf.Attach()
			if err != nil {
				t.Fatalf("attaching %q: %+v", target, err)
			}
			if err := link.Close(); err != nil {
				t.Errorf("detaching %q: %v", target, err)
			}
		})
	}
}
