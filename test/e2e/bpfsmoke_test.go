package e2e_test

import (
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/nirmata/runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/runtime/pkg/bpf/lsm"
	"github.com/nirmata/runtime/pkg/bpf/protofilter"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/runtimeevent"
	"github.com/nirmata/runtime/pkg/utils"

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

// TestBPFProtocolMapsRoundTrip programs the protocol maps through the same
// calls egressmgr makes and reads them back. Verifier acceptance is
// TestBPFVerify's job; what this adds is that the loaded maps are usable from
// Go.
func TestBPFProtocolMapsRoundTrip(t *testing.T) {
	requireBPFCapableHost(t)

	logger := logr.Discard()
	f, err := protofilter.New(&logger)
	if err != nil {
		t.Fatalf("loading protoclassifier objects: %+v", err)
	}

	// Load alone does not prove the maps are usable. Program allow and deny
	// targets and read the flag back: this is the same path a manager takes.
	rejected, err := f.AddProtocols(&compiler.AllowDenyPair{
		Allow: []string{"tls/h2", "ssh"},
		Deny:  []string{"*", "http/2"},
	})
	if err != nil {
		t.Fatalf("programming protocol maps: %v", err)
	}
	if len(rejected) != 0 {
		t.Errorf("unexpected rejected targets for valid protocol tokens: %v", rejected)
	}

	f.SetFlagIdx(protofilter.DEFAULT_DENY, true)
	on, err := f.FlagIdx(protofilter.DEFAULT_DENY)
	if err != nil {
		t.Fatalf("reading DEFAULT_DENY flag: %v", err)
	}
	if !on {
		t.Error("DEFAULT_DENY flag did not stick after SetFlagIdx(true)")
	}

	f.SetFlagIdx(protofilter.OBSERVE, true)
	if _, err := f.ReadProtoEvents(); err != nil {
		t.Errorf("reading proto_events with OBSERVE set: %v", err)
	}

	// The observation round trip pins the Go<->BTF key layout: a synthetic
	// {tls, h2, deny} entry is written through the map handle and must come
	// back from ReadProtoEvents with the ALPN and decision intact. cilium/ebpf
	// rejects a Put or Iterate whose Go key size does not match the loaded
	// map's BTF key, so this is exactly the seam a key-struct marshaling bug
	// hides in. It cannot prove packet-driven counting — no packet traverses
	// the program here.
	seed := protofilter.Target{Protocol: compiler.ProtocolTLS, ALPN: "h2"}
	if err := f.SeedProtoEvent(seed, runtimeevent.DecisionDeny, 4); err != nil {
		t.Fatalf("seeding a synthetic deny observation: %v", err)
	}
	events, err := f.ReadProtoEvents()
	if err != nil {
		t.Fatalf("reading back the seeded observation: %v", err)
	}
	key := protofilter.ProtoEventKey{
		Protocol: compiler.ProtocolTLS,
		ALPN:     "h2",
		Decision: runtimeevent.DecisionDeny,
	}
	if got := events[key]; got != 4 {
		t.Errorf("ReadProtoEvents()[%v] = %d, want 4 (full map: %v)", key, got, events)
	}
	// the read resets: the entry must not be reported twice
	again, err := f.ReadProtoEvents()
	if err != nil {
		t.Fatalf("second ReadProtoEvents: %v", err)
	}
	if got, ok := again[key]; ok {
		t.Errorf("seeded entry survived the destructive read with count %d", got)
	}

	if _, err := f.DeleteProtocols(&compiler.AllowDenyPair{Allow: []string{"tls/h2"}}); err != nil {
		t.Errorf("removing an allow target: %v", err)
	}
}

// ipv4UDPPacket builds a BPF_PROG_TEST_RUN input packet: Ethernet header
// (which the kernel strips via eth_type_trans, so the program sees data
// starting at L3 exactly as cgroup_skb does), IPv4 header, UDP header,
// payload. Checksums stay zero; neither the test run nor the classifier
// validates them.
func ipv4UDPPacket(srcHost byte, sport, dport uint16, payload []byte) []byte {
	return ipv4Packet(17, srcHost, append([]byte{
		byte(sport >> 8), byte(sport), byte(dport >> 8), byte(dport),
		byte((8 + len(payload)) >> 8), byte(8 + len(payload)), 0, 0,
	}, payload...))
}

// ipv4TCPPacket builds a first-data-segment shape: a 20-byte TCP header (data
// offset 5, ACK+PSH) followed by payload.
func ipv4TCPPacket(srcHost byte, sport, dport uint16, payload []byte) []byte {
	tcp := []byte{
		byte(sport >> 8), byte(sport), byte(dport >> 8), byte(dport),
		0, 0, 0, 1, // seq
		0, 0, 0, 1, // ack
		0x50, 0x18, // data offset 5, ACK|PSH
		0x20, 0x00, // window
		0, 0, // checksum
		0, 0, // urgent
	}
	return ipv4Packet(6, srcHost, append(tcp, payload...))
}

func ipv4Packet(l4proto, srcHost byte, l4 []byte) []byte {
	eth := []byte{
		0, 0, 0, 0, 0, 2, // dst MAC
		0, 0, 0, 0, 0, 1, // src MAC
		0x08, 0x00, // ethertype IPv4
	}
	total := 20 + len(l4)
	ip := []byte{
		0x45, 0,
		byte(total >> 8), byte(total),
		0, 0, 0, 0, // id, frag_off
		64, l4proto,
		0, 0, // checksum
		192, 0, 2, srcHost,
		198, 51, 100, 1,
	}
	return append(append(eth, ip...), l4...)
}

// dnsQueryPayload is a well-formed single-question query: RD set, opcode 0,
// QR clear, QDCOUNT 1, ANCOUNT 0, QNAME example.com, QTYPE A, QCLASS IN.
func dnsQueryPayload() []byte {
	return []byte{
		0x12, 0x34, // id
		0x01, 0x00, // flags: RD
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
}

// clientHelloPayload is a minimal TLS 1.2/1.3 ClientHello record with no
// extensions, which classifies as bare tls.
func clientHelloPayload() []byte {
	body := []byte{0x01, 0x00, 0x00, 0x2b, 0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body,
		0x00,                   // session_id length
		0x00, 0x02, 0x13, 0x01, // cipher_suites: TLS_AES_128_GCM_SHA256
		0x01, 0x00, // compression_methods: null
		0x00, 0x00, // extensions length
	)
	return append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(body))}, body...)
}

// TestBPFProtocolClassifierClassifiesPackets drives synthetic packets through
// the loaded proto_egress program with BPF_PROG_TEST_RUN and pins the
// classification verdicts under a default-deny allow list. Every packet gets
// its own source port so the flow LRU cache can never reuse a verdict across
// cases.
func TestBPFProtocolClassifierClassifiesPackets(t *testing.T) {
	requireBPFCapableHost(t)

	logger := logr.Discard()
	f, err := protofilter.New(&logger)
	if err != nil {
		t.Fatalf("loading protoclassifier objects: %+v", err)
	}

	if rejected, err := f.AddProtocols(&compiler.AllowDenyPair{Allow: []string{"dns"}}); err != nil || len(rejected) != 0 {
		t.Fatalf("programming allow {dns}: err=%v rejected=%v", err, rejected)
	}
	f.SetFlagIdx(protofilter.DEFAULT_DENY, true)

	// A DNS header whose QNAME label chain runs past the segment end: the walk
	// must classify it unclassified, not guess dns.
	unterminated := append(dnsQueryPayload()[:12], 0x3f, 'a', 'a', 'a')

	// A response flips QR; only queries are dns.
	response := dnsQueryPayload()
	response[2] |= 0x80

	tests := []struct {
		name   string
		packet []byte
		want   uint32
	}{
		{
			name:   "well-formed DNS query passes under allow dns",
			packet: ipv4UDPPacket(10, 40001, 53, dnsQueryPayload()),
			want:   1,
		},
		{
			name:   "DNS response is unclassified and drops under default deny",
			packet: ipv4UDPPacket(10, 40002, 53, response),
			want:   0,
		},
		{
			name:   "unterminated QNAME is unclassified and drops under default deny",
			packet: ipv4UDPPacket(10, 40003, 53, unterminated),
			want:   0,
		},
		{
			name:   "DNS-over-TLS ClientHello is tls, not dns: drops under allow dns",
			packet: ipv4TCPPacket(10, 40004, 853, clientHelloPayload()),
			want:   0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := f.RunPacket(tc.packet)
			if err != nil {
				t.Fatalf("RunPacket: %v", err)
			}
			if got != tc.want {
				t.Errorf("verdict = %d, want %d", got, tc.want)
			}
		})
	}

	if rejected, err := f.AddProtocols(&compiler.AllowDenyPair{Allow: []string{"tls"}}); err != nil || len(rejected) != 0 {
		t.Fatalf("programming allow {tls}: err=%v rejected=%v", err, rejected)
	}
	t.Run("DNS-over-TLS ClientHello passes once tls is allowed", func(t *testing.T) {
		got, err := f.RunPacket(ipv4TCPPacket(11, 40005, 853, clientHelloPayload()))
		if err != nil {
			t.Fatalf("RunPacket: %v", err)
		}
		if got != 1 {
			t.Errorf("verdict = %d, want 1", got)
		}
	})
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
			d, err := lsm.NewDispatcherForTarget(target)
			if err != nil {
				t.Fatalf("loading dispatcher for %q: %+v", target, err)
			}
			// Attaching proves the kernel accepted the program for this hook,
			// which is the assertion the map writes alone do not make.
			if err := d.Attach(); err != nil {
				t.Fatalf("attaching %q: %+v", target, err)
			}

			enf, err := lsm.NewForAttachTarget(d, &logger, target)
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
		})
	}
}
