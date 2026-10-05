package egressfilter

import (
	"net/netip"
	"os"
	"testing"

	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
)

// testPacket builds a BPF_PROG_TEST_RUN input carrying an IP header addressed
// to dst. It starts at the Ethernet header: the kernel derives skb->protocol
// from the ethertype and strips it, so the program reads from L3 as it does on
// the cgroup hook.
func testPacket(dst netip.Addr) []byte {
	eth := []byte{0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1}
	if dst.Is4() {
		d := dst.As4()
		ip := []byte{
			0x45, 0, 0, 20,
			0, 0, 0, 0,
			64, 17, 0, 0,
			192, 0, 2, 1,
			d[0], d[1], d[2], d[3],
		}
		return append(append(eth, 0x08, 0x00), ip...)
	}
	d := dst.As16()
	ip := []byte{0x60, 0, 0, 0, 0, 0, 17, 64}
	ip = append(ip, netip.MustParseAddr("2001:db8::100").AsSlice()...)
	ip = append(ip, d[:]...)
	return append(append(eth, 0x86, 0xdd), ip...)
}

func TestEgressProgramEnforcesBothFamilies(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}

	logger := logr.Discard()
	f, err := New(&logger)
	if err != nil {
		t.Fatalf("loading egressblock objects: %+v", err)
	}

	rejected, err := f.AddIps(&compiler.AllowDenyPair{
		Allow: []string{"192.0.2.0/24", "2001:db8:a::/48"},
		Deny:  []string{"192.0.2.9", "2001:db8:a::9"},
	})
	if err != nil || len(rejected) != 0 {
		t.Fatalf("programming egress maps: err=%v rejected=%v", err, rejected)
	}
	f.SetFlagIdx(DEFAULT_DENY, true)
	f.SetObserve(true)

	tests := []struct {
		dst  string
		want runtimeevent.KernelDecision
	}{
		{dst: "192.0.2.7", want: runtimeevent.DecisionAllow},
		{dst: "192.0.2.9", want: runtimeevent.DecisionDeny},
		{dst: "198.51.100.1", want: runtimeevent.DecisionDeny},
		{dst: "2001:db8:a::7", want: runtimeevent.DecisionAllow},
		{dst: "2001:db8:a::9", want: runtimeevent.DecisionDeny},
		{dst: "2001:db8:b::1", want: runtimeevent.DecisionDeny},
	}
	for _, tc := range tests {
		dst := netip.MustParseAddr(tc.dst)
		got, err := f.bpfObjs.CgroupEgress.Run(&ebpf.RunOptions{Data: testPacket(dst)})
		if err != nil {
			t.Fatalf("running a packet to %s: %v", dst, err)
		}
		if want := uint32(1 - tc.want); got != want {
			t.Errorf("verdict for %s = %d, want %d", dst, got, want)
		}
	}

	events, err := f.ReadIPEvents()
	if err != nil {
		t.Fatalf("reading observations: %v", err)
	}
	for _, tc := range tests {
		key := IPEventKey{Addr: netip.MustParseAddr(tc.dst), Decision: tc.want}
		if events[key] != 1 {
			t.Errorf("observations[%v] = %d, want 1 (full map: %v)", key, events[key], events)
		}
	}
}

// ::/0 must not reach IPv4 traffic: the family leads the trie key.
func TestEgressProgramKeepsPrefixesWithinTheirFamily(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load BPF programs")
	}

	logger := logr.Discard()
	f, err := New(&logger)
	if err != nil {
		t.Fatalf("loading egressblock objects: %+v", err)
	}
	if _, err := f.AddIps(&compiler.AllowDenyPair{Deny: []string{"::/0"}}); err != nil {
		t.Fatalf("programming egress maps: %v", err)
	}

	for dst, want := range map[string]uint32{"192.0.2.7": 1, "2001:db8::7": 0} {
		got, err := f.bpfObjs.CgroupEgress.Run(&ebpf.RunOptions{Data: testPacket(netip.MustParseAddr(dst))})
		if err != nil {
			t.Fatalf("running a packet to %s: %v", dst, err)
		}
		if got != want {
			t.Errorf("verdict for %s = %d, want %d", dst, got, want)
		}
	}
}
