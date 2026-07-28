package netflow

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

// netip.Addr holds unexported state, so cmp needs an explicit comparer.
var addrCmp = cmp.Comparer(func(a, b netip.Addr) bool { return a == b })

// flowRecord builds a kernel record byte-for-byte the way
// _cprog/netflow.bpf.c writes it. Offsets are spelled out numerically so a
// layout change breaks the fixture instead of silently following the decoder.
type flowRecord struct {
	cgroupID uint64
	pid      uint32
	saddr    []byte
	daddr    []byte
	dport    uint16
	proto    uint8
	ipVer    uint8
	comm     []byte
	pad      int
}

func (r flowRecord) bytes() []byte {
	b := make([]byte, 64+r.pad)
	binary.LittleEndian.PutUint64(b[0:8], r.cgroupID)
	binary.LittleEndian.PutUint32(b[8:12], r.pid)
	copy(b[12:28], r.saddr)
	copy(b[28:44], r.daddr)
	binary.LittleEndian.PutUint16(b[44:46], r.dport)
	b[46] = r.proto
	b[47] = r.ipVer
	copy(b[48:64], r.comm)
	return b
}

func v4(a, b, c, d byte) []byte { return []byte{a, b, c, d} }

func TestDecodeFlowEvent(t *testing.T) {
	tests := []struct {
		name string
		rec  flowRecord
		want runtimeevent.Event
	}{
		{
			name: "ipv4 tcp 443",
			rec: flowRecord{
				cgroupID: 0x0102030405060708,
				pid:      31337,
				saddr:    v4(10, 244, 1, 7),
				daddr:    v4(104, 18, 6, 192),
				dport:    443,
				proto:    protoTCP,
				ipVer:    4,
				comm:     []byte("python3\x00junkjunk"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindNet,
				CgroupID: 0x0102030405060708,
				PID:      31337,
				Comm:     "python3",
				Count:    1,
				Net: &runtimeevent.NetFacts{
					DestIP:   netip.AddrFrom4([4]byte{104, 18, 6, 192}),
					DestPort: 443,
					Protocol: "tcp",
				},
			},
		},
		{
			name: "ipv4 udp 53",
			rec: flowRecord{
				cgroupID: 2,
				pid:      9,
				saddr:    v4(10, 244, 1, 7),
				daddr:    v4(10, 96, 0, 10),
				dport:    53,
				proto:    protoUDP,
				ipVer:    4,
				comm:     []byte("coredns"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindNet,
				CgroupID: 2,
				PID:      9,
				Comm:     "coredns",
				Count:    1,
				Net: &runtimeevent.NetFacts{
					DestIP:   netip.AddrFrom4([4]byte{10, 96, 0, 10}),
					DestPort: 53,
					Protocol: "udp",
				},
			},
		},
		{
			name: "ipv6 tcp",
			rec: flowRecord{
				cgroupID: 3,
				daddr:    netip.MustParseAddr("2606:4700::6812:6c0").AsSlice(),
				dport:    8080,
				proto:    protoTCP,
				ipVer:    6,
				comm:     []byte("node"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindNet,
				CgroupID: 3,
				Comm:     "node",
				Count:    1,
				Net: &runtimeevent.NetFacts{
					DestIP:   netip.MustParseAddr("2606:4700::6812:6c0"),
					DestPort: 8080,
					Protocol: "tcp",
				},
			},
		},
		{
			name: "ipv4 mapped ipv6 destination is unmapped",
			rec: flowRecord{
				cgroupID: 4,
				daddr:    netip.MustParseAddr("::ffff:104.18.6.192").AsSlice(),
				dport:    443,
				proto:    protoTCP,
				ipVer:    6,
				comm:     []byte("curl"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindNet,
				CgroupID: 4,
				Comm:     "curl",
				Count:    1,
				Net: &runtimeevent.NetFacts{
					DestIP:   netip.AddrFrom4([4]byte{104, 18, 6, 192}),
					DestPort: 443,
					Protocol: "tcp",
				},
			},
		},
		{
			name: "unknown protocol leaves Protocol empty",
			rec: flowRecord{
				cgroupID: 5,
				daddr:    v4(1, 1, 1, 1),
				dport:    0,
				proto:    132, // SCTP
				ipVer:    4,
				comm:     []byte("weird"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindNet,
				CgroupID: 5,
				Comm:     "weird",
				Count:    1,
				Net: &runtimeevent.NetFacts{
					DestIP:   netip.AddrFrom4([4]byte{1, 1, 1, 1}),
					Protocol: "",
				},
			},
		},
		{
			name: "comm without NUL terminator keeps all 16 bytes",
			rec: flowRecord{
				cgroupID: 6,
				daddr:    v4(8, 8, 8, 8),
				dport:    443,
				proto:    protoTCP,
				ipVer:    4,
				comm:     []byte("0123456789abcdef"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindNet,
				CgroupID: 6,
				Comm:     "0123456789abcdef",
				Count:    1,
				Net: &runtimeevent.NetFacts{
					DestIP:   netip.AddrFrom4([4]byte{8, 8, 8, 8}),
					DestPort: 443,
					Protocol: "tcp",
				},
			},
		},
		{
			name: "highest port number survives the round trip",
			rec: flowRecord{
				cgroupID: 7,
				daddr:    v4(127, 0, 0, 1),
				dport:    65535,
				proto:    protoTCP,
				ipVer:    4,
				comm:     []byte("x"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindNet,
				CgroupID: 7,
				Comm:     "x",
				Count:    1,
				Net: &runtimeevent.NetFacts{
					DestIP:   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
					DestPort: 65535,
					Protocol: "tcp",
				},
			},
		},
		{
			name: "trailing bytes beyond the layout are ignored",
			rec: flowRecord{
				cgroupID: 8,
				daddr:    v4(1, 2, 3, 4),
				dport:    11434,
				proto:    protoTCP,
				ipVer:    4,
				comm:     []byte("ollama"),
				pad:      16,
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindNet,
				CgroupID: 8,
				Comm:     "ollama",
				Count:    1,
				Net: &runtimeevent.NetFacts{
					DestIP:   netip.AddrFrom4([4]byte{1, 2, 3, 4}),
					DestPort: 11434,
					Protocol: "tcp",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeFlowEvent(tc.rec.bytes())
			if err != nil {
				t.Fatalf("DecodeFlowEvent() error = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, addrCmp); diff != "" {
				t.Errorf("DecodeFlowEvent() mismatch (-want +got):\n%s", diff)
			}
			if got.Net.Governed != nil {
				t.Errorf("Governed = %v, want nil: the decoder must not guess the governed bit", *got.Net.Governed)
			}
		})
	}
}

func TestDecodeFlowEvent_Errors(t *testing.T) {
	full := flowRecord{daddr: v4(1, 1, 1, 1), dport: 443, proto: protoTCP, ipVer: 4}.bytes()

	tests := []struct {
		name    string
		in      []byte
		wantErr error
	}{
		{name: "nil buffer", in: nil, wantErr: ErrTruncated},
		{name: "empty buffer", in: []byte{}, wantErr: ErrTruncated},
		{name: "one byte short", in: full[:len(full)-1], wantErr: ErrTruncated},
		{name: "addresses only", in: full[:44], wantErr: ErrTruncated},
		{
			name:    "ip version zero",
			in:      flowRecord{daddr: v4(1, 1, 1, 1), proto: protoTCP, ipVer: 0}.bytes(),
			wantErr: ErrBadIPVersion,
		},
		{
			name:    "ip version five",
			in:      flowRecord{daddr: v4(1, 1, 1, 1), proto: protoTCP, ipVer: 5}.bytes(),
			wantErr: ErrBadIPVersion,
		},
		{
			name:    "ip version 255",
			in:      flowRecord{daddr: v4(1, 1, 1, 1), proto: protoTCP, ipVer: 255}.bytes(),
			wantErr: ErrBadIPVersion,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeFlowEvent(tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecodeFlowEvent() error = %v, want %v", err, tc.wantErr)
			}
			if diff := cmp.Diff(runtimeevent.Event{}, got, addrCmp); diff != "" {
				t.Errorf("DecodeFlowEvent() returned a partial event on error (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDecodeFlowEvent_LittleEndian pins the byte order of every scalar field.
func TestDecodeFlowEvent_LittleEndian(t *testing.T) {
	b := make([]byte, EventSize)
	copy(b[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	copy(b[8:12], []byte{0x39, 0x30, 0x00, 0x00}) // 12345
	copy(b[28:32], []byte{192, 168, 0, 1})
	copy(b[44:46], []byte{0xbb, 0x01}) // 443, low byte first
	b[46] = protoTCP
	b[47] = 4
	copy(b[48:64], []byte("go"))

	got, err := DecodeFlowEvent(b)
	if err != nil {
		t.Fatalf("DecodeFlowEvent() error = %v", err)
	}
	want := runtimeevent.Event{
		Kind:     runtimeevent.KindNet,
		CgroupID: 0x8877665544332211,
		PID:      12345,
		Comm:     "go",
		Count:    1,
		Net: &runtimeevent.NetFacts{
			DestIP:   netip.AddrFrom4([4]byte{192, 168, 0, 1}),
			DestPort: 443,
			Protocol: "tcp",
		},
	}
	if diff := cmp.Diff(want, got, addrCmp); diff != "" {
		t.Errorf("DecodeFlowEvent() mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodeFlowEvent_NeverPanics walks every truncation of a valid record and
// every ip_ver value. Kernel bytes are untrusted: error, never panic.
func TestDecodeFlowEvent_NeverPanics(t *testing.T) {
	full := flowRecord{
		cgroupID: 1, pid: 2,
		saddr: v4(10, 0, 0, 1), daddr: v4(10, 0, 0, 2),
		dport: 443, proto: protoTCP, ipVer: 4, comm: []byte("fuzz"),
	}.bytes()

	for i := 0; i <= len(full); i++ {
		_, err := DecodeFlowEvent(full[:i])
		if i < EventSize && err == nil {
			t.Fatalf("DecodeFlowEvent(prefix of %d bytes) unexpectedly succeeded", i)
		}
	}

	for v := 0; v < 256; v++ {
		rec := flowRecord{daddr: v4(1, 1, 1, 1), ipVer: uint8(v), proto: uint8(v)}
		got, err := DecodeFlowEvent(rec.bytes())
		switch v {
		case 4, 6:
			if err != nil {
				t.Fatalf("ip_ver %d: unexpected error %v", v, err)
			}
			if !got.Net.DestIP.IsValid() {
				t.Fatalf("ip_ver %d: destination address is invalid", v)
			}
		default:
			if !errors.Is(err, ErrBadIPVersion) {
				t.Fatalf("ip_ver %d: error = %v, want ErrBadIPVersion", v, err)
			}
		}
	}
}
