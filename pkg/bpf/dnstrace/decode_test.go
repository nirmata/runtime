package dnstrace

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

// dnsRecord builds a kernel record byte-for-byte the way _cprog/dns.bpf.c
// writes it. Field offsets are spelled out numerically (not via the package
// constants) so a layout change has to break this fixture, not silently follow
// the decoder.
type dnsRecord struct {
	cgroupID uint64
	pid      uint32
	qtype    uint16
	qnameLen uint16 // if nil-ish (0) and wire is set, len(wire) is used
	comm     []byte
	wire     []byte
	pad      int // extra trailing bytes (C struct padding)
}

func (r dnsRecord) bytes() []byte {
	b := make([]byte, 285+r.pad)
	binary.LittleEndian.PutUint64(b[0:8], r.cgroupID)
	binary.LittleEndian.PutUint32(b[8:12], r.pid)
	binary.LittleEndian.PutUint16(b[12:14], r.qtype)
	n := r.qnameLen
	if n == 0 {
		n = uint16(len(r.wire))
	}
	binary.LittleEndian.PutUint16(b[14:16], n)
	copy(b[16:32], r.comm)
	copy(b[32:285], r.wire)
	return b
}

// wireName encodes labels the way they appear in a DNS question, without the
// terminating root byte (the kernel stops copying there).
func wireName(labels ...string) []byte {
	var out []byte
	for _, l := range labels {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return out
}

func TestDecodeDNSEvent(t *testing.T) {
	// 63+63+63+60 labels => 4 length bytes + 249 label bytes = 253 wire bytes,
	// exactly MaxQName, the longest question the kernel can deliver.
	maxLabels := []string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 60),
	}
	maxWire := wireName(maxLabels...)
	if len(maxWire) != MaxQName {
		t.Fatalf("fixture bug: max wire name is %d bytes, want %d", len(maxWire), MaxQName)
	}

	tests := []struct {
		name string
		rec  dnsRecord
		want runtimeevent.Event
	}{
		{
			name: "hosted provider A query",
			rec: dnsRecord{
				cgroupID: 0x0807060504030201,
				pid:      4242,
				qtype:    1,
				comm:     []byte("python3\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
				wire:     wireName("api", "openai", "com"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindDNS,
				CgroupID: 0x0807060504030201,
				PID:      4242,
				Comm:     "python3",
				Count:    1,
				DNS:      &runtimeevent.DNSFacts{QName: "api.openai.com", QType: 1},
			},
		},
		{
			name: "single label and AAAA qtype",
			rec: dnsRecord{
				cgroupID: 7,
				pid:      1,
				qtype:    28,
				comm:     []byte("curl"),
				wire:     wireName("ollama"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindDNS,
				CgroupID: 7,
				PID:      1,
				Comm:     "curl",
				Count:    1,
				DNS:      &runtimeevent.DNSFacts{QName: "ollama", QType: 28},
			},
		},
		{
			name: "maximum length qname",
			rec: dnsRecord{
				cgroupID: 9,
				qtype:    1,
				comm:     []byte("node"),
				wire:     maxWire,
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindDNS,
				CgroupID: 9,
				Comm:     "node",
				Count:    1,
				DNS:      &runtimeevent.DNSFacts{QName: strings.Join(maxLabels, "."), QType: 1},
			},
		},
		{
			name: "root query decodes to empty name",
			rec: dnsRecord{
				cgroupID: 3,
				qtype:    2,
				comm:     []byte("dig"),
				wire:     nil,
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindDNS,
				CgroupID: 3,
				Comm:     "dig",
				Count:    1,
				DNS:      &runtimeevent.DNSFacts{QName: "", QType: 2},
			},
		},
		{
			name: "comm without NUL terminator keeps all 16 bytes",
			rec: dnsRecord{
				cgroupID: 1,
				qtype:    1,
				comm:     []byte("0123456789abcdef"),
				wire:     wireName("x"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindDNS,
				CgroupID: 1,
				Comm:     "0123456789abcdef",
				Count:    1,
				DNS:      &runtimeevent.DNSFacts{QName: "x", QType: 1},
			},
		},
		{
			name: "trailing struct padding is ignored",
			rec: dnsRecord{
				cgroupID: 5,
				qtype:    1,
				comm:     []byte("sh"),
				wire:     wireName("a", "b"),
				pad:      3, // sizeof(struct dns_event) == 288
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindDNS,
				CgroupID: 5,
				Comm:     "sh",
				Count:    1,
				DNS:      &runtimeevent.DNSFacts{QName: "a.b", QType: 1},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeDNSEvent(tc.rec.bytes())
			if err != nil {
				t.Fatalf("DecodeDNSEvent() error = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("DecodeDNSEvent() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecodeDNSEvent_Errors(t *testing.T) {
	full := dnsRecord{cgroupID: 1, qtype: 1, comm: []byte("sh"), wire: wireName("a")}.bytes()

	tests := []struct {
		name    string
		in      []byte
		wantErr error
	}{
		{name: "nil buffer", in: nil, wantErr: ErrTruncated},
		{name: "empty buffer", in: []byte{}, wantErr: ErrTruncated},
		{name: "one byte short", in: full[:len(full)-1], wantErr: ErrTruncated},
		{name: "header only", in: full[:32], wantErr: ErrTruncated},
		{
			name:    "qname_len beyond maximum",
			in:      dnsRecord{qnameLen: MaxQName + 1, wire: wireName("a")}.bytes(),
			wantErr: ErrBadQName,
		},
		{
			name:    "label longer than remaining bytes",
			in:      dnsRecord{qnameLen: 4, wire: []byte{9, 'a', 'b', 'c'}}.bytes(),
			wantErr: ErrBadQName,
		},
		{
			name:    "compression pointer is not valid in a question",
			in:      dnsRecord{wire: []byte{0xc0, 0x0c}}.bytes(),
			wantErr: ErrBadQName,
		},
		{
			name:    "reserved label type",
			in:      dnsRecord{wire: []byte{0x40, 'a'}}.bytes(),
			wantErr: ErrBadQName,
		},
		{
			name:    "empty label mid sequence",
			in:      dnsRecord{wire: append(wireName("api"), 0x00, 'x')}.bytes(),
			wantErr: ErrBadQName,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeDNSEvent(tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecodeDNSEvent() error = %v, want %v", err, tc.wantErr)
			}
			if diff := cmp.Diff(runtimeevent.Event{}, got); diff != "" {
				t.Errorf("DecodeDNSEvent() returned a partial event on error (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDecodeDNSEvent_LittleEndian pins the byte order of every scalar field:
// the C side writes host-order values and bpf2go targets little-endian, so a
// hand-written byte pattern must decode to these exact numbers.
func TestDecodeDNSEvent_LittleEndian(t *testing.T) {
	b := make([]byte, EventSize)
	copy(b[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	copy(b[8:12], []byte{0x0d, 0x00, 0x00, 0x00})
	copy(b[12:14], []byte{0x1c, 0x00}) // qtype 28
	copy(b[14:16], []byte{0x02, 0x00}) // qname_len 2
	copy(b[16:32], []byte("go"))
	copy(b[32:34], []byte{0x01, 'z'})

	got, err := DecodeDNSEvent(b)
	if err != nil {
		t.Fatalf("DecodeDNSEvent() error = %v", err)
	}
	want := runtimeevent.Event{
		Kind:     runtimeevent.KindDNS,
		CgroupID: 0x8877665544332211,
		PID:      13,
		Comm:     "go",
		Count:    1,
		DNS:      &runtimeevent.DNSFacts{QName: "z", QType: 28},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("DecodeDNSEvent() mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodeDNSEvent_NeverPanics feeds every truncation of a valid record plus a
// range of adversarial qname bytes through the decoder. Kernel-supplied bytes
// are untrusted input: the hard rule is an error, never a panic.
func TestDecodeDNSEvent_NeverPanics(t *testing.T) {
	full := dnsRecord{
		cgroupID: 1, pid: 2, qtype: 1,
		comm: []byte("fuzz"),
		wire: wireName("api", "anthropic", "com"),
	}.bytes()

	for i := 0; i <= len(full); i++ {
		if _, err := DecodeDNSEvent(full[:i]); err == nil && i < EventSize {
			t.Fatalf("DecodeDNSEvent(prefix of %d bytes) unexpectedly succeeded", i)
		}
	}

	// Every possible label-length byte: rejecting is fine, crashing is not.
	for v := 0; v < 256; v++ {
		rec := dnsRecord{qnameLen: 3, wire: []byte{byte(v), byte(v), byte(v)}}
		_, _ = DecodeDNSEvent(rec.bytes())
	}
}
