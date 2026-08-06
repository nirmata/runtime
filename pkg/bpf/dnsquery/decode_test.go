package dnsquery

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

// record builds the bytes the kernel writes. Offsets are spelled out numerically
// rather than through the package constants, so a layout change has to break this
// fixture instead of silently following the decoder.
type record struct {
	cgroupID uint64
	nameLen  uint32 // zero means "derive from wire, counting the root byte"
	wire     []byte
	pad      int
}

func (r record) bytes() []byte {
	b := make([]byte, 140+r.pad)
	binary.LittleEndian.PutUint64(b[0:8], r.cgroupID)
	n := r.nameLen
	if n == 0 {
		n = uint32(len(r.wire)) + 1
	}
	binary.LittleEndian.PutUint32(b[8:12], n)
	copy(b[12:140], r.wire)
	return b
}

// wireName encodes labels as they appear in a question: each prefixed by its
// length, with no terminating root byte (the kernel leaves that as zero padding).
func wireName(labels ...string) []byte {
	var out []byte
	for _, l := range labels {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return out
}

func TestDecodeQueryEvent(t *testing.T) {
	// 63+63 labels leave room for one more label plus the root byte inside the
	// 128-byte key: the longest question this record can carry.
	longLabels := []string{strings.Repeat("a", 63), strings.Repeat("b", 61)}
	longWire := wireName(longLabels...)
	if len(longWire)+1 > MaxName {
		t.Fatalf("fixture bug: wire name is %d bytes, cap is %d", len(longWire)+1, MaxName)
	}

	tests := []struct {
		name string
		rec  record
		want runtimeevent.Event
	}{
		{
			name: "hosted provider question",
			rec: record{
				cgroupID: 0x0807060504030201,
				wire:     wireName("api", "openai", "com"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindDNS,
				CgroupID: 0x0807060504030201,
				Count:    1,
				DNS:      &runtimeevent.DNSFacts{QName: "api.openai.com"},
			},
		},
		{
			name: "single label",
			rec:  record{cgroupID: 7, wire: wireName("ollama")},
			want: runtimeevent.Event{
				Kind: runtimeevent.KindDNS, CgroupID: 7, Count: 1,
				DNS: &runtimeevent.DNSFacts{QName: "ollama"},
			},
		},
		{
			name: "longest name the key holds",
			rec:  record{cgroupID: 9, wire: longWire},
			want: runtimeevent.Event{
				Kind: runtimeevent.KindDNS, CgroupID: 9, Count: 1,
				DNS: &runtimeevent.DNSFacts{QName: strings.Join(longLabels, ".")},
			},
		},
		{
			name: "root question decodes to an empty name",
			rec:  record{cgroupID: 3, nameLen: 1},
			want: runtimeevent.Event{
				Kind: runtimeevent.KindDNS, CgroupID: 3, Count: 1,
				DNS: &runtimeevent.DNSFacts{QName: ""},
			},
		},
		{
			name: "trailing struct padding is ignored",
			rec:  record{cgroupID: 5, wire: wireName("a", "b"), pad: 4},
			want: runtimeevent.Event{
				Kind: runtimeevent.KindDNS, CgroupID: 5, Count: 1,
				DNS: &runtimeevent.DNSFacts{QName: "a.b"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeQueryEvent(tc.rec.bytes())
			if err != nil {
				t.Fatalf("DecodeQueryEvent() error = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("DecodeQueryEvent() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecodeQueryEventErrors(t *testing.T) {
	full := record{cgroupID: 1, wire: wireName("a", "b")}.bytes()

	tests := []struct {
		name    string
		in      []byte
		wantErr error
	}{
		{name: "nil buffer", in: nil, wantErr: ErrTruncated},
		{name: "empty buffer", in: []byte{}, wantErr: ErrTruncated},
		{name: "one byte short", in: full[:len(full)-1], wantErr: ErrTruncated},
		{name: "header only", in: full[:12], wantErr: ErrTruncated},
		{
			name:    "name_len beyond the key width",
			in:      record{nameLen: MaxName + 1, wire: wireName("a")}.bytes(),
			wantErr: ErrBadName,
		},
		{
			name:    "label longer than the remaining bytes",
			in:      record{nameLen: 5, wire: []byte{9, 'a', 'b', 'c'}}.bytes(),
			wantErr: ErrBadName,
		},
		{
			name:    "compression pointer is not legal in a question",
			in:      record{nameLen: 3, wire: []byte{0xc0, 0x0c}}.bytes(),
			wantErr: ErrBadName,
		},
		{
			name:    "reserved label type",
			in:      record{nameLen: 3, wire: []byte{0x40, 'a'}}.bytes(),
			wantErr: ErrBadName,
		},
		{
			name:    "empty label mid sequence",
			in:      record{nameLen: 6, wire: append(wireName("api"), 0x00, 'x')}.bytes(),
			wantErr: ErrBadName,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeQueryEvent(tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecodeQueryEvent() error = %v, want %v", err, tc.wantErr)
			}
			if diff := cmp.Diff(runtimeevent.Event{}, got); diff != "" {
				t.Errorf("DecodeQueryEvent() returned a partial event on error (-want +got):\n%s", diff)
			}
		})
	}
}

// The C writes host-order scalars and bpf2go targets little-endian, so a
// hand-written byte pattern must decode to these exact numbers.
func TestDecodeQueryEventIsLittleEndian(t *testing.T) {
	b := make([]byte, EventSize)
	copy(b[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	copy(b[8:12], []byte{0x03, 0x00, 0x00, 0x00}) // name_len 3
	copy(b[12:14], []byte{0x01, 'z'})

	got, err := DecodeQueryEvent(b)
	if err != nil {
		t.Fatalf("DecodeQueryEvent() error = %v", err)
	}
	want := runtimeevent.Event{
		Kind:     runtimeevent.KindDNS,
		CgroupID: 0x8877665544332211,
		Count:    1,
		DNS:      &runtimeevent.DNSFacts{QName: "z"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("DecodeQueryEvent() mismatch (-want +got):\n%s", diff)
	}
}

// Kernel-supplied bytes are untrusted input: the hard rule is an error, never a
// panic.
func TestDecodeQueryEventNeverPanics(t *testing.T) {
	full := record{cgroupID: 1, wire: wireName("api", "anthropic", "com")}.bytes()

	for i := 0; i <= len(full); i++ {
		if _, err := DecodeQueryEvent(full[:i]); err == nil && i < EventSize {
			t.Fatalf("DecodeQueryEvent(prefix of %d bytes) unexpectedly succeeded", i)
		}
	}

	// Every possible label-length byte: rejecting is fine, crashing is not.
	for v := 0; v < 256; v++ {
		rec := record{nameLen: 4, wire: []byte{byte(v), byte(v), byte(v)}}
		_, _ = DecodeQueryEvent(rec.bytes())
	}
}

// The value schema caps a policy-declared name at what this record can carry.
// If the key width changes and the schema does not, admission starts accepting
// names the observer can never produce, and a policy naming one matches nothing
// while looking correct.
func TestNameCapAgreesWithTheValueSchema(t *testing.T) {
	// Wire form is two bytes longer than the dotted name: every dot becomes a
	// length prefix, plus a leading prefix and a trailing root byte.
	if got, want := compiler.MaxDNSNameLen+2, MaxName; got != want {
		t.Errorf("the schema admits %d-character names, needing %d bytes, but the record holds %d",
			compiler.MaxDNSNameLen, got, want)
	}
}
