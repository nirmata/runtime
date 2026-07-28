package tlspeek

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
)

// netip.Addr has unexported fields, so it needs an explicit comparer (same
// approach as pkg/runtimeevent's own tests).
var eventCmp = []cmp.Option{cmp.Comparer(func(a, b netip.Addr) bool { return a == b })}

// tlsRecord hand-assembles a tls_event exactly as the C struct writes it. It is
// the mirror of the offsets in decode.go: if this helper and the C ever
// disagree, every test in this file is wrong in the same direction, so the
// offsets are also asserted independently by TestEventLayoutOffsets.
type tlsRecord struct {
	cgroupID uint64
	pid      uint32
	dport    uint16
	sniLen   uint16 // written verbatim, may disagree with len(sni) on purpose
	alpnLen  uint16
	sni      []byte
	alpn     []byte
	comm     string
	// pad appends trailing bytes, as the real C struct's alignment padding and
	// the ring buffer's 8 byte record rounding do.
	pad int
}

func (r tlsRecord) bytes() []byte {
	b := make([]byte, EventSize+r.pad)
	binary.LittleEndian.PutUint64(b[offCgroupID:], r.cgroupID)
	binary.LittleEndian.PutUint32(b[offPID:], r.pid)
	binary.LittleEndian.PutUint16(b[offDport:], r.dport)
	binary.LittleEndian.PutUint16(b[offSNILen:], r.sniLen)
	binary.LittleEndian.PutUint16(b[offALPNLen:], r.alpnLen)
	copy(b[offSNI:offSNI+MaxSNILen], r.sni)
	copy(b[offALPN:offALPN+MaxALPNLen], r.alpn)
	copy(b[offComm:offComm+CommLen], r.comm)
	return b
}

// sni is a convenience that keeps sniLen and the bytes in agreement.
func (r tlsRecord) withSNI(s string) tlsRecord {
	r.sni = []byte(s)
	r.sniLen = uint16(len(s))
	return r
}

// withALPN encodes names as the kernel hands them over: the raw
// ProtocolNameList body, {len, bytes} repeated, without the outer list length.
func (r tlsRecord) withALPN(names ...string) tlsRecord {
	var body []byte
	for _, n := range names {
		body = append(body, byte(len(n)))
		body = append(body, n...)
	}
	r.alpn = body
	r.alpnLen = uint16(len(body))
	return r
}

func TestEventLayoutOffsets(t *testing.T) {
	// Guards the C contract: 8 + 4 + 2 + 2 + 2 + 256 + 32 + 16, no interior
	// padding. A change here means _cprog/tlspeek.bpf.c must change too.
	want := []struct {
		name string
		got  int
		want int
	}{
		{"offCgroupID", offCgroupID, 0},
		{"offPID", offPID, 8},
		{"offDport", offDport, 12},
		{"offSNILen", offSNILen, 14},
		{"offALPNLen", offALPNLen, 16},
		{"offSNI", offSNI, 18},
		{"offALPN", offALPN, 274},
		{"offComm", offComm, 306},
		{"EventSize", EventSize, 322},
	}
	for _, c := range want {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestDecodeTLSEvent(t *testing.T) {
	tests := []struct {
		name string
		rec  tlsRecord
		want runtimeevent.Event
	}{
		{
			name: "sni and alpn",
			rec: tlsRecord{cgroupID: 0xdeadbeefcafe, pid: 4242, dport: 443, comm: "python3"}.
				withSNI("api.openai.com").withALPN("h2", "http/1.1"),
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindTLS,
				CgroupID: 0xdeadbeefcafe,
				PID:      4242,
				Comm:     "python3",
				Count:    1,
				TLS:      &runtimeevent.TLSFacts{SNI: "api.openai.com", ALPN: []string{"h2", "http/1.1"}},
				Net:      &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "empty alpn yields nil slice not empty slice",
			rec:  tlsRecord{cgroupID: 7, pid: 1, dport: 443, comm: "curl"}.withSNI("api.anthropic.com"),
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindTLS,
				CgroupID: 7,
				PID:      1,
				Comm:     "curl",
				Count:    1,
				TLS:      &runtimeevent.TLSFacts{SNI: "api.anthropic.com"},
				Net:      &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "alpn only, no sni (degraded metadata case)",
			rec:  tlsRecord{cgroupID: 9, dport: 8443, comm: "node"}.withALPN("h2"),
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindTLS,
				CgroupID: 9,
				Comm:     "node",
				Count:    1,
				TLS:      &runtimeevent.TLSFacts{ALPN: []string{"h2"}},
				Net:      &runtimeevent.NetFacts{DestPort: 8443, Protocol: "tcp"},
			},
		},
		{
			name: "sni is lowercased",
			rec:  tlsRecord{dport: 443}.withSNI("API.OpenAI.CoM"),
			want: runtimeevent.Event{
				Kind:  runtimeevent.KindTLS,
				Count: 1,
				TLS:   &runtimeevent.TLSFacts{SNI: "api.openai.com"},
				Net:   &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "sni length shorter than the buffer content wins",
			// The kernel wrote 8 bytes of a longer name; only sni_len counts.
			rec: tlsRecord{dport: 443, sni: []byte("api.openai.com"), sniLen: 8},
			want: runtimeevent.Event{
				Kind:  runtimeevent.KindTLS,
				Count: 1,
				TLS:   &runtimeevent.TLSFacts{SNI: "api.open"},
				Net:   &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "sni of exactly MaxSNILen decodes",
			rec:  tlsRecord{dport: 443}.withSNI(strings.Repeat("a", MaxSNILen)),
			want: runtimeevent.Event{
				Kind:  runtimeevent.KindTLS,
				Count: 1,
				TLS:   &runtimeevent.TLSFacts{SNI: strings.Repeat("a", MaxSNILen)},
				Net:   &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "trailing NULs inside sni_len are trimmed",
			rec:  tlsRecord{dport: 443, sni: []byte("ollama.local\x00\x00\x00"), sniLen: 15},
			want: runtimeevent.Event{
				Kind:  runtimeevent.KindTLS,
				Count: 1,
				TLS:   &runtimeevent.TLSFacts{SNI: "ollama.local"},
				Net:   &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "alpn of exactly MaxALPNLen decodes",
			// 3 x "aaaaaaaaaa" = 3 * (1 + 10) = 33 > 32, so use 2 x 15 + 0.
			rec: tlsRecord{dport: 443}.withSNI("h.example").
				withALPN(strings.Repeat("x", 15), strings.Repeat("y", 15)),
			want: runtimeevent.Event{
				Kind:  runtimeevent.KindTLS,
				Count: 1,
				TLS: &runtimeevent.TLSFacts{
					SNI:  "h.example",
					ALPN: []string{strings.Repeat("x", 15), strings.Repeat("y", 15)},
				},
				Net: &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "alpn tail entry clamped away by the kernel is dropped",
			// The C clamps list_len to 32: "h2" + a declared-11-byte name with
			// only 4 bytes present.
			rec: tlsRecord{dport: 443, sni: []byte("x.example"), sniLen: 9,
				alpn: append([]byte{2, 'h', '2', 11}, "http"...), alpnLen: 8},
			want: runtimeevent.Event{
				Kind:  runtimeevent.KindTLS,
				Count: 1,
				TLS:   &runtimeevent.TLSFacts{SNI: "x.example", ALPN: []string{"h2"}},
				Net:   &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "comm filling the whole array has no terminator",
			rec:  tlsRecord{dport: 443, comm: "abcdefghijklmnop"}.withSNI("x.example"),
			want: runtimeevent.Event{
				Kind:  runtimeevent.KindTLS,
				Comm:  "abcdefghijklmnop",
				Count: 1,
				TLS:   &runtimeevent.TLSFacts{SNI: "x.example"},
				Net:   &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "trailing struct padding and ringbuf rounding are ignored",
			rec:  tlsRecord{dport: 443, pad: 6}.withSNI("x.example"),
			want: runtimeevent.Event{
				Kind:  runtimeevent.KindTLS,
				Count: 1,
				TLS:   &runtimeevent.TLSFacts{SNI: "x.example"},
				Net:   &runtimeevent.NetFacts{DestPort: 443, Protocol: "tcp"},
			},
		},
		{
			name: "high port survives the uint16 round trip",
			rec:  tlsRecord{dport: 65535}.withSNI("x.example"),
			want: runtimeevent.Event{
				Kind:  runtimeevent.KindTLS,
				Count: 1,
				TLS:   &runtimeevent.TLSFacts{SNI: "x.example"},
				Net:   &runtimeevent.NetFacts{DestPort: 65535, Protocol: "tcp"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeTLSEvent(tc.rec.bytes())
			if err != nil {
				t.Fatalf("DecodeTLSEvent() error = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, eventCmp...); diff != "" {
				t.Errorf("DecodeTLSEvent() mismatch (-want +got):\n%s", diff)
			}
			if !got.Time.IsZero() {
				t.Errorf("Time = %v, want zero: the decoder must stay pure and let the source stamp arrival", got.Time)
			}
			if got.Net.DestIP.IsValid() {
				t.Errorf("Net.DestIP = %v, want invalid: the tls_event layout carries no address", got.Net.DestIP)
			}
		})
	}
}

func TestDecodeTLSEvent_Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			name:    "nil buffer",
			input:   nil,
			wantErr: "short event",
		},
		{
			name:    "empty buffer",
			input:   []byte{},
			wantErr: "short event",
		},
		{
			name:    "one byte short of the fixed size",
			input:   tlsRecord{dport: 443}.withSNI("x.example").bytes()[:EventSize-1],
			wantErr: "short event",
		},
		{
			name:    "truncated inside the sni array",
			input:   tlsRecord{dport: 443}.withSNI("x.example").bytes()[:100],
			wantErr: "short event",
		},
		{
			name:    "oversize sni_len",
			input:   tlsRecord{dport: 443, sniLen: MaxSNILen + 1}.bytes(),
			wantErr: "sni_len 257 exceeds 256",
		},
		{
			name:    "sni_len at uint16 max",
			input:   tlsRecord{dport: 443, sniLen: 65535}.bytes(),
			wantErr: "sni_len 65535 exceeds 256",
		},
		{
			name:    "oversize alpn_len",
			input:   tlsRecord{dport: 443, alpnLen: MaxALPNLen + 1}.bytes(),
			wantErr: "alpn_len 33 exceeds 32",
		},
		{
			name:    "neither sni nor alpn",
			input:   tlsRecord{cgroupID: 5, dport: 443, comm: "curl"}.bytes(),
			wantErr: "neither sni nor alpn",
		},
		{
			name:    "sni that is only NULs decodes to nothing",
			input:   tlsRecord{dport: 443, sni: []byte{0, 0, 0}, sniLen: 3}.bytes(),
			wantErr: "neither sni nor alpn",
		},
		{
			name:    "sni with a space",
			input:   tlsRecord{dport: 443}.withSNI("api.openai.com evil").bytes(),
			wantErr: "sni contains an invalid byte",
		},
		{
			name:    "sni with a control byte",
			input:   tlsRecord{dport: 443}.withSNI("api\nopenai.com").bytes(),
			wantErr: "sni contains an invalid byte",
		},
		{
			name:    "sni with a colon would break evidence tokens",
			input:   tlsRecord{dport: 443}.withSNI("host:443").bytes(),
			wantErr: "sni contains an invalid byte",
		},
		{
			name:    "sni with a non-ascii byte",
			input:   tlsRecord{dport: 443}.withSNI("apï.openai.com").bytes(),
			wantErr: "sni contains an invalid byte",
		},
		{
			name: "zero-length alpn entry",
			input: tlsRecord{dport: 443, sni: []byte("x.example"), sniLen: 9,
				alpn: []byte{0, 2, 'h', '2'}, alpnLen: 4}.bytes(),
			wantErr: "zero-length protocol name",
		},
		{
			name: "alpn entry with a control byte",
			input: tlsRecord{dport: 443, sni: []byte("x.example"), sniLen: 9,
				alpn: []byte{2, 'h', '\n'}, alpnLen: 3}.bytes(),
			wantErr: "alpn protocol name contains an invalid byte",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeTLSEvent(tc.input)
			if err == nil {
				t.Fatalf("DecodeTLSEvent() error = nil, want %q (got event %+v)", tc.wantErr, got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("DecodeTLSEvent() error = %q, want it to contain %q", err, tc.wantErr)
			}
			if diff := cmp.Diff(runtimeevent.Event{}, got, eventCmp...); diff != "" {
				t.Errorf("failed decode must return the zero Event (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDecodeTLSEvent_NeverPanicsOnArbitraryBytes covers the CONVENTIONS.md hard
// rule: kernel-supplied bytes may never panic a decoder.
func TestDecodeTLSEvent_NeverPanicsOnArbitraryBytes(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x16, 0x03, 0x01},
		make([]byte, EventSize),
		bytes0xFF(EventSize),
		bytes0xFF(EventSize * 2),
		bytes0xFF(EventSize - 1),
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d: DecodeTLSEvent panicked: %v", i, r)
				}
			}()
			_, _ = DecodeTLSEvent(in)
		}()
	}
}

func bytes0xFF(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xff
	}
	return b
}

func TestDecodeALPNList(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		want    []string
		wantErr bool
	}{
		{name: "empty", raw: nil},
		{name: "single", raw: []byte{2, 'h', '2'}, want: []string{"h2"}},
		{
			name: "two",
			raw:  append([]byte{2, 'h', '2', 8}, "http/1.1"...),
			want: []string{"h2", "http/1.1"},
		},
		{name: "truncated single entry keeps nothing", raw: []byte{8, 'h', 't'}},
		{name: "zero length entry", raw: []byte{0}, wantErr: true},
		{name: "length byte with no body at all", raw: []byte{3}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeALPNList(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("decodeALPNList() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeALPNList() error = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, eventCmp...); diff != "" {
				t.Errorf("decodeALPNList() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestJSONRoundTripOfDecodedEvent proves a decoded event survives the fixture
// path used by collector.LoadEvents and the pipeline goldens.
func TestJSONRoundTripOfDecodedEvent(t *testing.T) {
	rec := tlsRecord{cgroupID: 42, pid: 7, dport: 443, comm: "python3"}.
		withSNI("api.openai.com").withALPN("h2")
	ev, err := DecodeTLSEvent(rec.bytes())
	if err != nil {
		t.Fatalf("DecodeTLSEvent() error = %v", err)
	}
	if got, want := ev.Kind, runtimeevent.KindTLS; got != want {
		t.Fatalf("Kind = %q, want %q", got, want)
	}
	// A tls event must not carry facts of other kinds.
	if ev.DNS != nil || ev.HTTP != nil || ev.Exec != nil || ev.Open != nil {
		t.Errorf("decoded tls event carries facts of another kind: %+v", ev)
	}
}

func TestNewSourceReportsNotWired(t *testing.T) {
	src, err := NewSource(logr.Discard())
	if !errors.Is(err, runtimeevent.ErrSourceNotWired) {
		t.Fatalf("NewSource() error = %v, want ErrSourceNotWired", err)
	}
	if src == nil {
		t.Fatal("NewSource() source = nil, want a usable source so daemon wiring can add it either way")
	}
	if got, want := src.Name(), SourceName; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	out := make(chan runtimeevent.Event, 1)
	if err := src.Run(context.Background(), out); !errors.Is(err, runtimeevent.ErrSourceNotWired) {
		t.Errorf("Run() error = %v, want ErrSourceNotWired", err)
	}
	if len(out) != 0 {
		t.Errorf("Run() emitted %d events, want 0", len(out))
	}
}
