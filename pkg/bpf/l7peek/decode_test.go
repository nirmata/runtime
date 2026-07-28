package l7peek

import (
	"context"
	"encoding/binary"
	"encoding/json"
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
var addrCmp = cmp.Comparer(func(a, b netip.Addr) bool { return a == b })

// Canary strings. They are the secret values a real request would carry and
// must never survive decoding. The same literals are used by the sample
// fixtures in test/samples/shadow-ai, so a regression here and there fails the
// same way.
const (
	canaryBearer = "Bearer sk-canary-XYZ"
	canaryAPIKey = "canary-KEY-123"
	canaryCookie = "session=canary-COOKIE-987"
)

// httpRecord hand-assembles an http_event exactly as the C struct writes it.
type httpRecord struct {
	cgroupID uint64
	pid      uint32
	dport    uint16
	dataLen  uint16 // written verbatim; zero means "len(data)"
	daddr    [16]byte
	ipver    uint8
	comm     string
	data     []byte
	// trimmed emits only HeaderSize+data_len bytes instead of a full record,
	// as a variable-length ring buffer submit would.
	trimmed bool
	// pad appends trailing bytes, as the C struct's tail padding does.
	pad int
}

func (r httpRecord) bytes() []byte {
	dataLen := r.dataLen
	if dataLen == 0 && len(r.data) > 0 {
		dataLen = uint16(len(r.data))
	}
	size := EventSize + r.pad
	if r.trimmed {
		size = HeaderSize + int(dataLen)
	}
	b := make([]byte, size)
	binary.LittleEndian.PutUint64(b[offCgroupID:], r.cgroupID)
	binary.LittleEndian.PutUint32(b[offPID:], r.pid)
	binary.LittleEndian.PutUint16(b[offDport:], r.dport)
	binary.LittleEndian.PutUint16(b[offDataLen:], dataLen)
	copy(b[offDaddr:offDaddr+16], r.daddr[:])
	b[offIPVer] = r.ipver
	copy(b[offComm:offComm+CommLen], r.comm)
	copy(b[offData:], r.data)
	return b
}

// v4 writes an IPv4 destination in the v4-mapped form the C uses.
func v4(s string) ([16]byte, uint8) {
	a := netip.MustParseAddr(s)
	return a.As16(), 4
}

func v6(s string) ([16]byte, uint8) {
	a := netip.MustParseAddr(s)
	return a.As16(), 6
}

// req joins lines with CRLF and appends the blank line + body.
func req(head string, body string) []byte {
	return []byte(strings.ReplaceAll(head, "\n", "\r\n") + "\r\n\r\n" + body)
}

// facts is the accessor-visible projection of an HTTPFacts. Comparing through
// the accessors rather than through cmp.AllowUnexported keeps the tests honest:
// they assert what a consumer can actually observe.
type facts struct {
	Method  string
	Path    string
	Host    string
	Headers map[string]string
	Body    string
}

func factsOf(h *runtimeevent.HTTPFacts) facts {
	return facts{
		Method:  h.Method(),
		Path:    h.Path(),
		Host:    h.Host(),
		Headers: h.Headers(),
		Body:    h.BodyPreview(),
	}
}

func TestEventLayoutOffsets(t *testing.T) {
	// Guards the C contract: 8 + 4 + 2 + 2 + 16 + 1 + 16 + 2048, no interior
	// padding. A change here means _cprog/l7peek.bpf.c must change too.
	cases := []struct {
		name      string
		got, want int
	}{
		{"offCgroupID", offCgroupID, 0},
		{"offPID", offPID, 8},
		{"offDport", offDport, 12},
		{"offDataLen", offDataLen, 14},
		{"offDaddr", offDaddr, 16},
		{"offIPVer", offIPVer, 32},
		{"offComm", offComm, 33},
		{"offData", offData, 49},
		{"HeaderSize", HeaderSize, 49},
		{"EventSize", EventSize, 2097},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestDecodeHTTPEvent(t *testing.T) {
	ollamaAddr, ollamaVer := v4("10.244.3.9")
	v6Addr, v6Ver := v6("2001:db8::42")

	tests := []struct {
		name      string
		rec       httpRecord
		wantEvent runtimeevent.Event // HTTP is checked separately via wantFacts
		wantFacts facts
	}{
		{
			name: "ollama chat completion",
			rec: httpRecord{
				cgroupID: 0x1234, pid: 991, dport: 11434,
				daddr: ollamaAddr, ipver: ollamaVer, comm: "python3",
				data: req("POST /api/chat HTTP/1.1\nHost: ollama.ai-team.svc.cluster.local:11434\nContent-Type: application/json",
					`{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, CgroupID: 0x1234, PID: 991, Comm: "python3", Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 11434, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "POST", Path: "/api/chat",
				Host: "ollama.ai-team.svc.cluster.local",
				Headers: map[string]string{
					"host":         "ollama.ai-team.svc.cluster.local:11434",
					"content-type": "application/json",
				},
				Body: `{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`,
			},
		},
		{
			name: "a2a agent card discovery, GET with no body",
			rec: httpRecord{
				cgroupID: 5, dport: 80, daddr: ollamaAddr, ipver: ollamaVer, comm: "agent",
				data: req("GET /.well-known/agent.json HTTP/1.1\nHost: partner.example.com\nAccept: application/json", ""),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, CgroupID: 5, Comm: "agent", Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 80, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "GET", Path: "/.well-known/agent.json", Host: "partner.example.com",
				Headers: map[string]string{"host": "partner.example.com", "accept": "application/json"},
			},
		},
		{
			name: "mcp streamable http signature is preserved verbatim",
			rec: httpRecord{
				dport: 8080, daddr: ollamaAddr, ipver: ollamaVer,
				data: req("POST /mcp HTTP/1.1\nHost: tools.internal\nAccept: text/event-stream\nMCP-Session-Id: 8f2\nContent-Type: application/json",
					`{"jsonrpc":"2.0","method":"tools/call","id":1}`),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 8080, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "POST", Path: "/mcp", Host: "tools.internal",
				Headers: map[string]string{
					"host":           "tools.internal",
					"accept":         "text/event-stream",
					"mcp-session-id": "8f2",
					"content-type":   "application/json",
				},
				Body: `{"jsonrpc":"2.0","method":"tools/call","id":1}`,
			},
		},
		{
			name: "ipv6 destination",
			rec: httpRecord{
				dport: 8000, daddr: v6Addr, ipver: v6Ver,
				data: req("GET /v1/models HTTP/1.1\nHost: vllm.svc", ""),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("2001:db8::42"), DestPort: 8000, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "GET", Path: "/v1/models", Host: "vllm.svc",
				Headers: map[string]string{"host": "vllm.svc"},
			},
		},
		{
			name: "absolute-form target supplies the host when no Host header is present",
			rec: httpRecord{
				dport: 3128, daddr: ollamaAddr, ipver: ollamaVer,
				data: req("POST http://api.openai.com:80/v1/chat/completions HTTP/1.1\nContent-Type: application/json", "{}"),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 3128, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "POST", Path: "http://api.openai.com:80/v1/chat/completions",
				Host:    "api.openai.com",
				Headers: map[string]string{"content-type": "application/json"},
				Body:    "{}",
			},
		},
		{
			name: "bare LF line endings",
			rec: httpRecord{
				dport: 11434, daddr: ollamaAddr, ipver: ollamaVer,
				data: []byte("POST /api/generate HTTP/1.1\nHost: ollama.local\n\n{\"model\":\"x\"}"),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 11434, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "POST", Path: "/api/generate", Host: "ollama.local",
				Headers: map[string]string{"host": "ollama.local"},
				Body:    `{"model":"x"}`,
			},
		},
		{
			name: "header block truncated by the 2KB capture keeps the headers that fit",
			rec: httpRecord{
				dport: 443, daddr: ollamaAddr, ipver: ollamaVer,
				data: []byte("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nanthropic-vers"),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 443, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "POST", Path: "/v1/messages", Host: "api.anthropic.com",
				Headers: map[string]string{"host": "api.anthropic.com"},
			},
		},
		{
			name: "request line only, no headers at all",
			rec: httpRecord{
				dport: 80, daddr: ollamaAddr, ipver: ollamaVer,
				data: []byte("GET /healthz HTTP/1.1\r\n"),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 80, Protocol: "tcp"},
			},
			wantFacts: facts{Method: "GET", Path: "/healthz"},
		},
		{
			name: "duplicate header values are joined",
			rec: httpRecord{
				dport: 80, daddr: ollamaAddr, ipver: ollamaVer,
				data: req("GET / HTTP/1.1\nHost: h\nX-Trace: a\nX-Trace: b", ""),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 80, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "GET", Path: "/", Host: "h",
				Headers: map[string]string{"host": "h", "x-trace": "a, b"},
			},
		},
		{
			name: "record trimmed to header plus data_len decodes",
			rec: httpRecord{
				dport: 80, daddr: ollamaAddr, ipver: ollamaVer, trimmed: true,
				data: req("GET / HTTP/1.1\nHost: h", ""),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 80, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "GET", Path: "/", Host: "h",
				Headers: map[string]string{"host": "h"},
			},
		},
		{
			name: "trailing struct padding is ignored",
			rec: httpRecord{
				dport: 80, daddr: ollamaAddr, ipver: ollamaVer, pad: 7,
				data: req("GET / HTTP/1.1\nHost: h", ""),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 80, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "GET", Path: "/", Host: "h",
				Headers: map[string]string{"host": "h"},
			},
		},
		{
			name: "data_len shorter than the buffer content wins",
			rec: httpRecord{
				dport: 80, daddr: ollamaAddr, ipver: ollamaVer,
				data:    append(req("GET / HTTP/1.1\nHost: h", "keepme"), []byte("DROPPED-TAIL")...),
				dataLen: uint16(len(req("GET / HTTP/1.1\nHost: h", "keepme"))),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.244.3.9"), DestPort: 80, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "GET", Path: "/", Host: "h",
				Headers: map[string]string{"host": "h"},
				Body:    "keepme",
			},
		},
		{
			name: "ipv6 literal host keeps its brackets and loses its port",
			rec: httpRecord{
				dport: 8000, daddr: v6Addr, ipver: v6Ver,
				data: req("GET /v1/completions HTTP/1.1\nHost: [2001:db8::42]:8000", ""),
			},
			wantEvent: runtimeevent.Event{
				Kind: runtimeevent.KindHTTP, Count: 1,
				Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("2001:db8::42"), DestPort: 8000, Protocol: "tcp"},
			},
			wantFacts: facts{
				Method: "GET", Path: "/v1/completions", Host: "[2001:db8::42]",
				Headers: map[string]string{"host": "[2001:db8::42]:8000"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeHTTPEvent(tc.rec.bytes())
			if err != nil {
				t.Fatalf("DecodeHTTPEvent() error = %v, want nil", err)
			}
			if got.HTTP == nil {
				t.Fatal("HTTP facts = nil, want facts")
			}
			if diff := cmp.Diff(tc.wantFacts, factsOf(got.HTTP)); diff != "" {
				t.Errorf("HTTP facts mismatch (-want +got):\n%s", diff)
			}
			// Compare the rest of the event with HTTP cleared, so the facts are
			// asserted exactly once and through the accessors only.
			gotShell := got
			gotShell.HTTP = nil
			if diff := cmp.Diff(tc.wantEvent, gotShell, addrCmp); diff != "" {
				t.Errorf("event mismatch (-want +got):\n%s", diff)
			}
			if !got.Time.IsZero() {
				t.Errorf("Time = %v, want zero: the decoder must stay pure and let the source stamp arrival", got.Time)
			}
			if got.DNS != nil || got.TLS != nil || got.Exec != nil || got.Open != nil {
				t.Errorf("decoded http event carries facts of another kind: %+v", got)
			}
		})
	}
}

// TestDecodeHTTPEvent_RedactsSecretHeaders is the blocking redaction assertion
// for this package (DESIGN.md §4): the secret value is present in the raw kernel
// bytes and must be gone from the decoded facts.
func TestDecodeHTTPEvent_RedactsSecretHeaders(t *testing.T) {
	addr, ver := v4("10.0.0.5")

	tests := []struct {
		name   string
		header string
		value  string
	}{
		{"authorization", "Authorization", canaryBearer},
		{"lowercase authorization", "authorization", canaryBearer},
		{"screaming authorization", "AUTHORIZATION", canaryBearer},
		{"x-api-key", "X-Api-Key", canaryAPIKey},
		{"api-key", "Api-Key", canaryAPIKey},
		{"x-goog-api-key", "X-Goog-Api-Key", canaryAPIKey},
		{"proxy-authorization", "Proxy-Authorization", canaryBearer},
		{"cookie", "Cookie", canaryCookie},
		{"x-amz-security-token", "X-Amz-Security-Token", canaryAPIKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := httpRecord{
				dport: 443, daddr: addr, ipver: ver, comm: "python3",
				data: req("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\n"+tc.header+": "+tc.value+"\nContent-Type: application/json",
					`{"model":"claude-3","messages":[{"role":"user","content":"hello"}]}`),
			}
			// Sanity: the secret really is in the bytes handed to the decoder.
			if !strings.Contains(string(raw.bytes()), tc.value) {
				t.Fatalf("test fixture is broken: %q is not in the raw record", tc.value)
			}

			ev, err := DecodeHTTPEvent(raw.bytes())
			if err != nil {
				t.Fatalf("DecodeHTTPEvent() error = %v", err)
			}
			if got, want := ev.HTTP.Header(tc.header), runtimeevent.Redacted; got != want {
				t.Errorf("Header(%q) = %q, want %q", tc.header, got, want)
			}
			assertNoCanary(t, ev, tc.value)
		})
	}
}

// TestRedactionSurvivesEveryPathOutOfTheEvent checks the canary is absent from
// every observable form of the event, not just the one accessor a caller
// happens to use: the header map copy, the JSON encoding (the fixture/golden
// path) and the Go formatting verbs a log line would reach for.
func TestRedactionSurvivesEveryPathOutOfTheEvent(t *testing.T) {
	addr, ver := v4("10.0.0.5")
	rec := httpRecord{
		dport: 443, daddr: addr, ipver: ver, comm: "curl",
		data: req("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\nAuthorization: "+canaryBearer+
			"\nX-Api-Key: "+canaryAPIKey+"\nCookie: "+canaryCookie+
			"\nX-Not-Secret: visible-CANARY-000", `{"model":"claude-3"}`),
	}
	ev, err := DecodeHTTPEvent(rec.bytes())
	if err != nil {
		t.Fatalf("DecodeHTTPEvent() error = %v", err)
	}

	// Proof that the scan below has teeth: a NON-secret header value with the
	// same shape does reach every output the scan inspects. Without this a
	// redaction bug and a broken scan would look identical.
	if b, err := json.Marshal(ev); err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	} else if !strings.Contains(string(b), "visible-CANARY-000") {
		t.Fatalf("scan is blind: a non-secret header value is not in the marshaled event:\n%s", b)
	}

	for _, canary := range []string{canaryBearer, canaryAPIKey, canaryCookie, "sk-canary-XYZ", "canary-COOKIE-987"} {
		assertNoCanary(t, ev, canary)
	}

	// The non-secret headers must still be there: redaction is targeted, not a
	// blanket wipe that would make the classifier blind.
	if got, want := ev.HTTP.Host(), "api.anthropic.com"; got != want {
		t.Errorf("Host() = %q, want %q", got, want)
	}
	for _, name := range []string{"authorization", "x-api-key", "cookie"} {
		if got := ev.HTTP.Header(name); got != runtimeevent.Redacted {
			t.Errorf("Header(%q) = %q, want %q", name, got, runtimeevent.Redacted)
		}
	}
}

// assertNoCanary fails if s appears anywhere in the event's observable state.
func assertNoCanary(t *testing.T, ev runtimeevent.Event, s string) {
	t.Helper()

	for k, v := range ev.HTTP.Headers() {
		if strings.Contains(v, s) {
			t.Errorf("Headers()[%q] contains the secret %q", k, s)
		}
	}
	if strings.Contains(ev.HTTP.BodyPreview(), s) {
		t.Errorf("BodyPreview() contains the secret %q", s)
	}
	if strings.Contains(ev.HTTP.Path(), s) || strings.Contains(ev.HTTP.Host(), s) {
		t.Errorf("path/host contains the secret %q", s)
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	}
	if strings.Contains(string(b), s) {
		t.Errorf("marshaled event contains the secret %q:\n%s", s, b)
	}

	// Round-tripping through the fixture path must not resurrect it either.
	var back runtimeevent.Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("json.Unmarshal(event) error = %v", err)
	}
	b2, err := json.Marshal(back)
	if err != nil {
		t.Fatalf("re-marshal error = %v", err)
	}
	if strings.Contains(string(b2), s) {
		t.Errorf("re-marshaled event contains the secret %q", s)
	}
}

// TestBodyPreviewCappedAtMaxBodyPreview: the kernel hands over up to 2KB, the
// chokepoint keeps 512 bytes.
func TestBodyPreviewCappedAtMaxBodyPreview(t *testing.T) {
	addr, ver := v4("10.0.0.7")
	head := "POST /api/chat HTTP/1.1\nHost: ollama.local\nContent-Type: application/json"

	tests := []struct {
		name     string
		bodyLen  int
		wantLen  int
		wantTail bool // the tail must be gone
	}{
		{name: "under the cap", bodyLen: 100, wantLen: 100},
		{name: "exactly at the cap", bodyLen: runtimeevent.MaxBodyPreview, wantLen: runtimeevent.MaxBodyPreview},
		{name: "one over the cap", bodyLen: runtimeevent.MaxBodyPreview + 1, wantLen: runtimeevent.MaxBodyPreview, wantTail: true},
		{name: "full 2KB capture", bodyLen: 1800, wantLen: runtimeevent.MaxBodyPreview, wantTail: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Repeat("A", tc.bodyLen-len("TAIL")) + "TAIL"
			if tc.bodyLen < len("TAIL") {
				t.Fatalf("bad test case: bodyLen %d too small", tc.bodyLen)
			}
			rec := httpRecord{dport: 11434, daddr: addr, ipver: ver, data: req(head, body)}
			ev, err := DecodeHTTPEvent(rec.bytes())
			if err != nil {
				t.Fatalf("DecodeHTTPEvent() error = %v", err)
			}
			got := ev.HTTP.BodyPreview()
			if len(got) != tc.wantLen {
				t.Errorf("len(BodyPreview()) = %d, want %d", len(got), tc.wantLen)
			}
			if tc.wantTail && strings.Contains(got, "TAIL") {
				t.Error("BodyPreview() kept the tail of an oversized body")
			}
			if len(got) > runtimeevent.MaxBodyPreview {
				t.Errorf("BodyPreview() length %d exceeds the hard cap %d", len(got), runtimeevent.MaxBodyPreview)
			}
		})
	}
}

// TestDecodeHTTPEvent_MalformedRequestLine: an error, never a panic, and never a
// bogus event. l7peek sees the first segment of every plaintext flow, so most of
// what reaches this decoder is not HTTP at all.
func TestDecodeHTTPEvent_MalformedRequestLine(t *testing.T) {
	addr, ver := v4("10.0.0.9")

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "empty payload", data: []byte{}, wantErr: "empty payload"},
		{name: "no line terminator", data: []byte("GET / HTTP/1.1"), wantErr: "no request line terminator"},
		{name: "single token", data: []byte("GARBAGE\r\n"), wantErr: "want 3 space-separated fields"},
		{name: "two fields", data: []byte("GET /\r\n"), wantErr: "want 3 space-separated fields"},
		{name: "four fields", data: []byte("GET / HTTP/1.1 extra\r\n"), wantErr: "want 3 space-separated fields"},
		{name: "empty request line", data: []byte("\r\nHost: h\r\n"), wantErr: "empty request line"},
		{name: "empty method", data: []byte(" / HTTP/1.1\r\n"), wantErr: "invalid method"},
		{name: "method with a control byte", data: []byte("G\x01T / HTTP/1.1\r\n"), wantErr: "invalid method"},
		{name: "method with a separator", data: []byte("GE(T / HTTP/1.1\r\n"), wantErr: "invalid method"},
		{name: "method too long", data: []byte(strings.Repeat("M", MaxMethodLen+1) + " / HTTP/1.1\r\n"), wantErr: "invalid method"},
		{name: "target with a control byte", data: []byte("GET /a\x00b HTTP/1.1\r\n"), wantErr: "invalid request target"},
		{name: "target with a non-ascii byte", data: []byte("GET /\xff HTTP/1.1\r\n"), wantErr: "invalid request target"},
		{name: "target too long", data: []byte("GET /" + strings.Repeat("a", MaxRequestTarget) + " HTTP/1.1\r\n"), wantErr: "invalid request target"},
		{name: "version misspelled", data: []byte("GET / HTTP/1.1x\r\n"), wantErr: "invalid version"},
		{name: "version without digits", data: []byte("GET / HTTP/a.b\r\n"), wantErr: "invalid version"},
		{name: "no version at all", data: []byte("GET / SPDY\r\n"), wantErr: "invalid version"},
		{
			name:    "a TLS ClientHello is not HTTP",
			data:    append([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01}, []byte("\r\n\r\n")...),
			wantErr: "want 3 space-separated fields",
		},
		{
			name:    "binary noise with spaces still fails on the method",
			data:    []byte("\x00\x01 \x02\x03 \x04\x05\n"),
			wantErr: "invalid method",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httpRecord{dport: 80, daddr: addr, ipver: ver, data: tc.data}
			if len(tc.data) == 0 {
				rec.dataLen = 0
			}
			got, err := DecodeHTTPEvent(rec.bytes())
			if err == nil {
				t.Fatalf("DecodeHTTPEvent() error = nil, want %q (got %+v)", tc.wantErr, got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("DecodeHTTPEvent() error = %q, want it to contain %q", err, tc.wantErr)
			}
			if got.HTTP != nil || got.Kind != "" {
				t.Errorf("failed decode must return the zero Event, got %+v", got)
			}
		})
	}
}

func TestDecodeHTTPEvent_RecordErrors(t *testing.T) {
	addr, ver := v4("10.0.0.11")
	good := httpRecord{dport: 80, daddr: addr, ipver: ver, data: req("GET / HTTP/1.1\nHost: h", "")}

	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{name: "nil buffer", input: nil, wantErr: "short event"},
		{name: "one byte short of the header", input: good.bytes()[:HeaderSize-1], wantErr: "short event"},
		{
			name:    "data_len over the array size",
			input:   httpRecord{dport: 80, daddr: addr, ipver: ver, dataLen: MaxData + 1}.bytes(),
			wantErr: "data_len 2049 exceeds 2048",
		},
		{
			name:    "data_len at uint16 max",
			input:   httpRecord{dport: 80, daddr: addr, ipver: ver, dataLen: 65535}.bytes(),
			wantErr: "data_len 65535 exceeds 2048",
		},
		{
			name:    "trimmed record shorter than data_len",
			input:   good.bytes()[:HeaderSize+4],
			wantErr: "truncated payload",
		},
		{
			name:    "ipver zero",
			input:   httpRecord{dport: 80, daddr: addr, ipver: 0, data: good.data}.bytes(),
			wantErr: "unsupported ipver 0",
		},
		{
			name:    "ipver bogus",
			input:   httpRecord{dport: 80, daddr: addr, ipver: 7, data: good.data}.bytes(),
			wantErr: "unsupported ipver 7",
		},
		{
			name: "ipver 4 with a non-v4-mapped address",
			input: func() []byte {
				a, _ := v6("2001:db8::1")
				return httpRecord{dport: 80, daddr: a, ipver: 4, data: good.data}.bytes()
			}(),
			wantErr: "not v4-mapped",
		},
		{
			name:    "data_len zero",
			input:   httpRecord{dport: 80, daddr: addr, ipver: ver}.bytes(),
			wantErr: "empty payload",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeHTTPEvent(tc.input)
			if err == nil {
				t.Fatalf("DecodeHTTPEvent() error = nil, want %q (got %+v)", tc.wantErr, got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("DecodeHTTPEvent() error = %q, want it to contain %q", err, tc.wantErr)
			}
			if got.HTTP != nil || got.Kind != "" {
				t.Errorf("failed decode must return the zero Event, got %+v", got)
			}
		})
	}
}

// TestDecodeHTTPEvent_NeverPanicsOnArbitraryBytes covers the CONVENTIONS.md hard
// rule: kernel-supplied bytes may never panic a decoder.
func TestDecodeHTTPEvent_NeverPanicsOnArbitraryBytes(t *testing.T) {
	addr, ver := v4("10.0.0.13")
	inputs := [][]byte{
		nil,
		{},
		{0x16, 0x03, 0x01},
		make([]byte, HeaderSize),
		make([]byte, EventSize),
		fill(0xff, EventSize),
		fill(0xff, HeaderSize+1),
		fill(0x0a, EventSize), // all newlines
		fill(0x20, EventSize), // all spaces
		httpRecord{dport: 80, daddr: addr, ipver: ver, data: fill(0xff, MaxData)}.bytes(),
		httpRecord{dport: 80, daddr: addr, ipver: ver, data: []byte(strings.Repeat("A: B\r\n", 300))}.bytes(),
		httpRecord{dport: 80, daddr: addr, ipver: ver, data: []byte("GET / HTTP/1.1\r\n" + strings.Repeat(":", 1000))}.bytes(),
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d: DecodeHTTPEvent panicked: %v", i, r)
				}
			}()
			_, _ = DecodeHTTPEvent(in)
		}()
	}
}

func fill(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}

func TestStripPort(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"host", "host"},
		{"host:8080", "host"},
		{"host:notaport", "host:notaport"},
		{"[2001:db8::1]:443", "[2001:db8::1]"},
		{"[2001:db8::1]", "[2001:db8::1]"},
		{"2001:db8::1", "2001:db8::1"},
		{"host:", "host"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := stripPort(tc.in); got != tc.want {
				t.Errorf("stripPort(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAuthorityOf(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/v1/messages", ""},
		{"http://api.openai.com/v1/chat", "api.openai.com"},
		{"https://api.openai.com:443/v1/chat?x=1", "api.openai.com:443"},
		{"http://host", "host"},
		{"http://host#frag", "host"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := authorityOf(tc.in); got != tc.want {
				t.Errorf("authorityOf(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
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
