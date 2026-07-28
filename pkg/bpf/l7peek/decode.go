// Package l7peek decodes plaintext L7 (HTTP) observations produced by the
// cgroup_skb/egress program in _cprog/l7peek.bpf.c.
//
// The kernel copies raw bytes and parses nothing (proposal §2.3 item 4). All
// parsing happens here, which makes this file the single point where an
// unredacted HTTP header could enter the system -- and therefore the reason
// DecodeHTTPEvent constructs its result exclusively through
// runtimeevent.NewHTTPFacts:
//
//   - runtimeevent.HTTPFacts has only unexported fields and NewHTTPFacts is its
//     only constructor, so there is no way to build one that skipped redaction.
//   - The parsed header map exists as a local inside parseHTTPRequest and is
//     handed straight to NewHTTPFacts. It is never returned, stored, logged, or
//     copied anywhere else in this package, so no caller of this package can
//     reach a raw header value even by mistake.
//   - The body is passed as raw bytes and capped by NewHTTPFacts at
//     runtimeevent.MaxBodyPreview; this package never keeps its own copy.
//
// Like every decoder here it is PURE: no clock, no kernel, no I/O, no logging.
package l7peek

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"net/textproto"
	"strings"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// Field sizes and offsets of the C `struct http_event`. Little-endian scalars.
//
//	off  size  field
//	  0     8  cgroup_id  __u64
//	  8     4  pid        __u32
//	 12     2  dport      __u16
//	 14     2  data_len   __u16
//	 16    16  daddr      __u8[16]
//	 32     1  ipver      __u8
//	 33    16  comm       __u8[16]
//	 49  2048  data       __u8[2048]
//	2097        end of fields (the C struct is padded to 2104)
const (
	// MaxData is the size of the C data[] array: the kernel copies at most
	// this many bytes of TCP payload.
	MaxData = 2048
	// CommLen is the size of the C comm[] array (TASK_COMM_LEN).
	CommLen = 16
	// MaxRequestTarget bounds the request target accepted from the wire. The
	// capture is 2KB, so anything near it is a truncated or hostile line.
	MaxRequestTarget = 1024
	// MaxMethodLen bounds the request method. The longest registered method
	// is 17 characters; 24 leaves room for extensions without accepting a
	// line of binary noise as a method.
	MaxMethodLen = 24

	offCgroupID = 0
	offPID      = 8
	offDport    = 12
	offDataLen  = 14
	offDaddr    = 16
	offIPVer    = 32
	offComm     = 33
	offData     = offComm + CommLen

	// HeaderSize is the fixed part of the record, before data[].
	HeaderSize = offData
	// EventSize is the size of a full, untrimmed record's fields.
	EventSize = HeaderSize + MaxData
)

// DecodeHTTPEvent decodes one http_event record into a runtimeevent.Event.
//
// The returned event has Kind KindHTTP, HTTPFacts built by
// runtimeevent.NewHTTPFacts (secret header values already replaced by
// runtimeevent.Redacted, body capped at runtimeevent.MaxBodyPreview) and
// NetFacts holding the destination address and port -- the classifier's
// self-hosted port heuristics and pkg/aicontrols' governed bit both live there.
//
// It accepts either a full record (HeaderSize+MaxData bytes, possibly with
// trailing struct padding) or one trimmed to HeaderSize+data_len bytes, so the
// kernel side is free to submit variable-length records later without a decoder
// change.
//
// Event.Time is NOT set: the decoder is pure, and the source stamps arrival
// time. Count is 1 because each ring buffer record is exactly one observation.
//
// Every failure mode is an error, never a panic: a malformed request line, a
// truncated record, an out-of-range data_len and a payload that is not HTTP at
// all (a TLS record, say) all return errors.
func DecodeHTTPEvent(b []byte) (runtimeevent.Event, error) {
	if len(b) < HeaderSize {
		return runtimeevent.Event{}, fmt.Errorf("l7peek: short event: got %d bytes, want at least %d", len(b), HeaderSize)
	}
	dataLen := int(binary.LittleEndian.Uint16(b[offDataLen:]))
	if dataLen > MaxData {
		return runtimeevent.Event{}, fmt.Errorf("l7peek: data_len %d exceeds %d", dataLen, MaxData)
	}
	if len(b) < HeaderSize+dataLen {
		return runtimeevent.Event{}, fmt.Errorf("l7peek: truncated payload: got %d bytes, want %d for data_len %d", len(b), HeaderSize+dataLen, dataLen)
	}

	addr, err := decodeAddr(b[offDaddr:offDaddr+16], b[offIPVer])
	if err != nil {
		return runtimeevent.Event{}, err
	}

	// The raw header map lives and dies inside parseHTTPRequest; only redacted
	// facts come back.
	facts, err := parseHTTPRequest(b[HeaderSize : HeaderSize+dataLen])
	if err != nil {
		return runtimeevent.Event{}, err
	}

	return runtimeevent.Event{
		Kind:     runtimeevent.KindHTTP,
		CgroupID: binary.LittleEndian.Uint64(b[offCgroupID:]),
		PID:      binary.LittleEndian.Uint32(b[offPID:]),
		Comm:     commString(b[offComm : offComm+CommLen]),
		Count:    1,
		HTTP:     facts,
		Net: &runtimeevent.NetFacts{
			DestIP:   addr,
			DestPort: binary.LittleEndian.Uint16(b[offDport:]),
			Protocol: "tcp",
		},
	}, nil
}

// decodeAddr turns the C daddr[16]/ipver pair into a netip.Addr. IPv4 is
// carried in the v4-mapped form (::ffff:a.b.c.d) the C writes, and is returned
// unmapped so NetFacts.DestIP prints as dotted quad and compares equal to
// addresses parsed from a policy.
func decodeAddr(raw []byte, ipver byte) (netip.Addr, error) {
	var a16 [16]byte
	copy(a16[:], raw)
	addr := netip.AddrFrom16(a16)
	switch ipver {
	case 4:
		if !addr.Is4In6() {
			return netip.Addr{}, fmt.Errorf("l7peek: ipver 4 but daddr is not v4-mapped")
		}
		return addr.Unmap(), nil
	case 6:
		return addr, nil
	default:
		return netip.Addr{}, fmt.Errorf("l7peek: unsupported ipver %d", ipver)
	}
}

// parseHTTPRequest parses a captured request head into redacted HTTPFacts.
//
// REDACTION INVARIANT: the header map built here is a function-local that is
// passed directly to runtimeevent.NewHTTPFacts and then dropped. Do not return
// it, store it, log it, or add a parameter that exposes it -- doing so would
// move an unredacted secret header value outside the chokepoint, which
// DESIGN.md §4 forbids and TestDecodeHTTPEvent_RedactsSecretHeaders /
// TestRawHeaderValueAppearsNowhereInTheEvent detect.
func parseHTTPRequest(data []byte) (*runtimeevent.HTTPFacts, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("l7peek: empty payload")
	}

	// The request line must be complete. A capture that cut it short carries
	// no usable identity, so it is an error rather than a partial event.
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return nil, fmt.Errorf("l7peek: no request line terminator in %d bytes", len(data))
	}
	line := bytes.TrimSuffix(data[:nl], []byte("\r"))
	method, target, err := parseRequestLine(line)
	if err != nil {
		return nil, err
	}

	headerBlock, body := splitHeadersBody(data[nl+1:])
	headers := parseHeaders(headerBlock)

	host := headers["Host"]
	if host == "" {
		// absolute-form target (proxy style): take the authority.
		host = authorityOf(target)
	}
	// Strip any port: HTTPFacts.Host is a hostname, and the port is already
	// carried by NetFacts.DestPort.
	host = stripPort(host)

	return runtimeevent.NewHTTPFacts(method, target, host, headers, body), nil
}

// parseRequestLine validates "METHOD SP request-target SP HTTP-version".
//
// It is strict on purpose: l7peek sees the first data segment of every
// plaintext flow from a selected cgroup, most of which is not HTTP at all. A
// lax parser would turn arbitrary binary protocol bytes into HTTP findings.
func parseRequestLine(line []byte) (method, target string, err error) {
	if len(line) == 0 {
		return "", "", fmt.Errorf("l7peek: empty request line")
	}
	parts := bytes.Split(line, []byte(" "))
	if len(parts) != 3 {
		return "", "", fmt.Errorf("l7peek: malformed request line: want 3 space-separated fields, got %d", len(parts))
	}
	m, t, v := parts[0], parts[1], parts[2]

	if len(m) == 0 || len(m) > MaxMethodLen || !isToken(m) {
		return "", "", fmt.Errorf("l7peek: malformed request line: invalid method")
	}
	if len(t) == 0 || len(t) > MaxRequestTarget || !isVisibleASCII(t) {
		return "", "", fmt.Errorf("l7peek: malformed request line: invalid request target")
	}
	if !isHTTPVersion(v) {
		return "", "", fmt.Errorf("l7peek: malformed request line: invalid version")
	}
	return string(m), string(t), nil
}

// isHTTPVersion matches "HTTP/<digit>.<digit>".
func isHTTPVersion(v []byte) bool {
	const prefix = "HTTP/"
	if len(v) != len(prefix)+3 {
		return false
	}
	if string(v[:len(prefix)]) != prefix {
		return false
	}
	return isDigit(v[5]) && v[6] == '.' && isDigit(v[7])
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isToken reports whether b is a non-empty RFC 9110 token (tchar only).
func isToken(b []byte) bool {
	for _, c := range b {
		if !isTChar(c) {
			return false
		}
	}
	return len(b) > 0
}

func isTChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// isVisibleASCII reports whether every byte is VCHAR (0x21..0x7E).
func isVisibleASCII(b []byte) bool {
	for _, c := range b {
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// splitHeadersBody splits the post-request-line bytes at the first blank line.
// It is done on the raw bytes rather than via textproto so a header the capture
// cut in half cannot also cost us the body preview.
func splitHeadersBody(rest []byte) (headerBlock, body []byte) {
	if i := bytes.Index(rest, []byte("\r\n\r\n")); i >= 0 {
		return rest[:i], rest[i+4:]
	}
	if i := bytes.Index(rest, []byte("\n\n")); i >= 0 {
		return rest[:i], rest[i+2:]
	}
	return rest, nil // header block truncated by the 2KB capture
}

// parseHeaders parses a header block with net/textproto.
//
// Parse errors are TOLERATED and the partial result kept, because a 2KB capture
// routinely ends in the middle of a header line: ReadMIMEHeader returns
// everything it read before the failure, and the request line plus the headers
// that did fit are exactly the signal the classifier needs. It never returns an
// error, so there is no path where a caller might be tempted to inspect a raw
// map to "recover" from one.
//
// The returned map is raw (values NOT redacted) and MUST be consumed by
// runtimeevent.NewHTTPFacts immediately; see parseHTTPRequest's invariant.
func parseHeaders(block []byte) map[string]string {
	if len(block) == 0 {
		return nil
	}
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(block)))
	// The error is deliberately discarded; mh holds whatever was parsed.
	mh, _ := r.ReadMIMEHeader()
	if len(mh) == 0 {
		return nil
	}
	out := make(map[string]string, len(mh))
	for k, vs := range mh {
		out[k] = strings.Join(vs, ", ")
	}
	return out
}

// authorityOf extracts the authority from an absolute-form request target
// ("http://host/path"). It returns "" for origin-form targets.
func authorityOf(target string) string {
	i := strings.Index(target, "://")
	if i < 0 {
		return ""
	}
	rest := target[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// stripPort removes a trailing ":port" from an authority, leaving IPv6 literals
// ("[::1]") and bare hostnames alone.
func stripPort(host string) string {
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, "]"); i >= 0 {
			return host[:i+1]
		}
		return host
	}
	i := strings.LastIndexByte(host, ':')
	if i < 0 {
		return host
	}
	if strings.Contains(host[:i], ":") {
		return host // bare IPv6 literal, no port
	}
	for _, c := range host[i+1:] {
		if c < '0' || c > '9' {
			return host // not a port
		}
	}
	return host[:i]
}

// commString trims the NUL padding the kernel leaves in a fixed comm[] array.
// A comm that fills the array has no terminator at all.
func commString(raw []byte) string {
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	return string(raw)
}
