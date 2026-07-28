// Package tlspeek decodes TLS ClientHello observations produced by the
// cgroup_skb/egress program in _cprog/tlspeek.bpf.c.
//
// The decoder in this file is the byte-layout contract between the C struct and
// the Go event plane. It is PURE: no clock, no kernel, no I/O, no logging. That
// is what makes it fully unit-testable on a host without clang, a BTF-enabled
// kernel, or bpf2go — which is deliberate, because the kernel side of this
// package cannot be built or verified here at all (see source.go).
package tlspeek

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// Field sizes and offsets of the C `struct tls_event`. Little-endian scalars
// (BPF writes native order and every supported target is little-endian; a
// big-endian build would need its own decoder, which is why the offsets live
// here and nowhere else).
//
//	off  size  field
//	  0     8  cgroup_id  __u64
//	  8     4  pid        __u32
//	 12     2  dport      __u16
//	 14     2  sni_len    __u16
//	 16     2  alpn_len   __u16
//	 18   256  sni        __u8[256]
//	274    32  alpn       __u8[32]
//	306    16  comm       __u8[16]
//	322        end of fields (the C struct is padded to 328)
const (
	// MaxSNILen is the size of the C sni[] array.
	MaxSNILen = 256
	// MaxALPNLen is the size of the C alpn[] array. It holds the raw
	// ProtocolNameList body, not a single protocol name.
	MaxALPNLen = 32
	// CommLen is the size of the C comm[] array (TASK_COMM_LEN).
	CommLen = 16

	offCgroupID = 0
	offPID      = 8
	offDport    = 12
	offSNILen   = 14
	offALPNLen  = 16
	offSNI      = 18
	offALPN     = offSNI + MaxSNILen
	offComm     = offALPN + MaxALPNLen

	// EventSize is the number of bytes DecodeTLSEvent requires. Records may
	// be longer (the C struct carries trailing alignment padding and the ring
	// buffer rounds records up to 8 bytes); trailing bytes are ignored.
	EventSize = offComm + CommLen
)

// DecodeTLSEvent decodes one tls_event record into a runtimeevent.Event.
//
// The returned event has Kind KindTLS, TLSFacts holding the SNI and the decoded
// ALPN protocol list, and NetFacts holding the destination port: NetFacts is
// the event plane's only home for a port, the classifier's self-hosted
// heuristics need it, and pkg/aicontrols sets Net.Governed on tls events. The
// tls_event layout carries no destination address, so Net.DestIP is left
// invalid (the zero netip.Addr) rather than guessed at.
//
// Event.Time is NOT set: the decoder is pure, and the source stamps arrival
// time. Count is 1 because each ring buffer record is exactly one observation.
//
// Every failure mode is an error, never a panic: the input is kernel-supplied
// bytes and per CONVENTIONS.md nothing reachable from them may panic.
func DecodeTLSEvent(b []byte) (runtimeevent.Event, error) {
	if len(b) < EventSize {
		return runtimeevent.Event{}, fmt.Errorf("tlspeek: short event: got %d bytes, want at least %d", len(b), EventSize)
	}

	sniLen := int(binary.LittleEndian.Uint16(b[offSNILen:]))
	if sniLen > MaxSNILen {
		return runtimeevent.Event{}, fmt.Errorf("tlspeek: sni_len %d exceeds %d", sniLen, MaxSNILen)
	}
	alpnLen := int(binary.LittleEndian.Uint16(b[offALPNLen:]))
	if alpnLen > MaxALPNLen {
		return runtimeevent.Event{}, fmt.Errorf("tlspeek: alpn_len %d exceeds %d", alpnLen, MaxALPNLen)
	}
	if sniLen == 0 && alpnLen == 0 {
		return runtimeevent.Event{}, fmt.Errorf("tlspeek: event carries neither sni nor alpn")
	}

	sni, err := decodeSNI(b[offSNI : offSNI+sniLen])
	if err != nil {
		return runtimeevent.Event{}, err
	}
	alpn, err := decodeALPNList(b[offALPN : offALPN+alpnLen])
	if err != nil {
		return runtimeevent.Event{}, err
	}
	if sni == "" && len(alpn) == 0 {
		return runtimeevent.Event{}, fmt.Errorf("tlspeek: event carries neither sni nor alpn")
	}

	return runtimeevent.Event{
		Kind:     runtimeevent.KindTLS,
		CgroupID: binary.LittleEndian.Uint64(b[offCgroupID:]),
		PID:      binary.LittleEndian.Uint32(b[offPID:]),
		Comm:     commString(b[offComm : offComm+CommLen]),
		Count:    1,
		TLS: &runtimeevent.TLSFacts{
			SNI:  sni,
			ALPN: alpn,
		},
		Net: &runtimeevent.NetFacts{
			DestPort: binary.LittleEndian.Uint16(b[offDport:]),
			Protocol: "tcp",
		},
	}, nil
}

// decodeSNI validates and normalizes a server_name. Hostnames are
// case-insensitive so the value is lowercased, matching HTTPFacts.Host and
// letting the provider catalog match on one canonical form.
//
// Bytes that cannot appear in a hostname are rejected rather than sanitized:
// the SNI ends up in finding evidence tokens, and a value carrying whitespace
// or control characters would either break the token grammar or need scrubbing
// downstream. Rejecting here keeps that impossible.
func decodeSNI(raw []byte) (string, error) {
	s := strings.TrimRight(string(raw), "\x00")
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > MaxSNILen {
		return "", fmt.Errorf("tlspeek: sni too long: %d bytes", len(s))
	}
	s = strings.ToLower(s)
	for i := 0; i < len(s); i++ {
		if !isHostByte(s[i]) {
			return "", fmt.Errorf("tlspeek: sni contains an invalid byte at index %d", i)
		}
	}
	return s, nil
}

// isHostByte reports whether c may appear in a lowercased DNS presentation
// name. IDNs arrive as punycode ("xn--..."), so ASCII is sufficient.
func isHostByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '.' || c == '-' || c == '_':
		return true
	}
	return false
}

// decodeALPNList walks the raw ProtocolNameList body: a sequence of
// {length byte, length bytes of name} entries with no outer length prefix (the
// C strips it).
//
// A final entry cut short by the 32 byte kernel buffer is DROPPED, not an
// error: truncation there is the expected consequence of the clamp in
// tlspeek.bpf.c, and losing "h2" because the third protocol name did not fit
// would be worse than reporting the two that did. A zero-length entry is a
// malformed list (RFC 7301 requires 1..255) and is an error.
func decodeALPNList(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []string
	for i := 0; i < len(raw); {
		n := int(raw[i])
		i++
		if n == 0 {
			return nil, fmt.Errorf("tlspeek: alpn list has a zero-length protocol name at index %d", i-1)
		}
		if i+n > len(raw) {
			break // truncated tail entry: keep what was complete
		}
		name := string(raw[i : i+n])
		i += n
		if !isALPNName(name) {
			return nil, fmt.Errorf("tlspeek: alpn protocol name contains an invalid byte")
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isALPNName reports whether every byte is printable ASCII, excluding space.
// IANA ALPN identifiers are things like "h2", "http/1.1", "grpc-exp".
func isALPNName(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// commString trims the NUL padding the kernel leaves in a fixed comm[] array.
// A comm that fills the array has no terminator at all.
func commString(raw []byte) string {
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	return string(raw)
}
