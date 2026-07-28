// Package dnstrace decodes DNS query events emitted by the kernel program in
// _cprog/dns.bpf.c.
//
// The kernel side is deliberately dumb: it copies the raw wire-format QNAME
// label sequence out of the packet and lets userspace turn it into a dotted
// name. That keeps the BPF loop a bounded byte copy (verifier friendly) and
// puts all the parsing — and therefore all the tests — here.
//
// The decoder is a pure function over kernel-supplied bytes. Per the no-panic
// rule it never indexes without a length check and returns an error for every
// truncated, oversized or malformed input.
package dnstrace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// Byte layout of `struct dns_event` in _cprog/dns.bpf.c. Little-endian, in the
// natural C field order with no internal padding:
//
//	off  size  field
//	  0     8  cgroup_id  __u64
//	  8     4  pid        __u32
//	 12     2  qtype      __u16   (already host-order: the C swaps it)
//	 14     2  qname_len  __u16   (bytes of wire-format QNAME copied, <= 253)
//	 16    16  comm       char[16] (NUL-padded, may be unterminated)
//	 32   253  qname      __u8[253] (wire format: len-prefixed labels, no root 0)
//
// The C struct's sizeof is 288 (8-byte alignment adds 3 trailing pad bytes);
// the decoder only requires the first EventSize bytes and ignores any trailing
// padding the ring buffer hands over.
const (
	// MaxQName is the largest wire-format QNAME the kernel copies (RFC 1035
	// caps a domain name at 255 bytes including the length prefix of the
	// first label and the root label; 253 is the usable remainder).
	MaxQName = 253
	// MaxLabel is the RFC 1035 maximum length of a single DNS label.
	MaxLabel = 63

	commLen = 16

	offCgroupID = 0
	offPID      = 8
	offQType    = 12
	offQNameLen = 14
	offComm     = 16
	offQName    = 32

	// EventSize is the minimum number of bytes DecodeDNSEvent needs.
	EventSize = offQName + MaxQName // 285
)

var (
	// ErrTruncated means the kernel handed over fewer bytes than the layout
	// requires; the Go and C sides disagree, or the ring buffer record is
	// damaged.
	ErrTruncated = errors.New("dnstrace: truncated kernel event")
	// ErrBadQName means qname_len or the label sequence itself is invalid.
	ErrBadQName = errors.New("dnstrace: malformed qname")
)

// DecodeDNSEvent converts one kernel DNS event record into a normalized event.
//
// Time is left zero: the record carries no timestamp, so the source stamps it.
// Count is 1 — every ring buffer record is exactly one observed query (unlike
// the poll sources, which aggregate).
func DecodeDNSEvent(b []byte) (runtimeevent.Event, error) {
	if len(b) < EventSize {
		return runtimeevent.Event{}, fmt.Errorf("%w: got %d bytes, want at least %d",
			ErrTruncated, len(b), EventSize)
	}

	nameLen := int(binary.LittleEndian.Uint16(b[offQNameLen : offQNameLen+2]))
	if nameLen > MaxQName {
		return runtimeevent.Event{}, fmt.Errorf("%w: qname_len %d exceeds %d",
			ErrBadQName, nameLen, MaxQName)
	}

	qname, err := decodeQName(b[offQName : offQName+nameLen])
	if err != nil {
		return runtimeevent.Event{}, err
	}

	return runtimeevent.Event{
		Kind:     runtimeevent.KindDNS,
		CgroupID: binary.LittleEndian.Uint64(b[offCgroupID : offCgroupID+8]),
		PID:      binary.LittleEndian.Uint32(b[offPID : offPID+4]),
		Comm:     cString(b[offComm : offComm+commLen]),
		Count:    1,
		DNS: &runtimeevent.DNSFacts{
			QName: qname,
			QType: binary.LittleEndian.Uint16(b[offQType : offQType+2]),
		},
	}, nil
}

// decodeQName turns a wire-format label sequence into a dotted, lowercase-safe
// name. The trailing root label (a single 0 byte) is not part of the input: the
// kernel stops copying when it sees it.
//
// A zero-length input is the root query and decodes to "" (not an error).
func decodeQName(wire []byte) (string, error) {
	if len(wire) == 0 {
		return "", nil
	}

	var sb strings.Builder
	sb.Grow(len(wire))

	for i := 0; i < len(wire); {
		n := int(wire[i])
		// A query never contains a compression pointer (0xc0) and the two
		// top bits are reserved otherwise, so anything above 63 is malformed.
		// This check also subsumes the MaxLabel bound.
		if n&0xc0 != 0 {
			return "", fmt.Errorf("%w: label length byte 0x%02x at offset %d is a pointer or reserved",
				ErrBadQName, wire[i], i)
		}
		if n == 0 {
			return "", fmt.Errorf("%w: empty label at offset %d", ErrBadQName, i)
		}
		if i+1+n > len(wire) {
			return "", fmt.Errorf("%w: label at offset %d claims %d bytes, only %d remain",
				ErrBadQName, i, n, len(wire)-i-1)
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(wire[i+1 : i+1+n])
		i += 1 + n
	}

	return sb.String(), nil
}

// cString trims a fixed-width, NUL-padded kernel char array. A buffer with no
// NUL at all (the kernel truncated the value) yields the whole buffer.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
