package dnsquery

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// Byte layout of `struct dns_query_event` in _cprog/maps.h. Little-endian, in
// the natural C field order with no internal padding:
//
//	off  size  field
//	  0     8  cgroup_id  __u64
//	  8     4  name_len   __u32  (offset of whatever follows the name, so it
//	                              counts the terminating zero byte)
//	 12   128  name       __u8[128] (wire format, lowercased, zero padded)
//
// The kernel never writes the terminating zero: it is the zero padding, which is
// why the decodable name is name_len-1 bytes long.
const (
	// MaxName is the key width shared with the domain interning in
	// pkg/bpf/egressfilter, so a question this decoder accepts is a question a
	// policy could have named.
	MaxName = 128

	offCgroupID = 0
	offNameLen  = 8
	offName     = 12

	// EventSize is the minimum number of bytes DecodeQueryEvent needs.
	EventSize = offName + MaxName // 140
)

var (
	// ErrTruncated means the kernel handed over fewer bytes than the layout
	// requires; the Go and C sides disagree, or the record is damaged.
	ErrTruncated = errors.New("dnsquery: truncated kernel event")
	// ErrBadName means name_len or the label sequence itself is invalid.
	ErrBadName = errors.New("dnsquery: malformed question name")
)

// DecodeQueryEvent converts one kernel record into a normalized event.
//
// Time is left zero: the record carries no timestamp, so the source stamps it.
// Count is 1 — every record is exactly one observed question, unlike the poll
// sources, which aggregate.
func DecodeQueryEvent(b []byte) (runtimeevent.Event, error) {
	if len(b) < EventSize {
		return runtimeevent.Event{}, fmt.Errorf("%w: got %d bytes, want at least %d",
			ErrTruncated, len(b), EventSize)
	}

	nameLen := binary.LittleEndian.Uint32(b[offNameLen : offNameLen+4])
	if nameLen == 0 || nameLen > MaxName {
		return runtimeevent.Event{}, fmt.Errorf("%w: name_len %d outside 1..%d",
			ErrBadName, nameLen, MaxName)
	}

	name, err := decodeWireName(b[offName : offName+int(nameLen)-1])
	if err != nil {
		return runtimeevent.Event{}, err
	}

	return runtimeevent.Event{
		Kind:     runtimeevent.KindDNS,
		CgroupID: binary.LittleEndian.Uint64(b[offCgroupID : offCgroupID+8]),
		Count:    1,
		DNS:      &runtimeevent.DNSFacts{QName: name},
	}, nil
}

// decodeWireName turns a length-prefixed label sequence into a dotted name. The
// terminating root label is not part of the input.
//
// A zero-length input is the root question and decodes to "" rather than an
// error: it is a legal question, just not one any policy names.
func decodeWireName(wire []byte) (string, error) {
	if len(wire) == 0 {
		return "", nil
	}

	var sb strings.Builder
	sb.Grow(len(wire))

	for i := 0; i < len(wire); {
		n := int(wire[i])
		// A question carries no compression pointer, and the two high bits are
		// reserved otherwise, so anything above 63 is malformed. This subsumes
		// the maximum label length.
		if n&0xc0 != 0 {
			return "", fmt.Errorf("%w: length byte 0x%02x at offset %d is a pointer or reserved",
				ErrBadName, wire[i], i)
		}
		if n == 0 {
			return "", fmt.Errorf("%w: empty label at offset %d", ErrBadName, i)
		}
		if i+1+n > len(wire) {
			return "", fmt.Errorf("%w: label at offset %d claims %d bytes, only %d remain",
				ErrBadName, i, n, len(wire)-i-1)
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(wire[i+1 : i+1+n])
		i += 1 + n
	}

	return sb.String(), nil
}
