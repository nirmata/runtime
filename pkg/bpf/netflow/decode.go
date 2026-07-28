// Package netflow decodes egress connection events emitted by the kernel
// program in _cprog/netflow.bpf.c.
//
// The decoder is a pure function over kernel-supplied bytes. Per the no-panic
// rule it never indexes without a length check and returns an error for every
// truncated or malformed input.
package netflow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// Byte layout of `struct flow_event` in _cprog/netflow.bpf.c. Little-endian, in
// the natural C field order with no padding at all (sizeof == 64):
//
//	off  size  field
//	  0     8  cgroup_id  __u64
//	  8     4  pid        __u32
//	 12    16  saddr      __u8[16]  (IPv4 in the first 4 bytes, rest zero)
//	 28    16  daddr      __u8[16]  (IPv4 in the first 4 bytes, rest zero)
//	 44     2  dport      __u16     (already host-order: the C swaps it)
//	 46     1  proto      __u8      (IANA protocol number)
//	 47     1  ip_ver     __u8      (4 or 6)
//	 48    16  comm       char[16]  (NUL-padded, may be unterminated)
const (
	addrLen = 16
	commLen = 16

	offCgroupID = 0
	offPID      = 8
	offSaddr    = 12
	offDaddr    = 28
	offDport    = 44
	offProto    = 46
	offIPVer    = 47
	offComm     = 48

	// EventSize is the minimum number of bytes DecodeFlowEvent needs.
	EventSize = offComm + commLen // 64
)

// IANA protocol numbers the decoder names. Anything else leaves
// NetFacts.Protocol empty, which is a documented value, not an error.
const (
	protoTCP = 6
	protoUDP = 17
)

var (
	// ErrTruncated means the kernel handed over fewer bytes than the layout
	// requires; the Go and C sides disagree, or the record is damaged.
	ErrTruncated = errors.New("netflow: truncated kernel event")
	// ErrBadIPVersion means ip_ver was neither 4 nor 6.
	ErrBadIPVersion = errors.New("netflow: unsupported ip version")
)

// DecodeFlowEvent converts one kernel flow event record into a normalized
// event.
//
// The source address is present in the record for future use (flow keying) but
// has no home in runtimeevent.NetFacts, so it is intentionally dropped here.
//
// Time is left zero: the record carries no timestamp, so the source stamps it.
// Count is 1 — every ring buffer record is one observed connection.
func DecodeFlowEvent(b []byte) (runtimeevent.Event, error) {
	if len(b) < EventSize {
		return runtimeevent.Event{}, fmt.Errorf("%w: got %d bytes, want at least %d",
			ErrTruncated, len(b), EventSize)
	}

	var raw [addrLen]byte
	copy(raw[:], b[offDaddr:offDaddr+addrLen])

	var dest netip.Addr
	switch v := b[offIPVer]; v {
	case 4:
		dest = netip.AddrFrom4([4]byte(raw[:4]))
	case 6:
		// Unmap normalizes a ::ffff:a.b.c.d destination to plain IPv4 so
		// policy CIDR matching sees one canonical form.
		dest = netip.AddrFrom16(raw).Unmap()
	default:
		return runtimeevent.Event{}, fmt.Errorf("%w: ip_ver %d", ErrBadIPVersion, v)
	}

	return runtimeevent.Event{
		Kind:     runtimeevent.KindNet,
		CgroupID: binary.LittleEndian.Uint64(b[offCgroupID : offCgroupID+8]),
		PID:      binary.LittleEndian.Uint32(b[offPID : offPID+4]),
		Comm:     cString(b[offComm : offComm+commLen]),
		Count:    1,
		Net: &runtimeevent.NetFacts{
			DestIP:   dest,
			DestPort: binary.LittleEndian.Uint16(b[offDport : offDport+2]),
			Protocol: protocolName(b[offProto]),
		},
	}, nil
}

// protocolName maps an IANA protocol number onto the lowercase names
// runtimeevent.NetFacts documents. Unknown protocols yield "".
func protocolName(p uint8) string {
	switch p {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	default:
		return ""
	}
}

// cString trims a fixed-width, NUL-padded kernel char array. A buffer with no
// NUL at all (the kernel truncated the value) yields the whole buffer.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
