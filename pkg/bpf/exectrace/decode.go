// Package exectrace decodes process-execution events emitted by the kernel
// program in _cprog/exec.bpf.c.
//
// This is an observation-only complement to the LSM exec hook in pkg/bpf/lsm:
// the LSM program decides, this one reports argv, which is what identifies a
// stdio MCP server (`npx @modelcontextprotocol/...`, `uvx ...`, `python -m ...`).
//
// The decoder is a pure function over kernel-supplied bytes. Per the no-panic
// rule it never indexes without a length check and returns an error for every
// truncated or malformed input.
package exectrace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// Byte layout of `struct exec_event` in _cprog/exec.bpf.c. Little-endian, in
// the natural C field order with no internal padding:
//
//	off   size  field
//	   0     8  cgroup_id  __u64
//	   8     4  pid        __u32   (tgid, i.e. the userspace "pid")
//	  12     4  ppid       __u32
//	  16    16  comm       char[16] (NUL-padded, may be unterminated)
//	  32     2  argv_len   __u16    (number of populated argv slots, <= 8)
//	  34   256  filename   char[256]
//	 290  1024  argv       char[8][128]
//
// The C struct's sizeof is 1320 (8-byte alignment adds 6 trailing pad bytes);
// the decoder only requires the first EventSize bytes and ignores trailing
// padding.
const (
	// MaxArgs is the number of argv slots the kernel program copies. Anything
	// beyond it is dropped in the kernel: an exec with more arguments is
	// reported truncated, never rejected.
	MaxArgs = 8
	// MaxArgLen is the size of one argv slot. An argument longer than this is
	// stored unterminated and decodes to its first MaxArgLen bytes.
	MaxArgLen = 128
	// MaxFilename is the size of the filename field.
	MaxFilename = 256

	commLen = 16

	offCgroupID = 0
	offPID      = 8
	offPPID     = 12
	offComm     = 16
	offArgvLen  = 32
	offFilename = 34
	offArgv     = offFilename + MaxFilename // 290

	// EventSize is the minimum number of bytes DecodeExecEvent needs.
	EventSize = offArgv + MaxArgs*MaxArgLen // 1314
)

var (
	// ErrTruncated means the kernel handed over fewer bytes than the layout
	// requires; the Go and C sides disagree, or the record is damaged.
	ErrTruncated = errors.New("exectrace: truncated kernel event")
	// ErrBadArgvLen means argv_len is larger than the kernel can produce,
	// which can only mean the layouts have drifted apart.
	ErrBadArgvLen = errors.New("exectrace: invalid argv count")
)

// DecodeExecEvent converts one kernel exec event record into a normalized
// event.
//
// Time is left zero: the record carries no timestamp, so the source stamps it.
// Count is 1 — every ring buffer record is one observed exec.
func DecodeExecEvent(b []byte) (runtimeevent.Event, error) {
	if len(b) < EventSize {
		return runtimeevent.Event{}, fmt.Errorf("%w: got %d bytes, want at least %d",
			ErrTruncated, len(b), EventSize)
	}

	n := int(binary.LittleEndian.Uint16(b[offArgvLen : offArgvLen+2]))
	if n > MaxArgs {
		return runtimeevent.Event{}, fmt.Errorf("%w: argv_len %d exceeds %d",
			ErrBadArgvLen, n, MaxArgs)
	}

	var argv []string
	if n > 0 {
		argv = make([]string, 0, n)
		for i := 0; i < n; i++ {
			start := offArgv + i*MaxArgLen
			argv = append(argv, cString(b[start:start+MaxArgLen]))
		}
	}

	return runtimeevent.Event{
		Kind:     runtimeevent.KindExec,
		CgroupID: binary.LittleEndian.Uint64(b[offCgroupID : offCgroupID+8]),
		PID:      binary.LittleEndian.Uint32(b[offPID : offPID+4]),
		Comm:     cString(b[offComm : offComm+commLen]),
		Count:    1,
		Exec: &runtimeevent.ExecFacts{
			Filename: cString(b[offFilename : offFilename+MaxFilename]),
			Argv:     argv,
			PPID:     binary.LittleEndian.Uint32(b[offPPID : offPPID+4]),
		},
	}, nil
}

// cString trims a fixed-width, NUL-padded kernel char array. A buffer with no
// NUL at all (the kernel truncated the value) yields the whole buffer.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
