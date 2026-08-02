package compiler

import (
	"errors"
	"fmt"
	"strings"
)

// MaxExecPathLen bounds a program path value. The banned and allowed maps are
// keyed by char[128] filled with bpf_probe_read_kernel_str, so every key the
// kernel can ever look up holds at most 127 bytes plus its NUL terminator: a
// 128-byte value would be programmed into a key no exec or open can produce.
const MaxExecPathLen = 127

// Sentinel errors returned by ParseExecValue. They are deliberately terse:
// callers that surface them to operators (admission's field errors, the
// enforcer's rejected-path conditions) map them into their own remedy-bearing
// vocabulary.
var (
	// ErrEmptyExecValue reports a value that is empty after trimming.
	ErrEmptyExecValue = errors.New("empty path")
	// ErrNULInExecValue reports an interior NUL byte, which no kernel path can
	// contain.
	ErrNULInExecValue = errors.New("path contains a NUL byte")
	// ErrExecValueTooLong reports a value longer than MaxExecPathLen.
	ErrExecValueTooLong = fmt.Errorf("path is longer than %d bytes", MaxExecPathLen)
)

// ExecValue is the parsed form of one program path value. Exactly one of the
// fields is meaningful: Star for the "*" sentinel, Path for a literal path.
type ExecValue struct {
	// Star is true when the value is the StarTarget sentinel.
	Star bool
	// Path is the literal path the kernel maps are keyed on, byte for byte.
	Path string
}

// ParseExecValue parses one policy-authored program path value. This is the ONE
// definition of that grammar: admission validation (validateExecBehavior),
// program-time key derivation (lsm.ParsePaths) and monitor-mode matching
// (monitor.newPathMatcher) all consume it, so they cannot disagree about what a
// value is. The open behavior's paths share it because they are programmed into
// the same kernel maps.
//
// The value is trimmed of surrounding whitespace — quotes and brackets are not
// trimmed, unlike ParseNetworkValue, because they are legal path bytes. Then:
//
//   - StarTarget ("*") yields Star
//   - anything else yields Path, a literal never split into tokens and never
//     interpreted as a glob
//   - an empty, NUL-bearing or over-long value is an error
func ParseExecValue(raw string) (ExecValue, error) {
	cleaned := strings.Trim(raw, " \t\r\n")

	switch {
	case cleaned == "":
		return ExecValue{}, ErrEmptyExecValue

	case cleaned == StarTarget:
		return ExecValue{Star: true}, nil

	case strings.IndexByte(cleaned, 0) >= 0:
		return ExecValue{}, ErrNULInExecValue

	case len(cleaned) > MaxExecPathLen:
		return ExecValue{}, ErrExecValueTooLong

	default:
		return ExecValue{Path: cleaned}, nil
	}
}
