package compiler

import (
	"errors"
	"fmt"
	"strings"
)

// MaxPathValueLen bounds an exec or open path value. The banned and allowed maps are
// keyed by char[128] filled with bpf_probe_read_kernel_str, so every key the
// kernel can ever look up holds at most 127 bytes plus its NUL terminator: a
// 128-byte value would be programmed into a key no exec or open can produce.
const MaxPathValueLen = 127

// Sentinel errors returned by ParsePathValue. They are deliberately terse:
// callers that surface them to operators (admission's field errors, the
// enforcer's rejected-path conditions) map them into their own remedy-bearing
// vocabulary.
var (
	// ErrEmptyPathValue reports a value that is empty after trimming.
	ErrEmptyPathValue = errors.New("empty path")
	// ErrNULInPathValue reports an interior NUL byte, which no kernel path can
	// contain.
	ErrNULInPathValue = errors.New("path contains a NUL byte")
	// ErrPathValueTooLong reports a value longer than MaxPathValueLen.
	ErrPathValueTooLong = fmt.Errorf("path is longer than %d bytes", MaxPathValueLen)
	// ErrRelativePathValue reports a value that is not an absolute path. The
	// kernel resolves every path it can match with bpf_d_path, which always
	// yields one, so a relative value programs a key nothing can ever produce.
	ErrRelativePathValue = errors.New("path must be absolute: the kernel matches resolved paths, so a bare program name never matches")
	// ErrPaddedStarValue reports a value that trims to the StarTarget sentinel
	// without being exactly it. The sentinel switches the whole behavior to
	// default deny, so a near-miss is corrected by the author, not normalized.
	ErrPaddedStarValue = errors.New(`the default-deny wildcard must be written exactly as "*"`)
)

// PathValue is the parsed form of one exec or open path value. Exactly one of the
// fields is meaningful: Star for the "*" sentinel, Path for a literal path.
type PathValue struct {
	// Star is true when the value is the StarTarget sentinel.
	Star bool
	// Path is the literal path the kernel maps are keyed on, byte for byte.
	Path string
}

// ParsePathValue parses one policy-authored exec or open path value. This is the
// ONE definition of that grammar: admission validation (validatePathBehavior),
// program-time key derivation (lsm.ParsePaths) and monitor-mode matching
// (monitor.newPathMatcher) all consume it, so they cannot disagree about what a
// value is. Exec and open share it because they are programmed into the same
// kernel maps.
//
// The value is trimmed of surrounding whitespace — quotes and brackets are not
// trimmed, unlike ParseNetworkValue, because they are legal path bytes. Then:
//
//   - StarTarget ("*"), written exactly, yields Star; a value that merely
//     trims to it is an error
//   - anything else yields Path, a literal never split into tokens and never
//     interpreted as a glob
//   - an empty, NUL-bearing, over-long or relative value is an error
func ParsePathValue(raw string) (PathValue, error) {
	cleaned := strings.Trim(raw, " \t\r\n")

	switch {
	case cleaned == "":
		return PathValue{}, ErrEmptyPathValue

	case cleaned == StarTarget:
		if raw != StarTarget {
			return PathValue{}, ErrPaddedStarValue
		}
		return PathValue{Star: true}, nil

	case strings.IndexByte(cleaned, 0) >= 0:
		return PathValue{}, ErrNULInPathValue

	case len(cleaned) > MaxPathValueLen:
		return PathValue{}, ErrPathValueTooLong

	case cleaned[0] != '/':
		return PathValue{}, ErrRelativePathValue

	default:
		return PathValue{Path: cleaned}, nil
	}
}
