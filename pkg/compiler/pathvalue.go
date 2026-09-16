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

// Sentinel errors returned by ParsePathValue. Their text reaches operators
// unchanged, through admission's field errors and through the rejected-path
// policy conditions, so each one names the remedy and not just the fault.
var (
	// ErrEmptyPathValue reports a value that is empty after trimming.
	ErrEmptyPathValue = errors.New("empty path value")
	// ErrNULInPathValue reports an interior NUL byte. A path key is NUL-padded
	// and read back with bpf_probe_read_kernel_str, so a value carrying its own
	// NUL keys an entry no exec or open can ever produce.
	ErrNULInPathValue = errors.New("path contains a NUL byte: kernel paths are NUL-terminated strings")
	// ErrPathValueTooLong reports a value longer than MaxPathValueLen.
	ErrPathValueTooLong = fmt.Errorf("path is longer than %d bytes: the kernel path maps cannot hold it", MaxPathValueLen)
	// ErrRelativePathValue reports a value that is not an absolute path. The
	// kernel resolves every path it can match with bpf_d_path, which always
	// yields one, so a relative value programs a key nothing can ever produce.
	ErrRelativePathValue = errors.New("path must be absolute: the kernel matches resolved paths, so a bare program name never matches")
	// ErrPaddedStarValue reports a value that trims to the StarTarget sentinel
	// without being exactly it. The sentinel switches the whole behavior to
	// default deny, so a near-miss is corrected by the author, not normalized.
	ErrPaddedStarValue = errors.New(`the default-deny wildcard must be written exactly as "*"`)
	// ErrStarInPathValue reports a "*" anywhere other than the whole value or
	// the end of a directory prefix.
	ErrStarInPathValue = errors.New(`a "*" is only accepted as the whole value or as a trailing "/*": write a directory as "/usr/lib/*"`)
	// ErrTrailingSlashPathValue reports a literal ending in "/". bpf_d_path
	// never yields one, so such a value matches nothing.
	ErrTrailingSlashPathValue = errors.New(`a path must not end in "/": to cover a directory write "/usr/lib/*"`)
)

// MaxPrefixDepth bounds how deep a directory prefix can match: only the first
// MaxPrefixDepth separators of an observed path are turned into a prefix key,
// in the kernel and in AncestorDirs alike, because the kernel loop that walks
// them has to be bounded for the verifier.
const MaxPrefixDepth = 16

// PathValue is the parsed form of one exec or open path value. Exactly one of the
// fields is meaningful: Star for the "*" sentinel, Path for a literal path,
// Prefix for a directory.
type PathValue struct {
	// Star is true when the value is the StarTarget sentinel.
	Star bool
	// Path is the literal path the kernel maps are keyed on, byte for byte.
	Path string
	// Prefix is the directory a "/*" value covers, keeping its trailing "/" so
	// that "/usr/lib/" cannot match "/usr/library".
	Prefix string
}

// ParsePathValue parses one policy-authored exec or open path value. This is
// the one definition of the exec and open value schema: admission validation,
// program-time key derivation and monitor-mode matching all reach it through
// ParsePathList, so they cannot disagree about what a value is. Exec and open
// share it because they are programmed into the same kernel maps.
//
// The value is trimmed of surrounding whitespace — quotes and brackets are not
// trimmed, unlike ParseNetworkValue, because they are legal path bytes. Then:
//
//   - StarTarget ("*"), written exactly, yields Star; a value that merely
//     trims to it is an error
//   - a value ending in "/*" yields Prefix, the directory it covers at any
//     depth
//   - anything else yields Path, a literal never split into tokens and never
//     interpreted as a glob
//   - an empty, NUL-bearing, over-long or relative value is an error, and so is
//     a "*" in any other position
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

	case strings.HasSuffix(cleaned, "/*"):
		prefix := strings.TrimSuffix(cleaned, StarTarget)
		if strings.ContainsRune(prefix, '*') {
			return PathValue{}, ErrStarInPathValue
		}
		return PathValue{Prefix: prefix}, nil

	case strings.ContainsRune(cleaned, '*'):
		return PathValue{}, ErrStarInPathValue

	case strings.HasSuffix(cleaned, "/"):
		return PathValue{}, ErrTrailingSlashPathValue

	default:
		return PathValue{Path: cleaned}, nil
	}
}

// AncestorDirs returns the directory prefixes a path is covered by, each
// keeping its trailing "/", shallowest first: "/usr/lib/libc.so" yields "/",
// "/usr/" and "/usr/lib/". This is the list the kernel walks, so a prefix
// matching here matches there.
func AncestorDirs(path string) []string {
	var dirs []string
	for i := 0; i < len(path) && len(dirs) < MaxPrefixDepth; i++ {
		if path[i] == '/' {
			dirs = append(dirs, path[:i+1])
		}
	}
	return dirs
}

// ParsePathList splits one behavior's path values into the four groups every
// consumer needs: the literal paths, the directory prefixes, whether the
// default-deny sentinel is present, and the values that could not be parsed.
// Both lists are de-duplicated, preserving first-seen order.
//
// The kernel enforcer keys its maps off this, and monitor mode matches off it,
// so neither can hold a path the other does not.
func ParsePathList(values []string) (paths, prefixes []string, star bool, rejected []RejectedTarget) {
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		v, err := ParsePathValue(raw)
		switch {
		case err != nil:
			rejected = append(rejected, RejectedTarget{Value: raw, Reason: err.Error()})
		case v.Star:
			star = true
		case v.Prefix != "":
			if _, dup := seen[v.Prefix]; dup {
				continue
			}
			seen[v.Prefix] = struct{}{}
			prefixes = append(prefixes, v.Prefix)
		default:
			if _, dup := seen[v.Path]; dup {
				continue
			}
			seen[v.Path] = struct{}{}
			paths = append(paths, v.Path)
		}
	}
	return paths, prefixes, star, rejected
}
