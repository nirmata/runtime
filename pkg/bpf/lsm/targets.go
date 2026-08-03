package lsm

import (
	"errors"
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

// PathKey is the char[MAX_PATH_LEN] key of the banned and allowed maps: the
// path's bytes, NUL-padded, exactly as bpf_probe_read_kernel_str leaves it.
type PathKey = [maxPathLen]byte

// Rejection reasons. They are surfaced verbatim to operators (V(0) logs and
// policy status conditions), so they explain the remedy, not just the fault.
var (
	ReasonEmptyPath   = "empty path value"
	ReasonNULInPath   = "path contains a NUL byte: kernel paths are NUL-terminated strings"
	ReasonPathTooLong = fmt.Sprintf("path is longer than %d bytes: the kernel path maps cannot hold it", compiler.MaxPathValueLen)
)

// RejectedTarget is a path value that could not be turned into a map key,
// together with the reason. Rejections are returned as typed values (never
// dropped, never folded into an error) so callers can log them and attach them
// to policy status.
type RejectedTarget struct {
	Value  string
	Reason string
}

func (r RejectedTarget) String() string {
	return fmt.Sprintf("%q: %s", r.Value, r.Reason)
}

// ParsePaths converts policy-authored path values into the keys the banned and
// allowed maps hold.
//
// The grammar is defined once, in compiler.ParsePathValue. ParsePaths is the
// only place a value becomes a key, so AddTargets and DeleteTargets cannot
// disagree about which values are programmed; a value that cannot become a key
// comes back in rejected rather than being skipped.
//
// compiler.StarTarget ("*") sets star and yields no key; it is the default-deny
// sentinel SetDefaultDeny carries, not a path.
func ParsePaths(values []string) (keys []PathKey, star bool, rejected []RejectedTarget) {
	seen := make(map[PathKey]struct{}, len(values))
	for _, raw := range values {
		v, err := compiler.ParsePathValue(raw)
		if err != nil {
			rejected = append(rejected, RejectedTarget{Value: raw, Reason: rejectionReason(err)})
			continue
		}
		if v.Star {
			star = true
			continue
		}
		key := PathKey{}
		copy(key[:], v.Path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys, star, rejected
}

func rejectionReason(err error) string {
	switch {
	case errors.Is(err, compiler.ErrEmptyPathValue):
		return ReasonEmptyPath
	case errors.Is(err, compiler.ErrNULInPathValue):
		return ReasonNULInPath
	case errors.Is(err, compiler.ErrPathValueTooLong):
		return ReasonPathTooLong
	default:
		return err.Error()
	}
}
