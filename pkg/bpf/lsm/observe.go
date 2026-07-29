package lsm

import (
	"errors"
	"fmt"
	"math"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf"
)

// ErrObservationUnavailable is returned when the loaded program has no
// open_events hash-of-maps (or it could not be prepared), so per-cgid path
// counting cannot be turned on.
var ErrObservationUnavailable = errors.New("lsm: observation maps unavailable")

// PathEventKey identifies one observation counter: a path (or exec filename)
// plus the enforcement verdict the kernel program applied to the operation.
type PathEventKey struct {
	Path    string
	Verdict runtimeevent.KernelVerdict
}

// pathEventKernelKey is the kernel layout of `struct path_event_key` in
// _cprog/maps.h: a NUL-padded 128-byte path followed by a naturally-aligned
// __u32 verdict, 132 bytes, no padding. It is kept separate from the exported
// PathEventKey so the iterator key's size and layout match the loaded map's
// BTF key exactly (cilium/ebpf rejects a mismatch).
type pathEventKernelKey struct {
	Path    [maxPathLen]byte
	Verdict uint32
}

// EnableObservation creates (or reuses) an inner hash map in open_events for
// each cgid so the kernel program starts recording path counts for it.
//
// Every cgid is attempted; failures are collected and joined so one bad cgid
// cannot stop the rest from being enabled.
func (l *LsmEnforcer) EnableObservation(cgids []uint64) error {
	if len(cgids) == 0 {
		return nil
	}
	if l.openEvents == nil || l.innerSpec == nil {
		return ErrObservationUnavailable
	}

	l.observeMu.Lock()
	defer l.observeMu.Unlock()
	if l.observed == nil {
		l.observed = make(map[uint64]*ebpf.Map, len(cgids))
	}

	var errs []error
	for _, cgid := range cgids {
		if _, ok := l.observed[cgid]; ok {
			continue
		}
		// The kernel may already hold an inner map for this cgid (another
		// enforcer, or a restart); reuse it instead of replacing it.
		if inner, err := l.lookupInner(cgid); err == nil {
			l.observed[cgid] = inner
			continue
		}

		inner, err := ebpf.NewMap(l.innerSpec)
		if err != nil {
			errs = append(errs, fmt.Errorf("creating observation map for cgid %d: %w", cgid, err))
			continue
		}
		if err := l.openEvents.Update(&cgid, inner, ebpf.UpdateAny); err != nil {
			_ = inner.Close()
			errs = append(errs, fmt.Errorf("registering observation map for cgid %d: %w", cgid, err))
			continue
		}
		l.observed[cgid] = inner
	}
	return errors.Join(errs...)
}

// DisableObservation removes the open_events entry for each cgid and releases
// the inner map. A cgid that was never enabled is not an error.
func (l *LsmEnforcer) DisableObservation(cgids []uint64) error {
	if len(cgids) == 0 {
		return nil
	}
	if l.openEvents == nil {
		return ErrObservationUnavailable
	}

	l.observeMu.Lock()
	defer l.observeMu.Unlock()

	var errs []error
	for _, cgid := range cgids {
		if err := l.openEvents.Delete(&cgid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("removing observation map for cgid %d: %w", cgid, err))
		}
		if inner, ok := l.observed[cgid]; ok {
			if err := inner.Close(); err != nil {
				errs = append(errs, fmt.Errorf("closing observation map for cgid %d: %w", cgid, err))
			}
			delete(l.observed, cgid)
		}
	}
	return errors.Join(errs...)
}

// ReadEvents reads and RESETS the per-cgid path counts.
//
// EVERY cgid in cgids is visited: a cgid with no inner map is skipped (not an
// error) and a read failure for one cgid is recorded and joined at the end
// rather than returned immediately. That structure is deliberate — an early
// `break` here once made the counts of every enforcer after the first
// invisible.
func (l *LsmEnforcer) ReadEvents(cgids []uint64) (map[uint64]map[PathEventKey]uint32, error) {
	out := make(map[uint64]map[PathEventKey]uint32, len(cgids))
	if len(cgids) == 0 {
		return out, nil
	}
	if l.openEvents == nil {
		return out, ErrObservationUnavailable
	}

	var errs []error
	for _, cgid := range cgids {
		inner, owned, err := l.innerFor(cgid)
		if err != nil {
			// no inner map for this cgid: nothing was observed. keep going.
			continue
		}

		counts, err := readAndResetCounts(inner)
		if !owned {
			// a handle we opened just for this read
			_ = inner.Close()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("reading observations for cgid %d: %w", cgid, err))
			// counts may still hold what was read before the failure; fold it in.
		}
		if len(counts) == 0 {
			continue
		}
		if out[cgid] == nil {
			out[cgid] = make(map[PathEventKey]uint32, len(counts))
		}
		mergeCounts(out[cgid], counts)
	}
	return out, errors.Join(errs...)
}

// innerFor returns the inner map for cgid. owned is true when the handle is the
// long-lived one this enforcer created (callers must not close it).
func (l *LsmEnforcer) innerFor(cgid uint64) (m *ebpf.Map, owned bool, err error) {
	l.observeMu.Lock()
	inner, ok := l.observed[cgid]
	l.observeMu.Unlock()
	if ok {
		return inner, true, nil
	}

	inner, err = l.lookupInner(cgid)
	if err != nil {
		return nil, false, err
	}
	return inner, false, nil
}

// lookupInner fetches the inner map registered for cgid from the kernel.
func (l *LsmEnforcer) lookupInner(cgid uint64) (*ebpf.Map, error) {
	if l.openEvents == nil {
		return nil, ErrObservationUnavailable
	}
	var inner *ebpf.Map
	if err := l.openEvents.Lookup(&cgid, &inner); err != nil {
		return nil, err
	}
	if inner == nil {
		return nil, ebpf.ErrKeyNotExist
	}
	return inner, nil
}

// readAndResetCounts drains one inner path->count map. Keys are collected
// before deletion because deleting during iteration can make the kernel restart
// the walk. Whatever was read is returned even when the sweep errors.
func readAndResetCounts(m *ebpf.Map) (map[PathEventKey]uint32, error) {
	counts := make(map[PathEventKey]uint32)
	keys := make([]pathEventKernelKey, 0, 16)

	var (
		key   pathEventKernelKey
		count uint32
	)
	it := m.Iterate()
	for it.Next(&key, &count) {
		keys = append(keys, key)
		if count == 0 {
			continue
		}
		path := trimPathKey(key.Path)
		if path == "" {
			continue
		}
		ek := PathEventKey{Path: path, Verdict: runtimeevent.KernelVerdict(key.Verdict)}
		mergeCounts(counts, map[PathEventKey]uint32{ek: count})
	}

	var errs []error
	if err := it.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterating open_events inner map: %w", err))
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("resetting count for %q: %w", trimPathKey(keys[i].Path), err))
		}
	}
	return counts, errors.Join(errs...)
}

// trimPathKey turns a fixed-size, NUL-padded kernel path key into a string.
func trimPathKey(key [maxPathLen]byte) string {
	for i, b := range key {
		if b == 0 {
			return string(key[:i])
		}
	}
	return string(key[:])
}

// mergeCounts folds src into dst, adding counts for (path, verdict) keys
// present in both. The addition saturates instead of wrapping: a wrapped
// counter would report a busy path as quiet, which is the wrong direction for
// a security signal.
func mergeCounts(dst, src map[PathEventKey]uint32) {
	if dst == nil {
		return
	}
	for key, count := range src {
		existing := dst[key]
		if count > math.MaxUint32-existing {
			dst[key] = math.MaxUint32
			continue
		}
		dst[key] = existing + count
	}
}
