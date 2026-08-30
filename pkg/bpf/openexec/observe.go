package openexec

import (
	"errors"
	"fmt"
	"math"

	"github.com/cilium/ebpf"
)

// ErrObservationUnavailable is returned when the loaded program has no usable
// open_events hash-of-maps, so per-cgid path counting cannot be turned on.
var ErrObservationUnavailable = errors.New("lsm: observation maps unavailable")

// pathEventKernelKey mirrors `struct path_event_key` in _cprog/maps.h.
// cilium/ebpf rejects a key whose Go layout does not match the loaded map's BTF
// key.
type PathEventKernelKey struct {
	Path     [maxPathLen]byte
	Decision uint32
}

func NewKernelKeyFromGoTypes(path string, d uint32) (PathEventKernelKey, error) {
	if len(path) > maxPathLen {
		return PathEventKernelKey{}, fmt.Errorf("invalid length. got %d but the maximum allowed is %d", len(path), maxPathLen)
	}

	pathArr := [maxPathLen]byte{}
	copy(pathArr[:], path)

	return PathEventKernelKey{
		Path:     pathArr,
		Decision: d,
	}, nil
}

// EnableObservation creates (or reuses) an inner hash map in open_events for
// each cgid so the kernel program starts recording path counts for it.
func (l *Prog) EnableObservation(cgids []uint64) error {
	if len(cgids) == 0 {
		return nil
	}
	if l.eventsMap == nil || l.innerSpec == nil {
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
		if err := l.eventsMap.Update(&cgid, inner, ebpf.UpdateAny); err != nil {
			_ = inner.Close()
			errs = append(errs, fmt.Errorf("registering observation map for cgid %d: %w", cgid, err))
			continue
		}
		l.observed[cgid] = inner
	}
	return errors.Join(errs...)
}

// DisableObservation removes the events_map entry for each cgid and releases
// the inner map. A cgid that was never enabled is not an error.
func (l *Prog) DisableObservation(cgids []uint64) error {
	if len(cgids) == 0 {
		return nil
	}
	if l.eventsMap == nil {
		return ErrObservationUnavailable
	}

	l.observeMu.Lock()
	defer l.observeMu.Unlock()

	var errs []error
	for _, cgid := range cgids {
		if err := l.eventsMap.Delete(&cgid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
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

// ReadEvents reads and resets the per-cgid path counts. Every cgid is visited
// even when one of them fails, so a single bad cgid cannot hide the counts of
// the rest.
func (l *Prog) ReadEvents() (map[uint64]map[PathEventKernelKey]uint32, error) {
	out := make(map[uint64]map[PathEventKernelKey]uint32)
	if l.eventsMap == nil {
		return out, ErrObservationUnavailable
	}

	var (
		k       uint64
		innerFd uint32

		errs []error
	)

	iter := l.eventsMap.Iterate()
	for iter.Next(&k, &innerFd) {
		innerMap, err := ebpf.NewMapFromFD(int(innerFd))
		if err != nil {
			return nil, err
		}

		counts, err := readAndResetCounts(innerMap)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[k] = counts
	}

	return out, errors.Join(errs...)
}

// pathStatCountMapFull mirrors PATH_STAT_COUNT_MAP_FULL in _cprog/maps.h.
const pathStatCountMapFull = uint32(0)

// ReadEventsLost reports open/exec observations the kernel program could not
// record because the cgid's count map was full. It shares ReadEvents' single
// caller, so statLast needs no lock of its own.
func (l *Prog) ReadEventsLost() (uint64, error) {
	if l.stats == nil {
		return 0, ErrObservationUnavailable
	}

	key := pathStatCountMapFull
	var perCPU []uint64
	if err := l.stats.Lookup(&key, &perCPU); err != nil {
		return 0, fmt.Errorf("reading lost observation counter: %w", err)
	}

	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return l.lostSince(sum), nil
}

// lostSince turns the kernel's cumulative counter into a per-call delta. A
// total below the previous one means the map behind it was replaced, so the
// baseline moves with it rather than reporting a negative interval as a huge
// positive one.
func (l *Prog) lostSince(sum uint64) uint64 {
	last := l.statLast
	l.statLast = sum
	if sum < last {
		return 0
	}
	return sum - last
}

// innerFor returns the inner map for cgid. owned is true when the handle is the
// long-lived one this enforcer created, which callers must not close.
func (l *Prog) innerFor(cgid uint64) (m *ebpf.Map, owned bool, err error) {
	l.observeMu.RLock()
	inner, ok := l.observed[cgid]
	l.observeMu.RUnlock()
	if ok {
		return inner, true, nil
	}

	inner, err = l.lookupInner(cgid)
	if err != nil {
		return nil, false, err
	}
	return inner, false, nil
}

func (l *Prog) lookupInner(cgid uint64) (*ebpf.Map, error) {
	if l.eventsMap == nil {
		return nil, ErrObservationUnavailable
	}
	var inner *ebpf.Map
	if err := l.eventsMap.Lookup(&cgid, &inner); err != nil {
		return nil, err
	}
	if inner == nil {
		return nil, ebpf.ErrKeyNotExist
	}
	return inner, nil
}

// readAndResetCounts drains one inner path->count map. Keys are collected
// before deletion because deleting during iteration can make the kernel restart
// the walk.
func readAndResetCounts(m *ebpf.Map) (map[PathEventKernelKey]uint32, error) {
	counts := make(map[PathEventKernelKey]uint32)
	keys := make([]PathEventKernelKey, 0, 16) // store keys so we later delete them from the inner map after reading

	var (
		key   PathEventKernelKey
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

		mergeCounts(counts, map[PathEventKernelKey]uint32{key: count})
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

// mergeCounts folds src into dst. The addition saturates rather than wrapping,
// so a busy path can never be reported as quiet.
func mergeCounts(dst, src map[PathEventKernelKey]uint32) {
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
