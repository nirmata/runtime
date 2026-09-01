package openexec

import (
	"errors"
	"fmt"
	"math"

	"github.com/cilium/ebpf"
)

// ErrObservationUnavailable reports that the loaded collection carries no
// events_map hash-of-maps, so per-cgid path counting cannot be turned on.
var ErrObservationUnavailable = errors.New("lsm: observation maps unavailable")

// PathEventKey identifies one observation counter: a path (or exec filename)
// plus the enforcement decision the kernel program applied to the operation.
// It mirrors `struct path_event_key` in _cprog/maps.h byte for byte — it is
// the map key cilium/ebpf marshals directly, and a layout drift from the BTF
// key is rejected at runtime.
type PathEventKey struct {
	Path     [maxPathLen]byte
	Decision uint32
}

// PathString returns the path without the NUL padding the kernel key carries.
func (k PathEventKey) PathString() string {
	for i, b := range k.Path {
		if b == 0 {
			return string(k.Path[:i])
		}
	}
	return string(k.Path[:])
}

// EnableObservation creates (or reuses) an inner hash map in events_map for
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

	var errs []error
	for _, cgid := range cgids {
		if _, ok := l.observed[cgid]; ok {
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

// ReadEvents reads and resets the path counts of every observed cgid, through
// the long-lived inner-map handles EnableObservation created. Every cgid is
// visited even when one of them fails, so a single bad map cannot hide the
// counts of the rest.
func (l *Prog) ReadEvents() (map[uint64]map[PathEventKey]uint32, error) {
	out := make(map[uint64]map[PathEventKey]uint32)
	if l.eventsMap == nil {
		return out, ErrObservationUnavailable
	}

	l.observeMu.RLock()
	defer l.observeMu.RUnlock()

	var errs []error
	for cgid, inner := range l.observed {
		counts, err := readAndResetCounts(inner)
		if err != nil {
			errs = append(errs, fmt.Errorf("reading observations for cgid %d: %w", cgid, err))
		}
		if len(counts) == 0 {
			continue
		}
		out[cgid] = counts
	}
	return out, errors.Join(errs...)
}

// pathStatCountMapFull is the PATH_STAT_COUNT_MAP_FULL slot of the stats map.
const pathStatCountMapFull = uint32(0)

// ReadEventsLost reports open/exec observations the kernel program could not
// record because the cgid's count map was full. It shares ReadEvents' single
// caller, so statLast needs no lock of its own.
func (l *Prog) ReadEventsLost() (uint64, error) {
	if l.stats == nil {
		return 0, ErrObservationUnavailable
	}

	var perCPU []uint64
	if err := l.stats.Lookup(pathStatCountMapFull, &perCPU); err != nil {
		return 0, fmt.Errorf("reading path stats: %w", err)
	}

	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return l.lostSince(sum), nil
}

// lostSince converts the kernel's cumulative counter into an interval delta. A
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

// readAndResetCounts drains one inner path->count map. Keys are collected
// before deletion because deleting during iteration can make the kernel restart
// the walk.
func readAndResetCounts(m *ebpf.Map) (map[PathEventKey]uint32, error) {
	counts := make(map[PathEventKey]uint32)
	keys := make([]PathEventKey, 0, 16)

	var (
		key   PathEventKey
		count uint32
	)
	it := m.Iterate()
	for it.Next(&key, &count) {
		keys = append(keys, key)
		if count == 0 {
			continue
		}
		if key.PathString() == "" {
			continue
		}
		mergeCounts(counts, map[PathEventKey]uint32{key: count})
	}

	var errs []error
	if err := it.Err(); err != nil {
		errs = append(errs, err)
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return counts, errors.Join(errs...)
}

// mergeCounts folds src into dst. The addition saturates rather than wrapping,
// so a busy path can never be reported as quiet.
func mergeCounts(dst, src map[PathEventKey]uint32) {
	if dst == nil {
		return
	}
	for k, v := range src {
		cur := dst[k]
		if v > math.MaxUint32-cur {
			dst[k] = math.MaxUint32
			continue
		}
		dst[k] = cur + v
	}
}
