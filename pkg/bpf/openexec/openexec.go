package openexec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"unsafe"

	"github.com/nirmata/runtime/pkg/compiler"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
)

const maxPathLen = 128

const (
	PROG_TYPE_LSM_OPEN   = "file_open"
	PROG_TYPE_LSM_EXEC   = "bprm_check_security"
	PROG_TYPE_TRACE_OPEN = "security_file_open"
	PROG_TYPE_TRACE_EXEC = "security_bprm_check"
)

// ProgTypes is the ordered list of lsm hooks: a hook's index here is the
// PROG_TYPE_* value the kernel programs write into lsm_ctx.prog_type and use
// as the prog_count key, so this order is the one in _cprog/maps.h and cannot
// be changed on one side alone.
var ProgTypes = map[string]int{
	PROG_TYPE_LSM_OPEN:   0,
	PROG_TYPE_TRACE_OPEN: 0,
	PROG_TYPE_LSM_EXEC:   1,
	PROG_TYPE_TRACE_EXEC: 1,
}

func progCountKey(target string) (uint32, error) {
	if key, ok := ProgTypes[target]; ok {
		return uint32(key), nil
	}

	return 0, fmt.Errorf("unknown lsm attach target %q", target)
}

//go:generate go tool bpf2go -target bpfel -cflags "-DLSM_FILE_OPEN" lsmDispatcherFileOpen ./_cprog/lsm.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel -cflags "-DLSM_EXEC_CHECK" lsmDispatcherExecCheck ./_cprog/lsm.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel -cflags "-DTRACE_FILE_OPEN" rawTpDispatcherFileOpen ./_cprog/trace.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel -cflags "-DTRACE_EXEC_CHECK" rawTpDispatcherExecCheck ./_cprog/trace.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel runtimePolicy ./_cprog/runtimepolicy.bpf.c -- -I../include -I./_cprog/include -I./_cprog

type PolicyMap struct {
	logger *logr.Logger
	closer io.Closer

	// dispatcher owns the lsm hook this enforcer is tail-called from; the
	// enforcer registers itself there on creation and leaves on Close.
	dispatcher *Dispatcher

	entries *ebpf.Map

	// observed is a map of uint64(cgid) to an event map
	observeMu sync.RWMutex
	observed  map[uint64]*ebpf.Map
}

type Prog struct {
	prog *ebpf.Program

	// openEvents is a hash-of-maps keyed by cgroup id; each value is an inner
	// path->count hash the kernel program bumps on every open/exec. innerSpec is
	// the template for those inner maps.
	eventsMap *ebpf.Map
	innerSpec *ebpf.MapSpec

	stats *ebpf.Map
	// statLast is the cumulative kernel total at the previous ReadEventsLost.
	statLast uint64

	// observed is a map of uint64(cgid) to an event map
	observeMu sync.RWMutex
	observed  map[uint64]*ebpf.Map
}

func NewPolicyMap(d *Dispatcher, logger *logr.Logger) (*PolicyMap, error) {
	// we need this function to just insert a map
	if _, err := progCountKey(d.dispatcherType); err != nil {
		return nil, err
	}

	o := &PolicyMap{logger: logger, dispatcher: d}

	spec, err := loadRuntimePolicy()
	if err != nil {
		return nil, err
	}

	var mapSpec *ebpf.MapSpec
	entriesMap, ok := spec.Maps["open_policies"]
	if !ok {
		mapSpec = &ebpf.MapSpec{
			KeySize:    uint32(unsafe.Sizeof(runtimePolicyEntry{})),
			ValueSize:  uint32(1),
			MaxEntries: 2048,
		}
	} else {
		mapSpec = entriesMap.InnerMap
	}

	m, err := ebpf.NewMap(mapSpec)
	if err != nil {
		return nil, err
	}

	if err := d.AddPolicy(m.FD()); err != nil {
		_ = m.Close()
		return nil, err
	}

	return o, nil
}

func NewProgram(d *Dispatcher) (*Prog, error) {
	p := &Prog{}

	spec, err := loadRuntimePolicy()
	if err != nil {
		return nil, err
	}

	objs := &runtimePolicyObjects{}
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, err
	}

	var zero uint32 = 0
	if err := d.progArray.Update(&zero, objs.RuntimePolicyExecutor.FD(), ebpf.UpdateAny); err != nil {
		return nil, err
	}

	innerSpec := prepareOpenEvents(spec)
	p.innerSpec = innerSpec

	p.prog = objs.RuntimePolicyExecutor
	return p, nil
}

// prepareOpenEvents returns a copy of the open_events inner-map template.
// nil means observation is unavailable for this program.
func prepareOpenEvents(spec *ebpf.CollectionSpec) *ebpf.MapSpec {
	outer := spec.Maps["open_events"]
	if outer == nil {
		return nil
	}
	inner := outer.InnerMap
	if inner == nil {
		inner = spec.Maps["inner_open_events"]
	}
	if inner == nil {
		return nil
	}
	return inner.Copy()
}

func (m *PolicyMap) Close() error {
	var retErr error
	if m.dispatcher != nil {
		if err := m.dispatcher.DeleteProgram(m.entries.FD()); err != nil {
			retErr = err
		}
	}

	if err := m.entries.Close(); err != nil {
		return err
	}

	return retErr
}

func (l *PolicyMap) AddCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		data := [128]int8{}
		binary.LittleEndian.PutUint32((*[4]byte)(unsafe.Pointer(&data))[:], uint32(cgid))
		cgidEntry := &runtimePolicyEntry{
			DataType: 2,
			Data:     data,
		}

		if err := l.entries.Put(cgidEntry, uint8(0)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (l *PolicyMap) DeleteCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		data := [128]int8{}
		binary.LittleEndian.PutUint32((*[4]byte)(unsafe.Pointer(&data))[:], uint32(cgid))
		cgidEntry := &runtimePolicyEntry{
			DataType: 2,
			Data:     data,
		}

		if err := l.entries.Delete(cgidEntry); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// AddTargets programs a policy's paths into the banned and allowed maps and
// returns every value PathKeys could not key.
func (l *PolicyMap) AddTargets(paths *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error) {
	deny, allow, rejected := parsePair(paths)

	for _, key := range deny {
		if err := l.entries.Put(&key, uint8(0)); err != nil {
			return rejected, err
		}
	}

	for _, key := range allow {
		if err := l.entries.Put(&key, uint8(0)); err != nil {
			return rejected, err
		}
	}
	return rejected, nil
}

// DeleteTargets removes what AddTargets programmed for the same pair. Both
// derive their keys from PathKeys, so a value one of them can key is a value
// the other can key too.
func (l *PolicyMap) DeleteTargets(paths *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error) {
	deny, allow, rejected := parsePair(paths)

	for _, key := range deny {
		if err := l.entries.Delete(&key); err != nil {
			l.logger.Error(err, "failed to remove path from banned map")
		}
	}

	for _, key := range allow {
		if err := l.entries.Delete(&key); err != nil {
			l.logger.Error(err, "failed to remove path from allowed map")
		}
	}
	return rejected, nil
}

func parsePair(paths *compiler.AllowDenyPair) (deny, allow []*runtimePolicyEntry, rejected []compiler.RejectedTarget) {
	if paths == nil {
		return nil, nil, nil
	}
	deny, _, denyRejected := PathKeys(paths.Deny, false)
	allow, _, allowRejected := PathKeys(paths.Allow, true)
	return deny, allow, append(denyRejected, allowRejected...)
}

func (l *PolicyMap) SetDefaultDeny(val bool) error {
	k := runtimePolicyEntry{
		DataType: 3,
		Data:     [128]int8{},
	}

	if val {
		err := l.entries.Put(&k, uint8(0))
		if err != nil {
			return err
		}
		return nil
	}

	_ = l.entries.Delete(&k)
	return nil
}
