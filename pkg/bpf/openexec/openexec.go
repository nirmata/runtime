package openexec

import (
	"errors"
	"fmt"
	"sync"

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

// ProgTypes maps each attach target to the PROG_TYPE_* value the kernel
// programs write into policy_ctx.prog_type and use as the prog_count key, so
// these values match _cprog/maps.h and cannot be changed on one side alone.
var ProgTypes = map[string]int{
	PROG_TYPE_LSM_OPEN:   0,
	PROG_TYPE_TRACE_OPEN: 0,
	PROG_TYPE_LSM_EXEC:   1,
	PROG_TYPE_TRACE_EXEC: 1,
}

// mirrors enum data_type in _cprog/maps.h: the discriminant of every entry in
// a policy map.
const (
	dataTypeAllow uint32 = 0
	dataTypeDeny  uint32 = 1
	dataTypeCgid  uint32 = 2
	dataTypeFlags uint32 = 3
)

func progCountKey(target string) (uint32, error) {
	if key, ok := ProgTypes[target]; ok {
		return uint32(key), nil
	}

	return 0, fmt.Errorf("unknown lsm attach target %q", target)
}

// policiesMapName returns the array-of-maps in _cprog/maps.h that holds
// target's policy maps.
func policiesMapName(target string) string {
	if ProgTypes[target] == 0 {
		return "open_policies"
	}
	return "exec_policies"
}

//go:generate go tool bpf2go -target bpfel -cflags "-DLSM_FILE_OPEN" lsmDispatcherFileOpen ./_cprog/lsm.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel -cflags "-DLSM_EXEC_CHECK" lsmDispatcherExecCheck ./_cprog/lsm.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel -cflags "-DTRACE_FILE_OPEN" rawTpDispatcherFileOpen ./_cprog/trace.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel -cflags "-DTRACE_EXEC_CHECK" rawTpDispatcherExecCheck ./_cprog/trace.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel runtimePolicy ./_cprog/runtimepolicy.bpf.c -- -I../include -I./_cprog/include -I./_cprog

// A PolicyMap holds one policy's kernel-side state — allow/deny paths, cgids
// and flags, all entries of one inner map — registered in the dispatcher's
// policies array on creation.
type PolicyMap struct {
	logger *logr.Logger

	// dispatcher owns the lsm hook whose executor evaluates this map; the map
	// registers itself there on creation and leaves on Close.
	dispatcher *Dispatcher

	entries *ebpf.Map
}

// A Prog is the policy executor for one attach target: the single program the
// dispatcher tail-calls, which loops over every registered policy map, plus
// the observation maps it records into.
type Prog struct {
	prog *ebpf.Program

	// eventsMap is a hash-of-maps keyed by cgroup id; each value is an inner
	// path->count hash the kernel program bumps on every open/exec. innerSpec is
	// the template for those inner maps.
	eventsMap *ebpf.Map
	innerSpec *ebpf.MapSpec

	stats *ebpf.Map
	// statLast is the cumulative kernel total at the previous ReadEventsLost.
	statLast uint64

	// observeMu guards observed, the inner maps this program created per cgid.
	observeMu sync.RWMutex
	observed  map[uint64]*ebpf.Map
}

func NewPolicyMap(d *Dispatcher, logger *logr.Logger) (*PolicyMap, error) {
	if _, err := progCountKey(d.dispatcherType); err != nil {
		return nil, err
	}

	spec, err := loadRuntimePolicy()
	if err != nil {
		return nil, err
	}

	name := policiesMapName(d.dispatcherType)
	outer, ok := spec.Maps[name]
	if !ok || outer.InnerMap == nil {
		return nil, fmt.Errorf("embedded runtime policy spec carries no inner map spec for %s", name)
	}

	m, err := ebpf.NewMap(outer.InnerMap)
	if err != nil {
		return nil, err
	}

	if err := d.AddPolicy(m.FD()); err != nil {
		_ = m.Close()
		return nil, err
	}

	return &PolicyMap{logger: logger, dispatcher: d, entries: m}, nil
}

func NewProgram(d *Dispatcher) (*Prog, error) {
	spec, err := loadRuntimePolicy()
	if err != nil {
		return nil, err
	}

	// the program's SEC carries no attachable prefix because it is never linked
	// to a hook itself: a tail call only reaches programs of the same type as
	// the dispatcher making it, so the type has to follow the dispatcher's.
	executor := spec.Programs["runtime_policy_executor"]
	switch d.dispatcherType {
	case PROG_TYPE_LSM_OPEN, PROG_TYPE_LSM_EXEC:
		executor.Type = ebpf.LSM
		executor.AttachTo = d.dispatcherType
		executor.AttachType = ebpf.AttachLSMMac
	case PROG_TYPE_TRACE_OPEN, PROG_TYPE_TRACE_EXEC:
		executor.Type = ebpf.Tracing
		executor.AttachTo = d.dispatcherType
		executor.AttachType = ebpf.AttachModifyReturn
	default:
		return nil, fmt.Errorf("unknown lsm attach target %q", d.dispatcherType)
	}

	innerSpec := prepareOpenEvents(spec)

	objs := &runtimePolicyObjects{}
	opts := &ebpf.CollectionOptions{
		// prog_count, open_prog, exec_prog and ctx_map are pinned by name, so the
		// executor resolves to the same kernel maps the dispatchers created
		Maps: ebpf.MapOptions{PinPath: pinDir},
		// the executor has to read the same policies array AddPolicy writes to;
		// the collection's own copy would stay empty forever
		MapReplacements: map[string]*ebpf.Map{policiesMapName(d.dispatcherType): d.progArray},
	}
	if err := spec.LoadAndAssign(objs, opts); err != nil {
		return nil, err
	}

	zero := uint32(0)
	if err := d.enforcerArray.Update(&zero, objs.RuntimePolicyExecutor, ebpf.UpdateAny); err != nil {
		_ = objs.Close()
		return nil, err
	}

	return &Prog{
		prog:      objs.RuntimePolicyExecutor,
		eventsMap: objs.EventsMap,
		innerSpec: innerSpec,
		stats:     objs.Stats,
		observed:  make(map[uint64]*ebpf.Map),
	}, nil
}

// prepareOpenEvents returns a copy of the events_map inner-map template.
// nil means observation is unavailable for this program.
func prepareOpenEvents(spec *ebpf.CollectionSpec) *ebpf.MapSpec {
	outer := spec.Maps["events_map"]
	if outer == nil {
		return nil
	}
	inner := outer.InnerMap
	if inner == nil {
		inner = spec.Maps["inner_events"]
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

	if err := m.entries.Close(); err != nil && retErr == nil {
		retErr = err
	}

	return retErr
}

// cgidEntry builds the map key for one cgroup id: all eight little-endian
// bytes, matching the kernel's memcpy of the full __u64.
func cgidEntry(cgid uint64) *runtimePolicyEntry {
	e := &runtimePolicyEntry{DataType: dataTypeCgid}
	for i := range 8 {
		e.Data[i] = int8(cgid >> (8 * i))
	}
	return e
}

func (l *PolicyMap) AddCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		if err := l.entries.Put(cgidEntry(cgid), uint8(0)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (l *PolicyMap) DeleteCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		if err := l.entries.Delete(cgidEntry(cgid)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// AddTargets programs a policy's paths into its entries map and returns every
// value PathKeys could not key.
func (l *PolicyMap) AddTargets(paths *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error) {
	deny, allow, rejected := parsePair(paths)

	for _, key := range deny {
		if err := l.entries.Put(key, uint8(0)); err != nil {
			return rejected, err
		}
	}

	for _, key := range allow {
		if err := l.entries.Put(key, uint8(0)); err != nil {
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
		if err := l.entries.Delete(key); err != nil {
			l.logger.Error(err, "failed to remove deny path from the policy map")
		}
	}

	for _, key := range allow {
		if err := l.entries.Delete(key); err != nil {
			l.logger.Error(err, "failed to remove allow path from the policy map")
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
	k := runtimePolicyEntry{DataType: dataTypeFlags}

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
