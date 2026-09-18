package openexec

import (
	"errors"
	"fmt"
	"sync"

	"github.com/nirmata/runtime/pkg/compiler"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
)

const (
	maxPathLen = 128
	// maxPolicies is the width of the slot mask an entry carries, MAX_POLICIES
	// in _cprog/maps.h.
	maxPolicies = 64
)

const (
	PROG_TYPE_LSM_OPEN   = "file_open"
	PROG_TYPE_LSM_EXEC   = "bprm_check_security"
	PROG_TYPE_TRACE_OPEN = "security_file_open"
	PROG_TYPE_TRACE_EXEC = "security_bprm_check"
)

// ProgTypes maps each attach target to the PROG_TYPE_* value the kernel
// programs write into policy_ctx.prog_type to pick the entries map, so these
// values match _cprog/maps.h and cannot be changed on one side alone.
var ProgTypes = map[string]int{
	PROG_TYPE_LSM_OPEN:   0,
	PROG_TYPE_TRACE_OPEN: 0,
	PROG_TYPE_LSM_EXEC:   1,
	PROG_TYPE_TRACE_EXEC: 1,
}

// mirrors enum data_type in _cprog/maps.h: the discriminant of every entry in
// a policy map.
const (
	dataTypeAllow       uint32 = 0
	dataTypeDeny        uint32 = 1
	dataTypeCgid        uint32 = 2
	dataTypeFlags       uint32 = 3
	dataTypeAllowPrefix uint32 = 4
	dataTypeDenyPrefix  uint32 = 5
)

func checkTarget(target string) error {
	if _, ok := ProgTypes[target]; !ok {
		return fmt.Errorf("unknown lsm attach target %q", target)
	}
	return nil
}

// entriesMapName returns the map in _cprog/maps.h that holds target's policy
// entries.
func entriesMapName(target string) string {
	if ProgTypes[target] == 0 {
		return "open_entries"
	}
	return "exec_entries"
}

//go:generate go tool bpf2go -target bpfel -cflags "-DLSM_FILE_OPEN" lsmDispatcherFileOpen ./_cprog/lsm.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel -cflags "-DLSM_EXEC_CHECK" lsmDispatcherExecCheck ./_cprog/lsm.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel rawTpDispatcherFileOpen ./_cprog/trace.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -target bpfel runtimePolicy ./_cprog/runtimepolicy.bpf.c -- -I../include -I./_cprog/include -I./_cprog

// A PolicyMap is one policy's view of its hook's shared entries map: every
// key it programs (allow/deny paths, cgids, flags) carries this policy's slot
// bit in the entry's value, alongside the bits of any other policy holding the
// same key.
type PolicyMap struct {
	logger *logr.Logger

	// dispatcher owns the hook whose executor evaluates entries; the policy
	// takes a slot from it on creation and returns the slot on Close.
	dispatcher *Dispatcher
	entries    *ebpf.Map

	slot uint32
	bit  uint64
	// keys is every entry this policy has set its bit on, so Close can clear
	// exactly those.
	keys map[runtimePolicyEntry]struct{}
}

// A Prog is the policy executor for one attach target: the single program the
// dispatcher tail-calls, which evaluates the hook's entries map, plus the
// observation maps it records into.
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
	if err := checkTarget(d.dispatcherType); err != nil {
		return nil, err
	}

	slot, err := d.AddPolicy()
	if err != nil {
		return nil, err
	}

	return &PolicyMap{
		logger:     logger,
		dispatcher: d,
		entries:    d.entries,
		slot:       slot,
		bit:        1 << slot,
		keys:       make(map[runtimePolicyEntry]struct{}),
	}, nil
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
		// exec is detected by checking the __FMODE_EXEC flag presence
		executor.AttachTo = PROG_TYPE_TRACE_OPEN
		executor.AttachType = ebpf.AttachModifyReturn
	default:
		return nil, fmt.Errorf("unknown lsm attach target %q", d.dispatcherType)
	}

	innerSpec := prepareOpenEvents(spec)

	objs := &runtimePolicyObjects{}
	opts := &ebpf.CollectionOptions{
		// open_prog, exec_prog and ctx_map are pinned by name, so the executor
		// resolves to the same kernel maps the dispatchers created
		Maps: ebpf.MapOptions{PinPath: pinDir},
		// the executor has to read the same entries map the policies write to;
		// the collection's own copy would stay empty forever
		MapReplacements: map[string]*ebpf.Map{entriesMapName(d.dispatcherType): d.entries},
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

// Close releases the executor and its maps. The dispatcher's prog array still
// holds the executor until the dispatcher itself is closed and the pins are
// cleared, so callers close the dispatcher afterwards.
func (p *Prog) Close() error {
	p.observeMu.Lock()
	defer p.observeMu.Unlock()
	var errs []error
	for cgid, m := range p.observed {
		errs = append(errs, m.Close())
		delete(p.observed, cgid)
	}
	if p.prog != nil {
		errs = append(errs, p.prog.Close())
	}
	if p.eventsMap != nil {
		errs = append(errs, p.eventsMap.Close())
	}
	if p.stats != nil {
		errs = append(errs, p.stats.Close())
	}
	p.prog, p.eventsMap, p.stats = nil, nil, nil
	return errors.Join(errs...)
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

// Close withdraws the policy from the kernel: cgids first, so the policy stops
// selecting anything before its rules go, then every other key it set.
func (m *PolicyMap) Close() error {
	var errs []error
	for _, pass := range []bool{true, false} {
		for key := range m.keys {
			if (key.DataType == dataTypeCgid) != pass {
				continue
			}
			if err := m.clear(&key); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if m.dispatcher != nil {
		if err := m.dispatcher.RemovePolicy(m.slot); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// store that policy's bit in the value corresonding to `key`
func (m *PolicyMap) set(key *runtimePolicyEntry) error {
	var v uint64
	if err := m.entries.Lookup(key, &v); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	if err := m.entries.Put(key, v|m.bit); err != nil {
		return err
	}
	m.keys[*key] = struct{}{}
	return nil
}

// clear removes this policy's bit from key's value and drops the entry once no
// policy holds it. A key this policy never set is left alone.
func (m *PolicyMap) clear(key *runtimePolicyEntry) error {
	var v uint64
	if err := m.entries.Lookup(key, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			delete(m.keys, *key)
			return nil
		}
		return err
	}

	// clear the bit at position m.bit in v
	v &^= m.bit
	var err error
	// no policies specify that key anymore (all bits are zero), delete it
	if v == 0 {
		err = m.entries.Delete(key)
	} else {
		err = m.entries.Put(key, v)
	}
	if err != nil {
		return err
	}
	delete(m.keys, *key)
	return nil
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
		if err := l.set(cgidEntry(cgid)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (l *PolicyMap) DeleteCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		if err := l.clear(cgidEntry(cgid)); err != nil {
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
		if err := l.set(key); err != nil {
			return rejected, err
		}
	}

	for _, key := range allow {
		if err := l.set(key); err != nil {
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
		if err := l.clear(key); err != nil {
			l.logger.Error(err, "failed to remove deny path from the policy map")
		}
	}

	for _, key := range allow {
		if err := l.clear(key); err != nil {
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
		return l.set(&k)
	}
	return l.clear(&k)
}
