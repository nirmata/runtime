package openexec

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/nirmata/runtime/pkg/compiler"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
)

const maxPathLen = 128

const (
	PROG_TYPE_LSM_OPEN   = "file_open"
	PROG_TYPE_LSM_EXEC   = "bprm_check_security"
	PROG_TYPE_TRACE_OPEN = "sys_enter_openat"
	PROG_TYPE_TRACE_EXEC = "sys_enter_execve"
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

//go:generate go tool bpf2go -cflags "-DLSM_FILE_OPEN" lsmDispatcherFileOpen ./_cprog/lsm.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -cflags "-DLSM_EXEC_CHECK" lsmDispatcherExecCheck ./_cprog/lsm.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -cflags "-DTRACE_FILE_OPEN" rawTpDispatcherFileOpen ./_cprog/trace.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -cflags "-DTRACE_EXEC_CHECK" rawTpDispatcherExecCheck ./_cprog/trace.dispatcher.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go runtimePolicy ./_cprog/runtimepolicy.bpf.c -- -I../include -I./_cprog/include -I./_cprog

type OpenExecEnforcer struct {
	logger *logr.Logger
	closer io.Closer

	// dispatcher owns the lsm hook this enforcer is tail-called from; the
	// enforcer registers itself there on creation and leaves on Close.
	dispatcher *Dispatcher

	prog        *ebpf.Program
	cgids       *ebpf.Map
	banned      *ebpf.Map
	allowed     *ebpf.Map
	defaultDeny *ebpf.Map

	// openEvents is a hash-of-maps keyed by cgroup id; each value is an inner
	// path->count hash the kernel program bumps on every open/exec. innerSpec is
	// the template for those inner maps.
	openEvents *ebpf.Map
	innerSpec  *ebpf.MapSpec

	stats *ebpf.Map
	// statLast is the cumulative kernel total at the previous ReadEventsLost.
	statLast uint64

	// observeMu guards observed, the inner maps this enforcer created.
	observeMu sync.RWMutex
	observed  map[uint64]*ebpf.Map
}

func NewForAttachTarget(d *Dispatcher, logger *logr.Logger) (*OpenExecEnforcer, error) {
	if _, err := progCountKey(d.dispatcherType); err != nil {
		return nil, err
	}

	l := &OpenExecEnforcer{logger: logger, dispatcher: d}

	spec, err := loadLsmRuntimePolicy()
	if err != nil {
		return nil, err
	}
	// the program is never linked to the hook itself, but loading an lsm
	// program still requires the BTF id of a real hook, and tail calls only
	// reach programs loaded for the same hook as the dispatcher
	spec.Programs["runtime_policy_executor"].AttachTo = d.dispatcherType
	spec.Programs["runtime_policy_executor"].AttachType = ebpf.AttachLSMMac

	innerSpec := prepareOpenEvents(spec)

	objs := &lsmRuntimePolicyObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
		// bind the placeholder chain_progs to this dispatcher's prog array; the
		// program can then only reference one array, whose owner hook matches
		// its own AttachTo, which is what the kernel's tail-call ownership
		// check demands
		MapReplacements: map[string]*ebpf.Map{"chain_progs": d.progArray},
	}
	if err := spec.LoadAndAssign(objs, opts); err != nil {
		return nil, err
	}
	l.innerSpec = innerSpec
	// hoist the collection's objects into generic fields so the rest of the
	// code never has to ask which variant is loaded
	l.closer = objs
	l.prog = objs.RuntimePolicyExecutor
	l.cgids = objs.Cgids
	l.banned = objs.Banned
	l.allowed = objs.Allowed
	l.defaultDeny = objs.DefaultDeny
	l.openEvents = objs.OpenEvents
	l.stats = objs.Stats

	if err := d.AddProgram(l.prog.FD()); err != nil {
		_ = objs.Close()
		return nil, err
	}

	return l, nil
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

func (l *OpenExecEnforcer) Close() error {
	var retErr error
	// leave the tail-call chain before anything is released: the prog array
	// holds its own reference, so a closed-but-still-registered program would
	// keep running with its policy maps gone from userspace.
	if l.dispatcher != nil {
		if err := l.dispatcher.DeleteProgram(l.prog.FD()); err != nil {
			retErr = err
		}
	}
	// release the observation inner maps next; the kernel keeps its own
	// reference through open_events until the outer map goes away.
	l.observeMu.Lock()
	for cgid, inner := range l.observed {
		if err := inner.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("closing observation map for cgid %d: %w", cgid, err)
		}
		delete(l.observed, cgid)
	}
	l.observeMu.Unlock()

	if l.closer != nil {
		if err := l.closer.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}

	return retErr
}

func (l *OpenExecEnforcer) AddCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		if err := l.cgids.Put(&cgid, uint8(0)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (l *OpenExecEnforcer) DeleteCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		if err := l.cgids.Delete(&cgid); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// AddTargets programs a policy's paths into the banned and allowed maps and
// returns every value PathKeys could not key.
func (l *OpenExecEnforcer) AddTargets(paths *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error) {
	deny, allow, rejected := parsePair(paths)

	for _, key := range deny {
		if err := l.banned.Put(&key, uint8(0)); err != nil {
			return rejected, err
		}
	}

	for _, key := range allow {
		if err := l.allowed.Put(&key, uint8(0)); err != nil {
			return rejected, err
		}
	}
	return rejected, nil
}

// DeleteTargets removes what AddTargets programmed for the same pair. Both
// derive their keys from PathKeys, so a value one of them can key is a value
// the other can key too.
func (l *OpenExecEnforcer) DeleteTargets(paths *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error) {
	deny, allow, rejected := parsePair(paths)

	for _, key := range deny {
		if err := l.banned.Delete(&key); err != nil {
			l.logger.Error(err, "failed to remove path from banned map")
		}
	}

	for _, key := range allow {
		if err := l.allowed.Delete(&key); err != nil {
			l.logger.Error(err, "failed to remove path from allowed map")
		}
	}
	return rejected, nil
}

func parsePair(paths *compiler.AllowDenyPair) (deny, allow [][maxPathLen]byte, rejected []compiler.RejectedTarget) {
	if paths == nil {
		return nil, nil, nil
	}
	deny, _, denyRejected := PathKeys(paths.Deny)
	allow, _, allowRejected := PathKeys(paths.Allow)
	return deny, allow, append(denyRejected, allowRejected...)
}

func (l *OpenExecEnforcer) SetDefaultDeny(val bool) error {
	k := uint32(0)
	if val {
		err := l.defaultDeny.Put(&k, uint8(0))
		if err != nil {
			return err
		}
		return nil
	}

	_ = l.defaultDeny.Delete(&k)
	return nil
}
