package openexec

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// pinDir is the bpffs directory holding the maps shared across collections:
// the prog arrays, prog counts and chain context are pinned by name so the
// dispatchers and every enforcer loaded later resolve to the same kernel maps.
const pinDir = "/sys/fs/bpf/kyverno-runtime"

// A Dispatcher owns one lsm hook: it is the only program attached to the
// kernel, and it tail-calls every enforcer registered in its prog array.
// Enforcers come and go with policies; the dispatcher stays for the process
// lifetime. Callers serialize access (the lsm manager holds its lock across
// every AddProgram/DeleteProgram).
type Dispatcher struct {
	prog *ebpf.Program

	// progArray holds this hook's policy maps; enforcerArray holds the single
	// executor it tail-calls to walk them.
	progArray     *ebpf.Map
	enforcerArray *ebpf.Map
	progCount     *ebpf.Map

	// progCountKey is this hook's slot in the shared prog_count array.
	progCountKey uint32
	// progIdx maps an enforcer program fd to its prog array slot.
	progIdx map[int]uint32

	link link.Link

	dispatcherType string
}

// ClearPins wipes the pin directory at startup. The pinned maps outlive the
// process, so a restart would otherwise inherit prog arrays holding fds of
// programs this process never loaded and a prog_count covering them
func ClearPins() error {
	if err := os.RemoveAll(pinDir); err != nil {
		return fmt.Errorf("removing bpf pin directory: %w", err)
	}
	return nil
}

func NewDispatcherForTarget(target string) (*Dispatcher, error) {
	key, err := progCountKey(target)
	if err != nil {
		return nil, err
	}

	d := &Dispatcher{
		dispatcherType: target,
		progCountKey:   key,
		progIdx:        make(map[int]uint32),
	}

	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating bpf pin directory: %w", err)
	}

	switch target {
	case PROG_TYPE_LSM_EXEC, PROG_TYPE_LSM_OPEN:
		if err := d.initializeForLsm(target); err != nil {
			return nil, err
		}
	case PROG_TYPE_TRACE_EXEC, PROG_TYPE_TRACE_OPEN:
		if err := d.initializeForTracepoint(target); err != nil {
			return nil, err
		}
	}

	if err := d.reset(); err != nil {
		return nil, err
	}

	return d, nil
}

func (d *Dispatcher) initializeForLsm(target string) error {
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}

	switch target {
	case PROG_TYPE_LSM_OPEN:
		spec, err := loadLsmDispatcherFileOpen()
		if err != nil {
			return err
		}
		spec.Programs["generic_lsm_handler"].AttachTo = target
		spec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac

		objs := &lsmDispatcherFileOpenObjects{}
		if err := spec.LoadAndAssign(objs, opts); err != nil {
			return err
		}

		d.prog = objs.GenericLsmHandler
		d.progCount = objs.ProgCount
		d.progArray = objs.OpenPolicies
		d.enforcerArray = objs.OpenProg

	case PROG_TYPE_LSM_EXEC:
		spec, err := loadLsmDispatcherExecCheck()
		if err != nil {
			return err
		}
		spec.Programs["generic_lsm_handler"].AttachTo = target
		spec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac

		objs := &lsmDispatcherExecCheckObjects{}
		if err := spec.LoadAndAssign(objs, opts); err != nil {
			return err
		}

		d.prog = objs.GenericLsmHandler
		d.progCount = objs.ProgCount
		d.progArray = objs.ExecPolicies
		d.enforcerArray = objs.ExecProg
	}

	return nil
}

func (d *Dispatcher) initializeForTracepoint(target string) error {
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}

	switch target {
	case PROG_TYPE_TRACE_OPEN:
		spec, err := loadRawTpDispatcherFileOpen()
		if err != nil {
			return err
		}
		objs := &rawTpDispatcherFileOpenObjects{}
		if err := spec.LoadAndAssign(objs, opts); err != nil {
			return err
		}

		d.prog = objs.GenericTracepointHandler
		d.progCount = objs.ProgCount
		d.progArray = objs.OpenPolicies
		d.enforcerArray = objs.OpenProg

	case PROG_TYPE_TRACE_EXEC:
		// security_bprm_check is not in the fmod_ret d_path allowlist, so exec
		// is enforced from the file_open dispatcher, which routes an exec open
		// by its __FMODE_EXEC flag. This target owns the exec policy state that
		// dispatcher routes into and loads no program of its own.
		spec, err := loadRawTpDispatcherFileOpen()
		if err != nil {
			return err
		}

		maps := &rawTpDispatcherFileOpenMaps{}
		if err := spec.LoadAndAssign(maps, opts); err != nil {
			return err
		}

		d.progCount = maps.ProgCount
		d.progArray = maps.ExecPolicies
		d.enforcerArray = maps.ExecProg
	}

	return nil
}

// zero out the maps to prevent the dispatcher inheriting programs that previously existed
// on the system
func (d *Dispatcher) reset() error {
	zero := uint8(0)
	if err := d.progCount.Update(&d.progCountKey, &zero, ebpf.UpdateAny); err != nil {
		return err
	}
	for i := uint32(0); i < d.progArray.MaxEntries(); i++ {
		if err := d.progArray.Delete(&i); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// Attach links the dispatcher's program to its hook. The tracepoint exec
// target carries no program: the file_open dispatcher is the one attached
// there, so linking again would run the handler twice per open.
func (d *Dispatcher) Attach() error {
	if d.prog == nil {
		return nil
	}

	var (
		l   link.Link
		err error
	)

	if d.dispatcherType == PROG_TYPE_LSM_OPEN || d.dispatcherType == PROG_TYPE_LSM_EXEC {
		l, err = link.AttachLSM(link.LSMOptions{Program: d.prog})
	} else {
		l, err = link.AttachTracing(link.TracingOptions{Program: d.prog, AttachType: ebpf.AttachModifyReturn})
	}

	if err != nil {
		return err
	}

	d.link = l
	return nil
}

// AddProgram publishes an enforcer in the prog array before bumping the count
// the kernel chain terminates on, so the chain never waits for a program that
// is not yet callable.
func (d *Dispatcher) AddPolicy(progFd int) error {
	idx, err := d.freeSlot()
	if err != nil {
		return err
	}

	fd := uint32(progFd)
	if err := d.progArray.Update(&idx, &fd, ebpf.UpdateAny); err != nil {
		return err
	}
	if err := d.bumpCount(1); err != nil {
		_ = d.progArray.Delete(&idx)
		return err
	}
	d.progIdx[progFd] = idx

	return nil
}

// DeleteProgram drops the count before clearing the slot, mirroring
// AddProgram's ordering: the kernel treats a populated slot past the count as
// unreachable and a missing slot as skipped, never as a chain that hangs.
func (d *Dispatcher) DeleteProgram(progFd int) error {
	idx, ok := d.progIdx[progFd]
	if !ok {
		return fmt.Errorf("program fd %d is not in the %s prog array", progFd, d.dispatcherType)
	}

	if err := d.progArray.Delete(&idx); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}

	if err := d.bumpCount(-1); err != nil {
		return err
	}
	delete(d.progIdx, progFd)

	return nil
}

// freeSlot returns the first array index no live entry occupies. progIdx is
// keyed by fd and holds the slot as its value, so the occupied set is its
// values: probing it by index instead answers whether some fd happens to equal
// that index, which for fds starting at 3 is never true of 0.
func (d *Dispatcher) freeSlot() (uint32, error) {
	taken := make(map[uint32]struct{}, len(d.progIdx))
	for _, idx := range d.progIdx {
		taken[idx] = struct{}{}
	}

	for i := uint32(0); i < d.progArray.MaxEntries(); i++ {
		if _, ok := taken[i]; !ok {
			return i, nil
		}
	}

	return 0, fmt.Errorf("the %s prog array is full", d.dispatcherType)
}

func (d *Dispatcher) bumpCount(delta int) error {
	var pc uint8
	if err := d.progCount.Lookup(&d.progCountKey, &pc); err != nil {
		return err
	}
	next := int(pc) + delta
	if next < 0 || next > int(d.progArray.MaxEntries()) {
		return fmt.Errorf("prog_count out of range for %s: %d", d.dispatcherType, next)
	}
	pc = uint8(next)
	return d.progCount.Update(&d.progCountKey, &pc, ebpf.UpdateAny)
}
