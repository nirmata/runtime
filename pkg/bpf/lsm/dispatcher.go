package lsm

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
	prog      *ebpf.Program
	progArray *ebpf.Map
	progCount *ebpf.Map

	// progCountKey is this hook's slot in the shared prog_count array.
	progCountKey uint32
	// progIdx maps an enforcer program fd to its prog array slot.
	progIdx map[int]uint32

	link link.Link

	dispatcherType string
}

// clear any existing pinned maps
func ClearPins() error {
	if err := os.RemoveAll(pinDir); err != nil {
		return fmt.Errorf("removing bpf pin directory: %w", err)
	}
	return nil
}

func NewDispatcherForTarget(target string) (*Dispatcher, error) {
	d := &Dispatcher{
		dispatcherType: target,
		progIdx:        make(map[int]uint32),
	}

	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating bpf pin directory: %w", err)
	}
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}

	switch target {
	case PROG_TYPE_LSM_OPEN:
		spec, err := loadLsmDispatcherFileOpen()
		if err != nil {
			return nil, err
		}
		spec.Programs["generic_lsm_handler"].AttachTo = target
		spec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac

		objs := &lsmDispatcherFileOpenObjects{}
		if err := spec.LoadAndAssign(objs, opts); err != nil {
			return nil, err
		}

		d.prog = objs.GenericLsmHandler
		d.progCount = objs.ProgCount
		d.progArray = objs.OpenProgs
		d.progCountKey = 0

	case PROG_TYPE_LSM_EXEC:
		spec, err := loadLsmDispatcherExecCheck()
		if err != nil {
			return nil, err
		}
		spec.Programs["generic_lsm_handler"].AttachTo = target
		spec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac

		objs := &lsmDispatcherExecCheckObjects{}
		if err := spec.LoadAndAssign(objs, opts); err != nil {
			return nil, err
		}

		d.prog = objs.GenericLsmHandler
		d.progCount = objs.ProgCount
		d.progArray = objs.ExecProgs
		d.progCountKey = 1

	default:
		return nil, fmt.Errorf("unknown lsm attach target %q", target)
	}

	if err := d.reset(); err != nil {
		return nil, err
	}

	return d, nil
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

func (d *Dispatcher) Attach() error {
	link, err := link.AttachLSM(link.LSMOptions{
		Program: d.prog,
	})
	if err != nil {
		return err
	}
	d.link = link

	return nil
}

// AddProgram publishes an enforcer in the prog array before bumping the count
// the kernel chain terminates on, so the chain never waits for a program that
// is not yet callable.
func (d *Dispatcher) AddProgram(progFd int) error {
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

	if err := d.bumpCount(-1); err != nil {
		return err
	}
	delete(d.progIdx, progFd)
	if err := d.progArray.Delete(&idx); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}

	return nil
}

func (d *Dispatcher) freeSlot() (uint32, error) {
	for i := uint32(0); i < d.progArray.MaxEntries(); i++ {
		var id uint32
		err := d.progArray.Lookup(&i, &id)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return i, nil
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, fmt.Errorf("the %s prog array is full", d.dispatcherType)
}

func (d *Dispatcher) bumpCount(delta int) error {
	var pc uint8
	if err := d.progCount.Lookup(&d.progCountKey, &pc); err != nil {
		return err
	}
	pc = uint8(int(pc) + delta)
	return d.progCount.Update(&d.progCountKey, &pc, ebpf.UpdateAny)
}
