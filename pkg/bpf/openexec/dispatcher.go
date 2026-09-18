package openexec

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// pinDir is the bpffs directory holding the maps shared across collections:
// the prog arrays and chain context are pinned by name so the dispatchers and
// the executor loaded later resolve to the same kernel maps.
const pinDir = "/sys/fs/bpf/kyverno-runtime"

// A Dispatcher owns one hook: it is the only program attached to the kernel,
// and it tail-calls the executor that evaluates its entries map. Every policy
// of the hook writes into that one map under its own slot bit; the dispatcher
// hands out the slots and stays for the process lifetime. Callers serialize
// access (OpenExecManager holds its lock across every PolicyMap call), which
// is what makes the read-modify-write of a shared entry safe.
type Dispatcher struct {
	prog *ebpf.Program

	// entries is this hook's policy keyspace; enforcerArray holds the single
	// executor it tail-calls to evaluate it.
	entries       *ebpf.Map
	enforcerArray *ebpf.Map

	// slots has bit i set while policy slot i is in use.
	slots uint64

	link link.Link

	dispatcherType string
}

// ClearPins wipes the pin directory at startup. The pinned maps outlive the
// process, so a restart would otherwise inherit prog arrays holding fds of
// programs this process never loaded.
func ClearPins() error {
	if err := os.RemoveAll(pinDir); err != nil {
		return fmt.Errorf("removing bpf pin directory: %w", err)
	}
	return nil
}

func NewDispatcherForTarget(target string) (*Dispatcher, error) {
	if err := checkTarget(target); err != nil {
		return nil, err
	}

	d := &Dispatcher{dispatcherType: target}

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
		d.entries = objs.OpenEntries
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
		d.entries = objs.ExecEntries
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
		d.entries = objs.OpenEntries
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

		d.entries = maps.ExecEntries
		d.enforcerArray = maps.ExecProg
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

// AddPolicy reserves the lowest free policy slot of this hook and returns it.
func (d *Dispatcher) AddPolicy() (uint32, error) {
	for slot := uint32(0); slot < maxPolicies; slot++ {
		// as soon as you find a clear bit in d.slots. indicated by ANDing with 1<<slot
		if d.slots&(1<<slot) == 0 {
			// set that slot to 1 (booked) and return it
			d.slots |= 1 << slot
			return slot, nil
		}
	}
	return 0, fmt.Errorf("all %d %s policy slots are in use", maxPolicies, d.dispatcherType)
}

func (d *Dispatcher) RemovePolicy(slot uint32) error {
	if slot >= maxPolicies || d.slots&(1<<slot) == 0 {
		return fmt.Errorf("policy slot %d is not in use for %s", slot, d.dispatcherType)
	}
	d.slots &^= 1 << slot
	return nil
}
