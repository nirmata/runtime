package lsm

import (
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
)

const maxPathLen = 128

// argtype values written into the `argtypes` map, read back out by the BPF program
// in lsm.bpf.c (ARGTYPE_FILE_OPEN / ARGTYPE_EXEC_CHECK). must stay in sync with those.
const (
	argTypeFileOpen  = uint8(1)
	argTypeExecCheck = uint8(2)
)

//go:generate go tool bpf2go lsmGeneric ./_cprog/lsm.bpf.c -- -I./_cprog/include -I./_cprog
type LsmEnforcer struct {
	logger  *logr.Logger
	bpfObjs *lsmGenericObjects
	link    link.Link
}

func NewForAttachTarget(logger *logr.Logger, target string) (*LsmEnforcer, error) {
	spec, err := loadLsmGeneric()
	if err != nil {
		return nil, err
	}
	spec.Programs["generic_lsm_handler"].AttachTo = target
	spec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac

	// the open_events map is defined in the bpf program but is currently unused
	// at the Go layer (it previously backed workload-profile learning mode).
	// keep its contents empty so it stays inert.
	spec.Maps["open_events"].Contents = nil

	objs := &lsmGenericObjects{}

	// this will load the program, but not attach it to anything
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}
	zero := uint32(0)

	switch target {
	case "file_open":
		if err := objs.Argtypes.Put(&zero, argTypeFileOpen); err != nil {
			return nil, err
		}
	case "bprm_check_security":
		if err := objs.Argtypes.Put(&zero, argTypeExecCheck); err != nil {
			return nil, err
		}
	}

	l := &LsmEnforcer{
		logger:  logger,
		bpfObjs: objs,
	}

	return l, nil
}

func (l *LsmEnforcer) Attach() (link.Link, error) {
	link, err := link.AttachLSM(link.LSMOptions{
		Program: l.bpfObjs.GenericLsmHandler,
	})
	if err != nil {
		return nil, err
	}
	l.link = link

	return link, nil
}

func (l *LsmEnforcer) AddCgids(cgids []uint64) error {
	for _, cgid := range cgids {
		if err := l.bpfObjs.Cgids.Put(&cgid, uint8(0)); err != nil {
			l.logger.Error(err, "failed to add cgid to target map")
		}
	}

	return nil
}

func (l *LsmEnforcer) DeleteCgids(cgids []uint64) error {
	for _, cgid := range cgids {
		if err := l.bpfObjs.Cgids.Delete(&cgid); err != nil {
			l.logger.Error(err, "failed to remove cgid from target map")
		}
	}
	return nil
}

func (l *LsmEnforcer) AddTargets(paths *compiler.AllowDenyPair) error {
	for _, p := range paths.Deny {
		if len(p) > maxPathLen {
			return fmt.Errorf("can't enforce limits on paths larger than %d", maxPathLen)
		}
		// todo: maybe we can optimize this by calling one big alloc and splitting it up ?
		key := [maxPathLen]byte{}
		copy(key[:], p)

		if err := l.bpfObjs.Banned.Put(&key, uint8(0)); err != nil {
			return err
		}
	}

	for _, p := range paths.Allow {
		if len(p) > maxPathLen {
			return fmt.Errorf("can't enforce limits on paths larger than %d", maxPathLen)
		}
		key := [maxPathLen]byte{}
		copy(key[:], p)

		if err := l.bpfObjs.Allowed.Put(&key, uint8(0)); err != nil {
			return err
		}
	}
	return nil
}

func (l *LsmEnforcer) DeleteTargets(paths *compiler.AllowDenyPair) error {
	for _, p := range paths.Deny {
		if len(p) > maxPathLen {
			continue
		}
		// allocate an array of byte
		key := [maxPathLen]byte{}
		copy(key[:], p)

		if err := l.bpfObjs.Banned.Delete(&key); err != nil {
			l.logger.Error(err, "failed to remove path from banned map")
		}
	}

	for _, p := range paths.Allow {
		if len(p) > maxPathLen {
			continue
		}
		// allocate an array of byte
		key := [maxPathLen]byte{}
		copy(key[:], p)

		if err := l.bpfObjs.Allowed.Delete(&key); err != nil {
			l.logger.Error(err, "failed to remove path from allowed map")
		}
	}
	return nil
}

func (l *LsmEnforcer) SetDefaultDeny(val bool) error {
	k := uint32(0)
	if val {
		err := l.bpfObjs.DefaultDeny.Put(&k, uint8(0))
		if err != nil {
			return err
		}
		return nil
	}

	// key deletions may error if the key doesn't exist. but thats fine
	// we don't care about that
	_ = l.bpfObjs.DefaultDeny.Delete(&k)
	return nil
}
