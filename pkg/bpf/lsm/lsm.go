package lsm

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
)

const maxPathLen = 128

//go:generate go tool bpf2go lsmGeneric ./_cprog/lsm.bpf.c -I./_cprog/include

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

	objs := &lsmGenericObjects{}

	// this will load the program, but not attach it to anything
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}
	zero := 0

	switch target {
	// todo: maintain a contract with kernel space for these things
	case "file_open":
		objs.lsmGenericMaps.Argtypes.Put(&zero, uint8(1))
	case "bprm_check_security":
		objs.lsmGenericMaps.Argtypes.Put(&zero, uint8(2))
	}

	spec.Programs["generic_lsm_handler"].AttachTo = target
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
		if err := l.bpfObjs.lsmGenericMaps.Cgids.Put(&cgid, uint8(0)); err != nil {
			l.logger.Error(err, "failed to add cgid to target map")
		}
	}

	return nil
}

func (l *LsmEnforcer) DeleteCgids(cgids []uint64) error {
	for _, cgid := range cgids {
		if err := l.bpfObjs.lsmGenericMaps.Cgids.Delete(&cgid); err != nil {
			l.logger.Error(err, "failed to remove cgid from target map")
		}
	}
	return nil
}

func (l *LsmEnforcer) AddTargets(paths []string) error {
	for _, p := range paths {
		if len(p) > maxPathLen {
			return fmt.Errorf("can't enforce limits on paths larger than %d", maxPathLen)
		}
		// todo: maybe we can optimize this by calling one big alloc and splitting it up ?
		key := [maxPathLen]byte{}
		copy(key[:], p)

		l.bpfObjs.lsmGenericMaps.Banned.Put(&key, uint8(0))
	}
	return nil
}

func (l *LsmEnforcer) DeleteTargets(paths []string) error {
	for _, p := range paths {
		if len(p) > maxPathLen {
			// don't even bother
			continue
		}
		// allocate an array of byte
		key := [maxPathLen]byte{}
		copy(key[:], p)

		l.bpfObjs.lsmGenericMaps.Banned.Delete(&key)
	}
	return nil
}
