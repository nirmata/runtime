package lsm

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
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

	objs := &lsmGenericObjects{}

	// this will load the program, but not attach it to anything
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}
	zero := uint32(0)

	switch target {
	case "file_open":
		if err := objs.lsmGenericMaps.Argtypes.Put(&zero, argTypeFileOpen); err != nil {
			return nil, err
		}
	case "bprm_check_security":
		if err := objs.lsmGenericMaps.Argtypes.Put(&zero, argTypeExecCheck); err != nil {
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

func (l *LsmEnforcer) AddTargets(paths *compiler.AllowDenyPair) error {
	for _, p := range paths.Deny {
		if len(p) > maxPathLen {
			return fmt.Errorf("can't enforce limits on paths larger than %d", maxPathLen)
		}
		// todo: maybe we can optimize this by calling one big alloc and splitting it up ?
		key := [maxPathLen]byte{}
		copy(key[:], p)

		if err := l.bpfObjs.lsmGenericMaps.Banned.Put(&key, uint8(0)); err != nil {
			return err
		}
	}

	for _, p := range paths.Allow {
		if len(p) > maxPathLen {
			return fmt.Errorf("can't enforce limits on paths larger than %d", maxPathLen)
		}
		key := [maxPathLen]byte{}
		copy(key[:], p)

		if err := l.bpfObjs.lsmGenericMaps.Allowed.Put(&key, uint8(0)); err != nil {
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

		if err := l.bpfObjs.lsmGenericMaps.Banned.Delete(&key); err != nil {
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

		if err := l.bpfObjs.lsmGenericMaps.Allowed.Delete(&key); err != nil {
			l.logger.Error(err, "failed to remove path from allowed map")
		}
	}
	return nil
}

func (l *LsmEnforcer) SetDefaultDeny(val bool) error {
	k := uint32(0)
	if val {
		err := l.bpfObjs.lsmGenericMaps.DefaultDeny.Put(&k, uint8(0))
		if err != nil {
			return err
		}
		return nil
	}

	err := l.bpfObjs.lsmGenericMaps.DefaultDeny.Delete(&k)
	if err != nil {
		return err
	}
	return nil
}

// we can skip having a value of 1 in the cgids map and indicate
// that learning mode is active by having an entry in the events map
func (l *LsmEnforcer) SetLearningModeForCgids(cgids []uint64, val bool) error {
	for _, cgid := range cgids {
		if val {
			innerSpec := &ebpf.MapSpec{
				Name:       "inner",
				KeySize:    128,
				Type:       ebpf.Hash,
				MaxEntries: 1024,
			}
			innerMap, err := ebpf.NewMap(innerSpec)
			if err != nil {
				l.logger.Error(err, "failed to create inner open events map", "cgid", cgid)
				continue
			}
			if err := l.bpfObjs.lsmGenericMaps.OpenEvents.Put(&cgid, uint32(innerMap.FD())); err != nil {
				l.logger.Error(err, "failed to enable learning mode for cgid", "cgid", cgid)
				innerMap.Close()
			}
			continue
		}
		// val was false, delete the entry
		if err := l.bpfObjs.lsmGenericMaps.OpenEvents.Delete(&cgid); err != nil {
			l.logger.Error(err, "failed to disable learning mode for cgid", "cgid", cgid)
		}
	}
	return nil
}

// pass a collector map because we will end up calling this function for many programs
// and we just wanna get the end result
func (l *LsmEnforcer) GetLearningModeForCgids(retMap map[string]uint32, cgids []uint64) error {
	for _, cgid := range cgids {
		var mapID ebpf.MapID
		if err := l.bpfObjs.lsmGenericMaps.OpenEvents.Lookup(&cgid, &mapID); err != nil {
			return fmt.Errorf("failed to lookup inner map id for cgid %d", cgid)
		}

		openCountMap, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			return err
		}

		var (
			k string
			v uint32
		)

		iter := openCountMap.Iterate()
		for iter.Next(&k, &v) {
			retMap[k] += v
		}
		if err := iter.Err(); err != nil {
			openCountMap.Close()
			return fmt.Errorf("failed to iterate open count map for cgid %d: %w", cgid, err)
		}

		if err := openCountMap.Close(); err != nil {
			l.logger.Error(err, "failed to close open count map", "cgid", cgid)
		}
	}

	return nil
}
