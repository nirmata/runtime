package lsm

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

const maxPathLen = 128

//go:generate go tool bpf2go lsmGeneric ./_cprog/lsm.bpf.c -I./_cprog/include -I./_cprog/maps.c
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
	// todo: maintain a contract with kernel space for these things
	case "file_open":
		objs.lsmGenericMaps.Argtypes.Put(&zero, uint64(1))
	case "bprm_check_security":
		objs.lsmGenericMaps.Argtypes.Put(&zero, uint64(2))
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

		l.bpfObjs.lsmGenericMaps.Banned.Put(&key, uint8(0))
	}

	for _, p := range paths.Allow {
		if len(p) > maxPathLen {
			return fmt.Errorf("can't enforce limits on paths larger than %d", maxPathLen)
		}
		// todo: maybe we can optimize this by calling one big alloc and splitting it up ?
		key := [maxPathLen]byte{}
		copy(key[:], p)

		l.bpfObjs.lsmGenericMaps.Allowed.Put(&key, uint8(0))
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

		l.bpfObjs.lsmGenericMaps.Banned.Delete(&key)
	}

	for _, p := range paths.Allow {
		if len(p) > maxPathLen {
			continue
		}
		// allocate an array of byte
		key := [maxPathLen]byte{}
		copy(key[:], p)

		l.bpfObjs.lsmGenericMaps.Banned.Delete(&key)
	}
	return nil
}

func (l *LsmEnforcer) SetDefaultDeny(val bool) error {
	k := 0
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
				return err
			}
			if err := l.bpfObjs.lsmGenericMaps.OpenEvents.Put(&cgid, uint32(innerMap.FD())); err != nil {
				return err
			}
			continue
		}
		// val was false, delete the entry
		if err := l.bpfObjs.lsmGenericMaps.OpenEvents.Delete(&cgid); err != nil {
			return err
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
		defer openCountMap.Close()

		var (
			k string
			v uint32
		)

		iter := openCountMap.Iterate()
		for iter.Next(&k, &v) {
			retMap[k] += v
		}
	}

	return nil
}
