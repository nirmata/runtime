package lsm

import (
	"fmt"
	"io"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
)

const maxPathLen = 128

const (
	PROG_TYPE_LSM_OPEN = "file_open"
	PROG_TYPE_LSM_EXEC = "bprm_check_security"
)

//go:generate go tool bpf2go -cflags "-DLSM_FILE_OPEN" lsmFileOpen ./_cprog/lsm.bpf.c -- -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -cflags "-DLSM_EXEC_CHECK" lsmExecCheck ./_cprog/lsm.bpf.c -- -I./_cprog/include -I./_cprog
type LsmEnforcer struct {
	logger *logr.Logger
	link   link.Link
	closer io.Closer

	prog        *ebpf.Program
	cgids       *ebpf.Map
	banned      *ebpf.Map
	allowed     *ebpf.Map
	defaultDeny *ebpf.Map
	openEvents  *ebpf.Map
}

func NewForAttachTarget(logger *logr.Logger, target string) (*LsmEnforcer, error) {
	switch target {
	case PROG_TYPE_LSM_OPEN:
		return newForFileOpen(logger)
	case PROG_TYPE_LSM_EXEC:
		return newForExec(logger)
	default:
		return nil, fmt.Errorf("unknown lsm attach target %q", target)
	}
}

func newForFileOpen(logger *logr.Logger) (*LsmEnforcer, error) {
	l := &LsmEnforcer{logger: logger}

	spec, err := loadLsmFileOpen()
	if err != nil {
		return nil, err
	}
	spec.Programs["generic_lsm_handler"].AttachTo = PROG_TYPE_LSM_OPEN
	spec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac
	// make the open events map contents empty for now. we will populate
	// them later when we decide learning mode should be enabled for a pod
	spec.Maps["open_events"].Contents = nil

	objs := &lsmFileOpenObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}
	// take out the relevant bpf objects from the program type specific variant
	// into generic fields and store them on the LsmEnforcer. this is to avoid
	// embedding both lsmFileOpenObjects and lsmExecCheckOptions and later in
	// the code having to check which one isn't nil
	l.closer = objs
	l.prog = objs.GenericLsmHandler
	l.cgids = objs.Cgids
	l.banned = objs.Banned
	l.allowed = objs.Allowed
	l.defaultDeny = objs.DefaultDeny
	l.openEvents = objs.OpenEvents
	return l, nil
}

func newForExec(logger *logr.Logger) (*LsmEnforcer, error) {

	l := &LsmEnforcer{logger: logger}
	spec, err := loadLsmExecCheck()
	if err != nil {
		return nil, err
	}
	spec.Programs["generic_lsm_handler"].AttachTo = PROG_TYPE_LSM_EXEC
	spec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac
	spec.Maps["open_events"].Contents = nil

	objs := &lsmExecCheckObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}
	l.closer = objs
	l.prog = objs.GenericLsmHandler
	l.cgids = objs.Cgids
	l.banned = objs.Banned
	l.allowed = objs.Allowed
	l.defaultDeny = objs.DefaultDeny
	l.openEvents = objs.OpenEvents

	return l, nil
}

func (l *LsmEnforcer) Close() error {
	if l.link != nil {
		if err := l.link.Close(); err != nil {
			return err
		}
	}
	return l.closer.Close()
}

func (l *LsmEnforcer) Attach() (link.Link, error) {
	link, err := link.AttachLSM(link.LSMOptions{
		Program: l.prog,
	})
	if err != nil {
		return nil, err
	}
	l.link = link

	return link, nil
}

func (l *LsmEnforcer) AddCgids(cgids []uint64) {
	for _, cgid := range cgids {
		// ignore the errors from adding an individual cgid
		if err := l.cgids.Put(&cgid, uint8(0)); err != nil {
			l.logger.Error(err, "failed to add cgid to target map")
		}
	}
}

func (l *LsmEnforcer) DeleteCgids(cgids []uint64) {
	for _, cgid := range cgids {
		// ignore the errors from deleting an individual cgid
		if err := l.cgids.Delete(&cgid); err != nil {
			l.logger.Error(err, "failed to remove cgid from target map")
		}
	}
}

func (l *LsmEnforcer) AddTargets(paths *compiler.AllowDenyPair) error {
	for _, p := range paths.Deny {
		if len(p) > maxPathLen {
			return fmt.Errorf("can't enforce limits on paths larger than %d", maxPathLen)
		}
		// todo: maybe we can optimize this by calling one big alloc and splitting it up ?
		key := [maxPathLen]byte{}
		copy(key[:], p)

		if err := l.banned.Put(&key, uint8(0)); err != nil {
			return err
		}
	}

	for _, p := range paths.Allow {
		if len(p) > maxPathLen {
			return fmt.Errorf("can't enforce limits on paths larger than %d", maxPathLen)
		}
		key := [maxPathLen]byte{}
		copy(key[:], p)

		if err := l.allowed.Put(&key, uint8(0)); err != nil {
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

		if err := l.banned.Delete(&key); err != nil {
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

		if err := l.allowed.Delete(&key); err != nil {
			l.logger.Error(err, "failed to remove path from allowed map")
		}
	}
	return nil
}

func (l *LsmEnforcer) SetDefaultDeny(val bool) error {
	k := uint32(0)
	if val {
		err := l.defaultDeny.Put(&k, uint8(0))
		if err != nil {
			return err
		}
		return nil
	}

	// key deletions may error if the key doesn't exist. but thats fine
	// we don't care about that
	_ = l.defaultDeny.Delete(&k)
	return nil
}

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

			if err := l.openEvents.Put(&cgid, uint32(innerMap.FD())); err != nil {
				l.logger.Error(err, "failed to enable learning mode for cgid", "cgid", cgid)
			}

			if err := innerMap.Close(); err != nil {
				l.logger.Error(err, "failed to close inner open events map", "cgid", cgid)
			}
			continue
		}
		// val was false, delete the entry
		if err := l.openEvents.Delete(&cgid); err != nil {
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
		if err := l.openEvents.Lookup(&cgid, &mapID); err != nil {
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
			// we're already returning an error from the iteration itself; a failure
			// to close here isn't worth reporting on top of that
			_ = openCountMap.Close()
			return fmt.Errorf("failed to iterate open count map for cgid %d: %w", cgid, err)
		}

		if err := openCountMap.Close(); err != nil {
			l.logger.Error(err, "failed to close open count map", "cgid", cgid)
		}
	}

	return nil
}
