package lsm

import (
	"errors"
	"fmt"
	"io"
	"sync"

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

//go:generate go tool bpf2go -cflags "-DLSM_FILE_OPEN" lsmFileOpen ./_cprog/lsm.bpf.c -- -I../include -I./_cprog/include -I./_cprog
//go:generate go tool bpf2go -cflags "-DLSM_EXEC_CHECK" lsmExecCheck ./_cprog/lsm.bpf.c -- -I../include -I./_cprog/include -I./_cprog
type LsmEnforcer struct {
	logger *logr.Logger
	link   link.Link
	closer io.Closer

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

	// observeMu guards observed, the inner maps this enforcer created.
	observeMu sync.RWMutex
	observed  map[uint64]*ebpf.Map
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

// prepareOpenEvents clears the ELF-provided contents of the open_events
// hash-of-maps, whose single entry is the template inner map at key 0 rather
// than a real cgroup id, and returns a copy of that template. nil means
// observation is unavailable for this program.
func prepareOpenEvents(spec *ebpf.CollectionSpec) *ebpf.MapSpec {
	outer := spec.Maps["open_events"]
	if outer == nil {
		return nil
	}
	outer.Contents = nil

	inner := outer.InnerMap
	if inner == nil {
		inner = spec.Maps["inner_open_events"]
	}
	if inner == nil {
		return nil
	}
	return inner.Copy()
}

func newForFileOpen(logger *logr.Logger) (*LsmEnforcer, error) {
	l := &LsmEnforcer{logger: logger}

	spec, err := loadLsmFileOpen()
	if err != nil {
		return nil, err
	}
	spec.Programs["generic_lsm_handler"].AttachTo = PROG_TYPE_LSM_OPEN
	spec.Programs["generic_lsm_handler"].AttachType = ebpf.AttachLSMMac

	innerSpec := prepareOpenEvents(spec)

	objs := &lsmFileOpenObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}
	l.innerSpec = innerSpec
	// hoist the program-specific objects into generic fields so the rest of the
	// code never has to ask which variant is loaded
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
	innerSpec := prepareOpenEvents(spec)

	objs := &lsmExecCheckObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}
	l.innerSpec = innerSpec
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
	var retErr error
	// release the observation inner maps first; the kernel keeps its own
	// reference through open_events until the outer map goes away.
	l.observeMu.Lock()
	for cgid, inner := range l.observed {
		if err := inner.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("closing observation map for cgid %d: %w", cgid, err)
		}
		delete(l.observed, cgid)
	}
	l.observeMu.Unlock()

	if l.link != nil {
		if err := l.link.Close(); err != nil {
			retErr = err
		}
	}
	if l.closer != nil {
		if err := l.closer.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}
	return retErr
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

func (l *LsmEnforcer) AddCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		if err := l.cgids.Put(&cgid, uint8(0)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (l *LsmEnforcer) DeleteCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		if err := l.cgids.Delete(&cgid); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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

	_ = l.defaultDeny.Delete(&k)
	return nil
}
