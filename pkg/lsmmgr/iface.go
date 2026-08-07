package lsmmgr

import (
	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"github.com/cilium/ebpf/link"
)

// CgroupSink is an observation-only kernel source that must see events from
// the same pods the exec policies select, and from no others.
type CgroupSink interface {
	AddCgids(cgids []uint64) error
	DeleteCgids(cgids []uint64) error
}

// the subset of *lsm.LsmEnforcer the manager uses, so its state machine can be
// exercised without loading bpf programs.
type lsmEnforcer interface {
	Attach() (link.Link, error)
	Close() error
	AddCgids(cgids []uint64) error
	DeleteCgids(cgids []uint64) error
	AddTargets(paths *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error)
	DeleteTargets(paths *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error)
	SetDefaultDeny(val bool) error
	EnableObservation(cgids []uint64) error
	DisableObservation(cgids []uint64) error
	ReadEvents(cgids []uint64) (map[uint64]map[lsm.PathEventKey]uint32, error)
}

var _ lsmEnforcer = (*lsm.LsmEnforcer)(nil)
