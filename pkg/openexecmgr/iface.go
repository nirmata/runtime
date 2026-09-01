package openexecmgr

import (
	"github.com/nirmata/runtime/pkg/bpf/openexec"
	"github.com/nirmata/runtime/pkg/compiler"
)

// CgroupSink is an observation-only kernel source that must see events from
// the same pods the exec policies select, and from no others.
type CgroupSink interface {
	AddCgids(cgids []uint64) error
	DeleteCgids(cgids []uint64) error
}

// the subset of *openexec.PolicyMap the manager uses, so its state machine can
// be exercised without loading bpf programs.
type openExecMap interface {
	Close() error
	AddCgids(cgids []uint64) error
	DeleteCgids(cgids []uint64) error
	AddTargets(paths *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error)
	DeleteTargets(paths *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error)
	SetDefaultDeny(val bool) error
}

// the subset of *openexec.Prog the manager uses for observation, for the same
// reason.
type monitoringIface interface {
	EnableObservation(cgids []uint64) error
	DisableObservation(cgids []uint64) error
	ReadEvents() (map[uint64]map[openexec.PathEventKey]uint32, error)
	ReadEventsLost() (uint64, error)
}
