package egressmgr

import (
	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/protofilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"github.com/cilium/ebpf/link"
)

// the subset of *egressfilter.EgressFilter the manager uses, so its bookkeeping
// can be exercised without loading or attaching bpf programs.
type egressFilter interface {
	AddIps(pair *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error)
	DeleteIps(pair *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error)
	SetFlagIdx(idx uint8, val bool)
	Attach(cgPath string) ([]link.Link, error)
	ReadIPEvents() (map[egressfilter.IPEventKey]uint32, error)
}

// the subset of *protofilter.ProtoFilter the manager uses.
type protoFilter interface {
	AddProtocols(pair *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error)
	DeleteProtocols(pair *compiler.AllowDenyPair) ([]compiler.RejectedTarget, error)
	SetFlagIdx(idx uint8, val bool)
	Attach(cgPath string) (link.Link, error)
	ReadProtoEvents() (map[protofilter.ProtoEventKey]uint32, error)
}
