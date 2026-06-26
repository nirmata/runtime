package egressfilter

import (
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

//go:generate go tool bpf2go egressBlock ./_cprog/probe.c

type EgressFilter struct {
	logger  *logr.Logger
	bpfObjs *egressBlockObjects
}

func New(l *logr.Logger) (*EgressFilter, error) {
	spec, err := loadEgressBlock()
	if err != nil {
		return nil, err
	}

	objs := &egressBlockObjects{} //nolint:typecheck

	// for the generic maps, we will load and assign to some object that will get generated
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}

	p := &EgressFilter{
		logger:  l,
		bpfObjs: objs,
	}

	return p, nil
}

func (e *EgressFilter) AddIps(pair *compiler.AllowDenyPair) {
	for _, ip := range pair.Allow {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			continue
		}
		ipBytes := binary.LittleEndian.Uint32(ip4)

		err := e.bpfObjs.AllowedIps.Put(&ipBytes, uint8(0))
		if err != nil {
			e.logger.Error(err, "failed to add ip to bpf map", ip)
		}
	}

	for _, ip := range pair.Deny {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			continue
		}
		ipBytes := binary.LittleEndian.Uint32(ip4)

		err := e.bpfObjs.BannedIps.Put(&ipBytes, uint8(0))
		if err != nil {
			e.logger.Error(err, "failed to add ip to bpf map", ip)
		}
	}
}

func (e *EgressFilter) DeleteIps(pair *compiler.AllowDenyPair) {
	for _, ip := range pair.Allow {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			continue
		}
		ipBytes := binary.LittleEndian.Uint32(ip4)

		err := e.bpfObjs.AllowedIps.Delete(&ipBytes)
		if err != nil {
			e.logger.Error(err, "failed to remove ip from bpf map", ip)
		}
	}

	for _, ip := range pair.Deny {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			continue
		}
		ipBytes := binary.LittleEndian.Uint32(ip4)

		err := e.bpfObjs.BannedIps.Delete(&ipBytes)
		if err != nil {
			e.logger.Error(err, "failed to remove ip from bpf map", ip)
		}
	}
}

func (e *EgressFilter) SetDefaultDeny(val bool) {
	key := 0
	if val {
		e.bpfObjs.egressBlockMaps.DefaultDeny.Put(&key, uint8(0))
	} else {
		e.bpfObjs.egressBlockMaps.DefaultDeny.Delete(&key)
	}
}

func (e *EgressFilter) Attach(cgPath string) (link.Link, error) {
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: e.bpfObjs.egressBlockPrograms.CgroupEgress,
	})
	if err != nil {
		return nil, err
	}
	return link, nil
}
