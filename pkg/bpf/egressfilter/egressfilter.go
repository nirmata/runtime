package egressfilter

import (
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
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

func (p *EgressFilter) DeleteIps(ips []string) {
	for _, ip := range ips {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			p.logger.Info("failed to parse ip as an ipv4", ip)
			continue
		}
		ipBytes := binary.LittleEndian.Uint32(ip4)
		p.bpfObjs.BannedIps.Delete(&ipBytes)
	}
}

func (p *EgressFilter) AddIps(ips []string) {
	for _, ip := range ips {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			continue
		}
		ipBytes := binary.LittleEndian.Uint32(ip4)

		err := p.bpfObjs.BannedIps.Put(&ipBytes, uint8(0))
		if err != nil {
			p.logger.Error(err, "failed to add ip to bpf map", ip)
		}
	}
}

func (p *EgressFilter) Attach(cgPath string) (link.Link, error) {
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: p.bpfObjs.egressBlockPrograms.CgroupEgress,
	})
	if err != nil {
		return nil, err
	}
	return link, nil
}
