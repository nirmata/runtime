package egressfilter

import (
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

//go:generate go tool bpf2go egressBlock ./_cprog/probe.c -I ./_cprog/maps.c

const (
	DEFAULT_DENY  = 1
	LEARNING_MODE = 2
)

type EgressFilter struct {
	logger              *logr.Logger
	bpfObjs             *egressBlockObjects
	learningModeEnabled bool
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

	// initialize flag values with zeros
	zeroFlags := 0
	objs.egressBlockMaps.Flags.Put(&zeroFlags, &zeroFlags)

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

func (e *EgressFilter) SetFlagIdx(idx uint8, val bool) {
	key := 0
	var currentval uint8

	err := e.bpfObjs.egressBlockMaps.Flags.Lookup(&key, &currentval)
	if err != nil {
		panic("failed to read the flags map. corrupt state")
	}

	if val {
		currentval |= idx
		e.bpfObjs.egressBlockMaps.Flags.Put(&key, &currentval)
	} else {
		currentval &^= 1 << idx
		e.bpfObjs.egressBlockMaps.Flags.Put(&key, &currentval)
	}
}

func (e *EgressFilter) ReadLearned() (map[uint32]uint32, error) {
	ret := make(map[uint32]uint32)
	iter := e.bpfObjs.IpEvents.Iterate()

	var (
		key   uint32
		value uint32
	)

	for iter.Next(&key, &value) {
		ret[key] = value
	}

	return ret, nil
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
