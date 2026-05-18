package probe

import (
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest egressBlock ./_cprog/probe.c

// call it something other than probe
type Probe struct {
	bpfObjs   *egressBlockObjects
	bannedIps map[string]struct{}
}

func New() (*Probe, error) {
	spec, err := loadEgressBlock()
	if err != nil {
		return nil, err
	}

	objs := &egressBlockObjects{} //nolint:typecheck

	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}

	return &Probe{}, nil
}

func (p *Probe) UpdateMap(ips []string) {
	newIpMap := make(map[string]struct{})

	for _, ip := range ips {
		newIpMap[ip] = struct{}{}
		delete(p.bannedIps, ip)

		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			continue
		}
		ipBytes := binary.BigEndian.Uint32(ip4)

		p.bpfObjs.BannedIps.Put(ipBytes, 0)
	}

	for ip := range p.bannedIps {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			continue
		}
		ipBytes := binary.BigEndian.Uint32(ip4)
		p.bpfObjs.BannedIps.Delete(ipBytes)
	}

	p.bannedIps = newIpMap
}

func (p *Probe) Attach() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	// attach to all interfaces for now till we think of how we wanna do pod filtering
	for _, iface := range ifaces {
		_, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   p.bpfObjs.TcEgress,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			return err
		}
	}
	return nil
}
