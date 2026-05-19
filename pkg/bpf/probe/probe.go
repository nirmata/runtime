package probe

import (
	"encoding/binary"
	"errors"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
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

	p := &Probe{
		bpfObjs:   objs,
		bannedIps: make(map[string]struct{}),
	}

	err = p.attach()
	if err != nil {
		return nil, err
	}

	return p, nil
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

func (p *Probe) attach() error {
	hostNs, err := netns.GetFromPath("/proc/1/ns/net")
	if err != nil {
		return err
	}
	defer hostNs.Close()

	// create a netlink handle inside host netns
	nlHandle, err := netlink.NewHandleAt(hostNs)
	if err != nil {
		return err
	}
	defer nlHandle.Close()

	// now list interfaces from host
	links, err := nlHandle.LinkList()
	if err != nil {
		return err
	}
	for _, link := range links {
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}

		if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}

		// attach the BPF program as a tc filter
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS, // or HANDLE_MIN_INGRESS
				Handle:    1,
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           p.bpfObjs.TcEgress.FD(),
			Name:         "tc_egress",
			DirectAction: true,
		}
		if err := netlink.FilterAdd(filter); err != nil {
			return err
		}
	}

	return nil
}
