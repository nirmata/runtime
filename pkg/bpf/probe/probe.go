package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest egressBlock ./_cprog/probe.c

// todo: call it something other than probe
type Probe struct {
	logger    *logr.Logger
	bpfObjs   *egressBlockObjects
	bannedIps map[string]struct{}
}

func New(l *logr.Logger) (*Probe, error) {
	spec, err := loadEgressBlock()
	if err != nil {
		return nil, err
	}

	objs := &egressBlockObjects{} //nolint:typecheck

	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}

	p := &Probe{
		logger:    l,
		bpfObjs:   objs,
		bannedIps: make(map[string]struct{}),
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
		ipBytes := binary.LittleEndian.Uint32(ip4)

		err := p.bpfObjs.BannedIps.Put(&ipBytes, uint8(0))
		if err != nil {
			p.logger.Error(err, "failed to add ip to bpf map", ip)
		}
	}

	for ip := range p.bannedIps {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			p.logger.Info("failed to parse ip as an ipv4", ip)
			continue
		}
		ipBytes := binary.LittleEndian.Uint32(ip4)
		p.bpfObjs.BannedIps.Delete(&ipBytes)
	}

	p.bannedIps = newIpMap
}

// we can't pass links because you cant get a nlHandle from a link, our best bet is pids
func (p *Probe) Attach(pid uint32) error {
	hostNs, err := netns.GetFromPath(fmt.Sprintf("/proc/%d/ns/net", pid))
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
		// not a pod interface
		if strings.HasPrefix(link.Attrs().Name, "lo") {
			continue
		}
		qdiscs, err := nlHandle.QdiscList(link)
		if err != nil {
			p.logger.Error(err, fmt.Sprintf("error listing qdiscs for link with index %d", link.Attrs().Index))
			continue
		}
		for _, disc := range qdiscs {
			if err := nlHandle.QdiscDel(disc); err != nil {
				p.logger.Error(err, fmt.Sprintf("error cleaning up qdisc %d", disc.Attrs().Handle))
				continue
			}
		}

		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}

		if err := nlHandle.QdiscAdd(qdisc); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}

		// attach the BPF program as a tc filter
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    1,
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           p.bpfObjs.TcEgress.FD(),
			Name:         "tc_egress",
			DirectAction: true,
		}
		if err := nlHandle.FilterAdd(filter); err != nil {
			return err
		}
	}

	return nil
}
