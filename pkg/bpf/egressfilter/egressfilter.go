package egressfilter

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
)

//go:generate go tool bpf2go egressBlock ./_cprog/probe.c -- -I ./_cprog

// Flag bit indices in the BPF `flags` array map, mirroring the defines in
// _cprog/maps.h; the C program tests `*f & (1 << IDX)`.
const (
	DEFAULT_DENY = 1
	// OBSERVE is LEARNING_MODE in the C.
	OBSERVE = 2

	// maxFlagIdx is bounded by the __u8 map value.
	maxFlagIdx = 7
)

// ErrNotLoaded is returned by map-touching methods when the BPF objects are not
// loaded (a filter built by a test, or a failed load).
var ErrNotLoaded = errors.New("egressfilter: bpf objects not loaded")

type EgressFilter struct {
	logger  *logr.Logger
	bpfObjs *egressBlockObjects

	domainIDs    map[string]uint32
	nextDomainID uint32
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
	var zeroKey uint32
	var zeroVal uint8
	if err := objs.Flags.Put(&zeroKey, &zeroVal); err != nil {
		return nil, err
	}

	p := &EgressFilter{
		logger:  l,
		bpfObjs: objs,
	}

	return p, nil
}

// AddIps programs the allow and deny targets of pair into the BPF maps.
// Targets ParseTargets cannot represent, and DNS names that no longer fit the
// pod's domain table, are returned as typed rejections and logged; err covers
// only map-write failures. Both may be non-empty at once.
func (e *EgressFilter) AddIps(pair *compiler.AllowDenyPair) ([]RejectedTarget, error) {
	if pair == nil {
		return nil, nil
	}

	allow, deny, rejected := parsePair(pair)

	allowedIPs, bannedIPs := e.ipMaps()
	allowedDomains, bannedDomains := e.domainMaps()

	allowRejected, allowErr := e.putDomains(allowedDomains, "allowed_domains", allow.hosts)
	denyRejected, denyErr := e.putDomains(bannedDomains, "banned_domains", deny.hosts)
	rejected = append(rejected, allowRejected...)
	rejected = append(rejected, denyRejected...)
	e.logRejected(rejected)

	return rejected, errors.Join(
		putAddrs(allowedIPs, "allowed_ips", allow.addrs),
		putAddrs(bannedIPs, "banned_ips", deny.addrs),
		allowErr,
		denyErr,
	)
}

// DeleteIps removes the allow and deny targets of pair from the BPF maps.
// Rejections are reported for symmetry with AddIps: a target that was never
// programmed cannot be removed either.
func (e *EgressFilter) DeleteIps(pair *compiler.AllowDenyPair) ([]RejectedTarget, error) {
	if pair == nil {
		return nil, nil
	}

	allow, deny, rejected := parsePair(pair)

	allowedIPs, bannedIPs := e.ipMaps()
	allowedDomains, bannedDomains := e.domainMaps()

	return rejected, errors.Join(
		deleteAddrs(allowedIPs, "allowed_ips", allow.addrs),
		deleteAddrs(bannedIPs, "banned_ips", deny.addrs),
		e.deleteDomains(allowedDomains, "allowed_domains", allow.hosts),
		e.deleteDomains(bannedDomains, "banned_domains", deny.hosts),
	)
}

type sideTargets struct {
	addrs []netip.Addr
	hosts []string
}

// parsePair resolves both target lists of pair through the single target
// grammar. rejected is nil when nothing was rejected.
func parsePair(pair *compiler.AllowDenyPair) (allow, deny sideTargets, rejected []RejectedTarget) {
	allowAddrs, allowHosts, _, allowRejected := ParseTargets(pair.Allow)
	denyAddrs, denyHosts, _, denyRejected := ParseTargets(pair.Deny)
	allow = sideTargets{addrs: allowAddrs, hosts: allowHosts}
	deny = sideTargets{addrs: denyAddrs, hosts: denyHosts}
	if len(allowRejected)+len(denyRejected) == 0 {
		return allow, deny, nil
	}

	rejected = make([]RejectedTarget, 0, len(allowRejected)+len(denyRejected))
	rejected = append(rejected, allowRejected...)
	rejected = append(rejected, denyRejected...)
	return allow, deny, rejected
}

func (e *EgressFilter) ipMaps() (allowed, banned *ebpf.Map) {
	if e.bpfObjs == nil {
		return nil, nil
	}
	return e.bpfObjs.AllowedIps, e.bpfObjs.BannedIps
}

func putAddrs(m *ebpf.Map, name string, addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	if m == nil {
		return fmt.Errorf("%s: %w", name, ErrNotLoaded)
	}

	var errs []error
	for _, addr := range addrs {
		key, ok := addrKey(addr)
		if !ok {
			continue
		}
		if err := m.Put(&key, uint8(0)); err != nil {
			errs = append(errs, fmt.Errorf("writing %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func deleteAddrs(m *ebpf.Map, name string, addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	if m == nil {
		return fmt.Errorf("%s: %w", name, ErrNotLoaded)
	}

	var errs []error
	for _, addr := range addrs {
		key, ok := addrKey(addr)
		if !ok {
			continue
		}
		if err := m.Delete(&key); err != nil {
			errs = append(errs, fmt.Errorf("deleting from %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func (e *EgressFilter) logRejected(rejected []RejectedTarget) {
	if e.logger == nil {
		return
	}
	for _, r := range rejected {
		e.logger.Info("rejected egress network target: it will not be enforced",
			"target", r.Value, "reason", r.Reason)
	}
}

// SetFlagIdx sets or clears bit idx of the flags map. It panics on an
// out-of-range idx, which can only be a programming error.
func (e *EgressFilter) SetFlagIdx(idx uint8, val bool) {
	checkFlagIdx(idx)
	if e.bpfObjs == nil || e.bpfObjs.Flags == nil {
		e.logError(ErrNotLoaded, "cannot set egress flag")
		return
	}

	var key uint32
	var currentval uint8

	if err := e.bpfObjs.Flags.Lookup(&key, &currentval); err != nil {
		e.logError(err, "failed to read the flags map, egress flag not applied")
		return
	}

	if val {
		currentval |= 1 << idx
	} else {
		currentval &^= 1 << idx
	}

	if err := e.bpfObjs.Flags.Put(&key, &currentval); err != nil {
		e.logError(err, "failed to write flags map. corrupt state")
	}
}

// FlagIdx reports whether bit idx is set. It panics on an out-of-range idx.
func (e *EgressFilter) FlagIdx(idx uint8) (bool, error) {
	checkFlagIdx(idx)
	if e.bpfObjs == nil || e.bpfObjs.Flags == nil {
		return false, ErrNotLoaded
	}

	var key uint32
	var currentval uint8
	if err := e.bpfObjs.Flags.Lookup(&key, &currentval); err != nil {
		return false, fmt.Errorf("reading flags map: %w", err)
	}
	return currentval&(1<<idx) != 0, nil
}

func checkFlagIdx(idx uint8) {
	if idx > maxFlagIdx {
		panic(fmt.Sprintf("egressfilter: flag index %d out of range (max %d)", idx, maxFlagIdx))
	}
}

func (e *EgressFilter) logError(err error, msg string) {
	if e.logger == nil {
		return
	}
	e.logger.Error(err, msg)
}

// Attach hooks both programs onto one cgroup: the egress filter that decides,
// and the DNS snooper that reads answers off the ingress path so the filter can
// tell which addresses belong to a named domain. A half-completed attach closes
// what it opened, because a link the caller never receives can never be closed.
func (e *EgressFilter) Attach(cgPath string) ([]link.Link, error) {
	if e.bpfObjs == nil {
		return nil, ErrNotLoaded
	}
	egress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: e.bpfObjs.CgroupEgress,
	})
	if err != nil {
		return nil, err
	}
	dns, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: e.bpfObjs.CgroupDnsIngress,
	})
	if err != nil {
		return nil, errors.Join(err, egress.Close())
	}
	return []link.Link{egress, dns}, nil
}
