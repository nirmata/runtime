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

// Flag bit indices in the BPF `flags` array map. They mirror the defines in
// _cprog/maps.h; the C program tests `*f & (1 << IDX)`.
const (
	// DEFAULT_DENY makes the program drop everything not in allowed_ips.
	DEFAULT_DENY = 1
	// OBSERVE (LEARNING_MODE in the C) makes the program count every flow
	// into ip_events, keyed by (destination, verdict). The program computes
	// its verdict first and records before returning, so flows dropped by a
	// default-deny are observed too, with VERDICT_DENY.
	OBSERVE = 2

	// maxFlagIdx is the highest usable bit index: the map value is a __u8.
	maxFlagIdx = 7
)

// ErrNotLoaded is returned by map-touching methods when the BPF objects are not
// loaded (a filter built by a test, or a failed load).
var ErrNotLoaded = errors.New("egressfilter: bpf objects not loaded")

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
// Targets ParseTargets cannot represent are returned as typed rejections and
// logged; err covers only map-write failures. Both may be non-empty at once.
func (e *EgressFilter) AddIps(pair *compiler.AllowDenyPair) ([]RejectedTarget, error) {
	rejected, err := e.applyIps(pair, mapOpAdd)
	e.logRejected(rejected)
	return rejected, err
}

// DeleteIps removes the allow and deny targets of pair from the BPF maps.
// Rejections are reported for symmetry with AddIps: a target that was never
// programmed cannot be removed either, and the caller's bookkeeping should say
// so out loud.
func (e *EgressFilter) DeleteIps(pair *compiler.AllowDenyPair) ([]RejectedTarget, error) {
	return e.applyIps(pair, mapOpDelete)
}

type mapOp int

const (
	mapOpAdd mapOp = iota
	mapOpDelete
)

func (e *EgressFilter) applyIps(pair *compiler.AllowDenyPair, op mapOp) ([]RejectedTarget, error) {
	if pair == nil {
		return nil, nil
	}

	allowAddrs, _, allowRejected := ParseTargets(pair.Allow)
	denyAddrs, _, denyRejected := ParseTargets(pair.Deny)

	rejected := make([]RejectedTarget, 0, len(allowRejected)+len(denyRejected))
	rejected = append(rejected, allowRejected...)
	rejected = append(rejected, denyRejected...)

	var allowedMap, bannedMap *ebpf.Map
	if e.bpfObjs != nil {
		allowedMap, bannedMap = e.bpfObjs.AllowedIps, e.bpfObjs.BannedIps
	}

	var errs []error
	errs = append(errs, e.applyAddrs(allowedMap, "allowed_ips", allowAddrs, op))
	errs = append(errs, e.applyAddrs(bannedMap, "banned_ips", denyAddrs, op))

	if len(rejected) == 0 {
		rejected = nil
	}
	return rejected, errors.Join(errs...)
}

func (e *EgressFilter) applyAddrs(m *ebpf.Map, name string, addrs []netip.Addr, op mapOp) error {
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
			// ParseTargets only ever returns IPv4; belt and braces.
			continue
		}
		var err error
		if op == mapOpAdd {
			err = m.Put(&key, uint8(0))
		} else {
			err = m.Delete(&key)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", opVerb(op), name, err))
		}
	}
	return errors.Join(errs...)
}

func opVerb(op mapOp) string {
	if op == mapOpAdd {
		return "writing"
	}
	return "deleting from"
}

func (e *EgressFilter) logRejected(rejected []RejectedTarget) {
	if e.logger == nil {
		return
	}
	for _, r := range rejected {
		e.logger.Info("rejected egress network target: it will NOT be enforced",
			"target", r.Value, "reason", r.Reason)
	}
}

// SetFlagIdx sets or clears one bit of the flags map. It never panics: a
// unreadable flags map is logged and the write is skipped, because clobbering
// the other bits with a guessed value would silently change enforcement.
func (e *EgressFilter) SetFlagIdx(idx uint8, val bool) {
	if idx > maxFlagIdx {
		e.logError(fmt.Errorf("flag index %d out of range (max %d)", idx, maxFlagIdx),
			"refusing to set out-of-range egress flag")
		return
	}
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

// FlagIdx reports whether the given flag bit is set.
func (e *EgressFilter) FlagIdx(idx uint8) (bool, error) {
	if idx > maxFlagIdx {
		return false, fmt.Errorf("flag index %d out of range (max %d)", idx, maxFlagIdx)
	}
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

func (e *EgressFilter) logError(err error, msg string) {
	if e.logger == nil {
		return
	}
	e.logger.Error(err, msg)
}

func (e *EgressFilter) Attach(cgPath string) (link.Link, error) {
	if e.bpfObjs == nil {
		return nil, ErrNotLoaded
	}
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: e.bpfObjs.CgroupEgress,
	})
	if err != nil {
		return nil, err
	}
	return link, nil
}
