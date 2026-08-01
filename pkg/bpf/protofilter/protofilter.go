package protofilter

import (
	"errors"
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
)

//go:generate go tool bpf2go protoClassifier ./_cprog/probe.c -- -I ./_cprog

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
var ErrNotLoaded = errors.New("protofilter: bpf objects not loaded")

type ProtoFilter struct {
	logger  *logr.Logger
	bpfObjs *protoClassifierObjects
}

func New(l *logr.Logger) (*ProtoFilter, error) {
	spec, err := loadProtoClassifier()
	if err != nil {
		return nil, err
	}

	objs := &protoClassifierObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, err
	}

	var zeroKey uint32
	var zeroVal uint8
	if err := objs.Flags.Put(&zeroKey, &zeroVal); err != nil {
		return nil, err
	}

	return &ProtoFilter{
		logger:  l,
		bpfObjs: objs,
	}, nil
}

// AddProtocols programs the allow and deny targets of pair into the BPF maps.
// Targets ParseTargets cannot represent are returned as typed rejections and
// logged; err covers only map-write failures. Both may be non-empty at once.
func (p *ProtoFilter) AddProtocols(pair *compiler.AllowDenyPair) ([]RejectedTarget, error) {
	if pair == nil {
		return nil, nil
	}

	allow, deny, rejected := parsePair(pair)
	p.logRejected(rejected)

	allowedMap, bannedMap := p.protoMaps()
	return rejected, errors.Join(
		putTargets(allowedMap, "allowed_protos", allow),
		putTargets(bannedMap, "banned_protos", deny),
	)
}

// DeleteProtocols removes the allow and deny targets of pair from the BPF maps.
// Rejections are reported for symmetry with AddProtocols: a target that was
// never programmed cannot be removed either.
func (p *ProtoFilter) DeleteProtocols(pair *compiler.AllowDenyPair) ([]RejectedTarget, error) {
	if pair == nil {
		return nil, nil
	}

	allow, deny, rejected := parsePair(pair)

	allowedMap, bannedMap := p.protoMaps()
	return rejected, errors.Join(
		deleteTargets(allowedMap, "allowed_protos", allow),
		deleteTargets(bannedMap, "banned_protos", deny),
	)
}

// parsePair resolves both target lists of pair through the single target
// grammar. rejected is nil when nothing was rejected.
func parsePair(pair *compiler.AllowDenyPair) (allow, deny []Target, rejected []RejectedTarget) {
	allow, _, allowRejected := ParseTargets(pair.Allow)
	deny, _, denyRejected := ParseTargets(pair.Deny)
	if len(allowRejected)+len(denyRejected) == 0 {
		return allow, deny, nil
	}

	rejected = make([]RejectedTarget, 0, len(allowRejected)+len(denyRejected))
	rejected = append(rejected, allowRejected...)
	rejected = append(rejected, denyRejected...)
	return allow, deny, rejected
}

func (p *ProtoFilter) protoMaps() (allowed, banned *ebpf.Map) {
	if p.bpfObjs == nil {
		return nil, nil
	}
	return p.bpfObjs.AllowedProtos, p.bpfObjs.BannedProtos
}

func putTargets(m *ebpf.Map, name string, targets []Target) error {
	if len(targets) == 0 {
		return nil
	}
	if m == nil {
		return fmt.Errorf("%s: %w", name, ErrNotLoaded)
	}

	var errs []error
	for _, t := range targets {
		key, ok := targetKernelKey(t)
		if !ok {
			continue
		}
		if err := m.Put(&key, uint8(0)); err != nil {
			errs = append(errs, fmt.Errorf("writing %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func deleteTargets(m *ebpf.Map, name string, targets []Target) error {
	if len(targets) == 0 {
		return nil
	}
	if m == nil {
		return fmt.Errorf("%s: %w", name, ErrNotLoaded)
	}

	var errs []error
	for _, t := range targets {
		key, ok := targetKernelKey(t)
		if !ok {
			continue
		}
		if err := m.Delete(&key); err != nil {
			errs = append(errs, fmt.Errorf("deleting from %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func (p *ProtoFilter) logRejected(rejected []RejectedTarget) {
	if p.logger == nil {
		return
	}
	for _, r := range rejected {
		p.logger.Info("rejected egress protocol target: it will not be enforced",
			"target", r.Value, "reason", r.Reason)
	}
}

// SetFlagIdx sets or clears bit idx of the flags map. It panics on an
// out-of-range idx, which can only be a programming error.
func (p *ProtoFilter) SetFlagIdx(idx uint8, val bool) {
	checkFlagIdx(idx)
	if p.bpfObjs == nil || p.bpfObjs.Flags == nil {
		p.logError(ErrNotLoaded, "cannot set protocol flag")
		return
	}

	var key uint32
	var currentval uint8

	if err := p.bpfObjs.Flags.Lookup(&key, &currentval); err != nil {
		p.logError(err, "failed to read the flags map, protocol flag not applied")
		return
	}

	if val {
		currentval |= 1 << idx
	} else {
		currentval &^= 1 << idx
	}

	if err := p.bpfObjs.Flags.Put(&key, &currentval); err != nil {
		p.logError(err, "failed to write flags map. corrupt state")
	}
}

// FlagIdx reports whether bit idx is set. It panics on an out-of-range idx.
func (p *ProtoFilter) FlagIdx(idx uint8) (bool, error) {
	checkFlagIdx(idx)
	if p.bpfObjs == nil || p.bpfObjs.Flags == nil {
		return false, ErrNotLoaded
	}

	var key uint32
	var currentval uint8
	if err := p.bpfObjs.Flags.Lookup(&key, &currentval); err != nil {
		return false, fmt.Errorf("reading flags map: %w", err)
	}
	return currentval&(1<<idx) != 0, nil
}

func checkFlagIdx(idx uint8) {
	if idx > maxFlagIdx {
		panic(fmt.Sprintf("protofilter: flag index %d out of range (max %d)", idx, maxFlagIdx))
	}
}

func (p *ProtoFilter) logError(err error, msg string) {
	if p.logger == nil {
		return
	}
	p.logger.Error(err, msg)
}

func (p *ProtoFilter) Attach(cgPath string) (link.Link, error) {
	if p.bpfObjs == nil {
		return nil, ErrNotLoaded
	}
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: p.bpfObjs.ProtoEgress,
	})
	if err != nil {
		return nil, err
	}
	return link, nil
}
