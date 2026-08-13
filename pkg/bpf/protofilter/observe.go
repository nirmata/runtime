package protofilter

import (
	"errors"
	"fmt"

	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf"
)

// ProtoEventKey identifies one observation counter: a classified protocol plus
// the enforcement decision the kernel program applied to the flow.
type ProtoEventKey struct {
	Protocol string
	ALPN     string
	Decision runtimeevent.KernelDecision
}

// protoEventKernelKey mirrors `struct proto_event_key` in _cprog/maps.h.
type protoEventKernelKey struct {
	Proto    uint32
	Alpn     [compiler.MaxALPNLength]byte
	Decision uint32
}

// ReadProtoEvents reads and resets the proto_events counter map, so each poll
// reports a delta rather than a running total. Entries whose counter is zero
// are omitted; entries whose key cannot be decoded are counted in the error,
// never dropped silently.
func (p *ProtoFilter) ReadProtoEvents() (map[ProtoEventKey]uint32, error) {
	if p.bpfObjs == nil || p.bpfObjs.ProtoEvents == nil {
		return nil, ErrNotLoaded
	}
	return readAndResetProtoEvents(p.bpfObjs.ProtoEvents)
}

// SeedProtoEvent writes one observation entry through the proto_events map
// handle. It exists for the kernel smoke test in test/e2e, which pins the key
// marshaling seam; production counting happens in the BPF program.
func (p *ProtoFilter) SeedProtoEvent(target Target, decision runtimeevent.KernelDecision, count uint32) error {
	if p.bpfObjs == nil || p.bpfObjs.ProtoEvents == nil {
		return ErrNotLoaded
	}
	k, ok := targetKernelKey(target)
	if !ok {
		return fmt.Errorf("seeding proto_events: %q/%q cannot be encoded as a map key", target.Protocol, target.ALPN)
	}
	key := protoEventKernelKey{Proto: k.Proto, Alpn: k.Alpn, Decision: uint32(decision)}
	return p.bpfObjs.ProtoEvents.Put(&key, &count)
}

// RunPacket drives proto_egress over one synthetic packet via
// BPF_PROG_TEST_RUN and returns the verdict: 1 pass, 0 drop. data must start
// at the Ethernet header: the kernel derives skb->protocol from its ethertype
// and strips it, so the program still reads from L3 as it does on the cgroup
// hook. It exists for the kernel smoke test in test/e2e, which pins the
// classifier against hand-built packet shapes; production packets arrive via
// the cgroup attachment.
func (p *ProtoFilter) RunPacket(data []byte) (uint32, error) {
	if p.bpfObjs == nil || p.bpfObjs.ProtoEgress == nil {
		return 0, ErrNotLoaded
	}
	return p.bpfObjs.ProtoEgress.Run(&ebpf.RunOptions{Data: data})
}

func readAndResetProtoEvents(m *ebpf.Map) (map[ProtoEventKey]uint32, error) {
	out := make(map[ProtoEventKey]uint32)
	keys := make([]protoEventKernelKey, 0, 16)

	var (
		key   protoEventKernelKey
		count uint32
		errs  []error
	)
	// Collect first, delete after: deleting during iteration can make the
	// kernel restart the walk and yield duplicates.
	it := m.Iterate()
	for it.Next(&key, &count) {
		keys = append(keys, key)
		if count == 0 {
			continue
		}
		ek, err := eventKey(key)
		if err != nil {
			errs = append(errs, fmt.Errorf("%d observations not attributable: %w", count, err))
			continue
		}
		out[ek] += count
	}
	if err := it.Err(); err != nil {
		errs = append(errs, fmt.Errorf("iterating proto_events: %w", err))
	}

	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("resetting proto_events entry {proto %d, decision %d}: %w",
				keys[i].Proto, keys[i].Decision, err))
		}
	}

	return out, errors.Join(errs...)
}

func eventKey(k protoEventKernelKey) (ProtoEventKey, error) {
	token, ok := protoToken(k.Proto)
	if !ok {
		return ProtoEventKey{}, fmt.Errorf("proto_events entry with unrecognized protocol id %d", k.Proto)
	}
	alpn, err := decodeALPN(k.Alpn)
	if err != nil {
		return ProtoEventKey{}, err
	}
	return ProtoEventKey{
		Protocol: token,
		ALPN:     alpn,
		Decision: runtimeevent.KernelDecision(k.Decision),
	}, nil
}

// decodeALPN reads bytes up to the first NUL. The kernel only stores visible
// ASCII here, so anything else is corruption, not data to pass through.
func decodeALPN(b [compiler.MaxALPNLength]byte) (string, error) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), nil
		}
		if c < 0x21 || c > 0x7e {
			return "", fmt.Errorf("proto_events entry with non-ASCII ALPN bytes % x", b)
		}
	}
	return string(b[:]), nil
}
