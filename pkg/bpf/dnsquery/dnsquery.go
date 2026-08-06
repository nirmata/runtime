package dnsquery

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go tool bpf2go dnsQuery ./_cprog/query.bpf.c -- -I../include -I./_cprog

// Stat indices in the BPF `stats` per-CPU array, mirroring enum dns_query_stat
// in _cprog/maps.h.
const (
	StatRingbufFull    = 0
	StatNameUnreadable = 1
	statCount          = 2
)

// StatNames labels each stat index for metrics and logs.
var StatNames = [statCount]string{
	StatRingbufFull:    "ringbuf_full",
	StatNameUnreadable: "name_unreadable",
}

// ErrNotLoaded is returned by map-touching methods on an Observer built without
// kernel objects.
var ErrNotLoaded = errors.New("dnsquery: bpf objects not loaded")

// Observer owns the loaded question observer: one program, one ring buffer, and
// one cgroup-id gate shared by every cgroup it is attached to.
//
// A single instance is deliberate. cgroup_skb programs attach per cgroup, so
// observing N pods means N links, but sharing one object keeps one ring buffer
// and one reader goroutine instead of N of each.
type Observer struct {
	objs *dnsQueryObjects
}

func New() (*Observer, error) {
	objs := &dnsQueryObjects{}
	if err := loadDnsQueryObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("dnsquery: load: %w", err)
	}
	return &Observer{objs: objs}, nil
}

// Attach hooks the program onto one container cgroup's egress path. The returned
// link must be closed to detach.
func (o *Observer) Attach(cgroupPath string) (link.Link, error) {
	if o.objs == nil {
		return nil, ErrNotLoaded
	}
	return link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: o.objs.CgroupDnsEgress,
	})
}

// AddCgids admits cgroup ids to the kernel-side gate. A question from a cgroup
// absent from this map produces no record at all, which is what keeps an
// unselected pod free of observation cost.
func (o *Observer) AddCgids(cgids []uint64) error {
	if o.objs == nil {
		return ErrNotLoaded
	}
	var one uint8 = 1
	var errs []error
	for _, id := range cgids {
		if err := o.objs.Cgids.Put(&id, &one); err != nil {
			errs = append(errs, fmt.Errorf("dnsquery: admit cgid %d: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// DeleteCgids revokes cgroup ids. A key that is already gone is not an error:
// pod deletion and policy deletion can both revoke the same cgroup.
func (o *Observer) DeleteCgids(cgids []uint64) error {
	if o.objs == nil {
		return ErrNotLoaded
	}
	var errs []error
	for _, id := range cgids {
		if err := o.objs.Cgids.Delete(&id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("dnsquery: revoke cgid %d: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// Reader opens a reader over the event ring buffer.
func (o *Observer) Reader() (*ringbuf.Reader, error) {
	if o.objs == nil {
		return nil, ErrNotLoaded
	}
	return ringbuf.NewReader(o.objs.Events)
}

// ReadStats returns the cumulative loss counters, summed across CPUs. They are
// never reset: the caller reports deltas.
func (o *Observer) ReadStats() ([statCount]uint64, error) {
	var out [statCount]uint64
	if o.objs == nil {
		return out, ErrNotLoaded
	}
	for i := uint32(0); i < statCount; i++ {
		var perCPU []uint64
		if err := o.objs.Stats.Lookup(&i, &perCPU); err != nil {
			return out, fmt.Errorf("dnsquery: read stat %s: %w", StatNames[i], err)
		}
		for _, v := range perCPU {
			out[i] += v
		}
	}
	return out, nil
}

func (o *Observer) Close() error {
	if o.objs == nil {
		return nil
	}
	return o.objs.Close()
}
