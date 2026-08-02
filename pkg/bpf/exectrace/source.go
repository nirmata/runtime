package exectrace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-logr/logr"
)

//go:generate go tool bpf2go execTrace ./_cprog/exec.bpf.c -- -I../include -I./_cprog

// SourceName is the name this source reports to the collector, and the value of
// the `source` label on its ingest and drop metrics.
const SourceName = "exec-trace"

// statInterval bounds how stale a kernel-side loss counter can be. The counters
// only move when an observation was lost, so this ticker is idle in the normal
// case.
const statInterval = 30 * time.Second

// statNames is indexed by the `enum exec_stat` values in _cprog/maps.h.
var statNames = [...]string{"argvOverflow", "ringbufFull", "argvUnreadable"}

const statCount = len(statNames)

// Source streams one event per execve in a selected cgroup.
type Source struct {
	log   logr.Logger
	objs  execTraceObjects
	link  link.Link
	rd    *ringbuf.Reader
	clock func() time.Time
}

// New loads and attaches the kernel program. The caller owns Close.
func New(log logr.Logger) (*Source, error) {
	s := &Source{log: log, clock: time.Now}

	if err := loadExecTraceObjects(&s.objs, nil); err != nil {
		return nil, fmt.Errorf("%s: loading objects: %w", SourceName, err)
	}

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: s.objs.TraceExec,
	})
	if err != nil {
		_ = s.objs.Close()
		return nil, fmt.Errorf("%s: attaching sched_process_exec: %w", SourceName, err)
	}
	s.link = l

	rd, err := ringbuf.NewReader(s.objs.Events)
	if err != nil {
		_ = l.Close()
		_ = s.objs.Close()
		return nil, fmt.Errorf("%s: opening ring buffer: %w", SourceName, err)
	}
	s.rd = rd

	return s, nil
}

func (s *Source) Name() string { return SourceName }

// AddCgids admits a pod's cgroups. Until a cgroup id is in this map the kernel
// program returns before reserving anything, so an unselected pod costs one
// hash lookup per exec and produces no traffic.
func (s *Source) AddCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		if err := s.objs.Cgids.Put(&cgid, uint8(0)); err != nil {
			errs = append(errs, fmt.Errorf("adding cgid %d: %w", cgid, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Source) DeleteCgids(cgids []uint64) error {
	var errs []error
	for _, cgid := range cgids {
		if err := s.objs.Cgids.Delete(&cgid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("deleting cgid %d: %w", cgid, err))
		}
	}
	return errors.Join(errs...)
}

// Run drains the ring buffer until ctx is done.
func (s *Source) Run(ctx context.Context, out chan<- runtimeevent.Event) error {
	// ringbuf.Read has no deadline; closing the reader is what unblocks it.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.rd.Close()
		case <-done:
		}
	}()

	go s.pollStats(ctx, done)

	for {
		rec, err := s.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("%s: reading ring buffer: %w", SourceName, err)
		}

		ev, err := DecodeExecEvent(rec.RawSample)
		if err != nil {
			// A record the kernel wrote but Go cannot parse means the layouts
			// have drifted; dropping it silently would hide that.
			s.log.Error(err, "discarding undecodable exec record", "source", SourceName, "bytes", len(rec.RawSample))
			continue
		}
		ev.Time = s.clock()

		if s.log.V(2).Enabled() {
			s.log.V(2).Info("observed exec", "source", SourceName,
				"cgroupID", ev.CgroupID, "pid", ev.PID,
				"filename", ev.Exec.Filename, "argv", ev.Exec.Argv)
		}

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// pollStats reports the kernel-side loss counters. They describe observations
// that never became records, so nothing downstream can infer them.
func (s *Source) pollStats(ctx context.Context, done <-chan struct{}) {
	t := time.NewTicker(statInterval)
	defer t.Stop()

	var last [statCount]uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-t.C:
		}
		cur, err := s.readStats()
		if err != nil {
			s.log.Error(err, "reading exec loss counters", "source", SourceName)
			continue
		}
		for i := range cur {
			if cur[i] > last[i] {
				s.log.Info("kernel dropped exec observations",
					"source", SourceName, "reason", statNames[i], "delta", cur[i]-last[i], "total", cur[i])
			}
		}
		last = cur
	}
}

func (s *Source) readStats() ([statCount]uint64, error) {
	var out [statCount]uint64
	for i := uint32(0); i < uint32(statCount); i++ {
		var perCPU []uint64
		if err := s.objs.Stats.Lookup(&i, &perCPU); err != nil {
			return out, fmt.Errorf("stat %d: %w", i, err)
		}
		for _, v := range perCPU {
			out[i] += v
		}
	}
	return out, nil
}

func (s *Source) Close() error {
	var errs []error
	if s.rd != nil {
		if err := s.rd.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if s.link != nil {
		errs = append(errs, s.link.Close())
	}
	errs = append(errs, s.objs.Close())
	return errors.Join(errs...)
}
