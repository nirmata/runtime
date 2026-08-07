package dnsquery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-logr/logr"
)

// SourceName is the name this source reports to the collector. It is also the
// label used for its drop metrics.
const SourceName = "dnsquery"

// DefaultStatsInterval is how often the kernel-side loss counters are read.
const DefaultStatsInterval = 30 * time.Second

// LossFunc receives the increase in one kernel-side loss counter since the last
// poll.
type LossFunc func(reason string, delta uint64)

// Source drains the question ring buffer into the collector.
type Source struct {
	obs   *Observer
	log   logr.Logger
	clock func() time.Time

	statsInterval time.Duration
	onLoss        LossFunc
}

type Option func(*Source)

// WithLossFunc reports kernel-side loss deltas, normally to a metrics counter.
func WithLossFunc(f LossFunc) Option {
	return func(s *Source) { s.onLoss = f }
}

// WithStatsInterval overrides the loss-counter poll period.
func WithStatsInterval(d time.Duration) Option {
	return func(s *Source) { s.statsInterval = d }
}

// WithClock overrides the event timestamp source.
func WithClock(f func() time.Time) Option {
	return func(s *Source) { s.clock = f }
}

// NewSource builds the question source over an already-loaded observer.
func NewSource(log logr.Logger, o *Observer, opts ...Option) *Source {
	if o == nil {
		panic("dnsquery: nil observer")
	}
	s := &Source{
		obs:           o,
		log:           log,
		clock:         time.Now,
		statsInterval: DefaultStatsInterval,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Source) Name() string { return SourceName }

// Run drains the ring buffer until ctx is cancelled.
//
// A record the decoder rejects is counted and dropped rather than fatal: the
// kernel and the Go layout would have to disagree for that to happen, and
// returning would lose every subsequent question too.
func (s *Source) Run(ctx context.Context, out chan<- runtimeevent.Event) error {
	rd, err := s.obs.Reader()
	if err != nil {
		return fmt.Errorf("%s: open ring buffer: %w", SourceName, err)
	}

	// Read blocks in the kernel and does not observe ctx, so closing the reader
	// is what unblocks it.
	done := make(chan struct{})
	defer func() {
		close(done)
		_ = rd.Close()
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = rd.Close()
		case <-done:
		}
	}()

	go s.pollStats(ctx, done)

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("%s: read ring buffer: %w", SourceName, err)
		}

		ev, err := DecodeQueryEvent(rec.RawSample)
		if err != nil {
			// A record the kernel wrote but Go cannot parse means the layouts
			// have drifted; dropping it silently would hide that.
			s.log.Error(err, "discarding undecodable dns record", "bytes", len(rec.RawSample))
			s.reportLoss("undecodable", 1)
			continue
		}
		ev.Time = s.clock()

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// pollStats reports the increase in each kernel loss counter. The counters are
// cumulative and never reset, so only deltas are reported.
func (s *Source) pollStats(ctx context.Context, done <-chan struct{}) {
	t := time.NewTicker(s.statsInterval)
	defer t.Stop()

	// Seeding from the current totals keeps a restarted drain loop from
	// re-reporting every loss the counters have accumulated over their life.
	last, err := s.obs.ReadStats()
	if err != nil {
		s.log.Error(err, "reading dns loss counters failed")
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-t.C:
		}
		cur, err := s.obs.ReadStats()
		if err != nil {
			s.log.Error(err, "reading dns loss counters failed")
			continue
		}
		for i := range cur {
			if cur[i] <= last[i] {
				continue
			}
			delta := cur[i] - last[i]
			s.log.Info("dns questions lost in the kernel",
				"reason", StatNames[i], "count", delta)
			s.reportLoss(StatNames[i], delta)
		}
		last = cur
	}
}

func (s *Source) reportLoss(reason string, delta uint64) {
	if s.onLoss != nil {
		s.onLoss(reason, delta)
	}
}
