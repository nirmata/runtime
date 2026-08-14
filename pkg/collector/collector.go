package collector

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nirmata/runtime/pkg/metrics"
	"github.com/nirmata/runtime/pkg/runtimeevent"
	"github.com/nirmata/runtime/pkg/utils"

	"github.com/go-logr/logr"
)

// Defaults used when New is given a non-positive value.
const (
	DefaultBufferSize     = 4096
	DefaultRestartBackoff = 5 * time.Second
)

// reasonBufferFull is the metrics label used when the fan-in buffer is full.
const reasonBufferFull = "buffer_full"

// Stage mutates/filters an event before sinks see it (attribution).
// Return false to drop.
type Stage interface {
	Name() string
	Process(ev *runtimeevent.Event) bool
}

// taggedEvent carries the producing source's name alongside the event so that
// drops occurring after fan-in can still be attributed to a source label.
type taggedEvent struct {
	source string
	ev     runtimeevent.Event
}

// Collector wires sources to sinks. Build it with New, register components
// before calling Run, then call Run exactly once.
type Collector struct {
	log     logr.Logger
	metrics *metrics.Metrics

	bufferSize int
	backoff    time.Duration

	sources []runtimeevent.Source
	stages  []Stage
	sinks   []runtimeevent.Sink

	events chan taggedEvent

	dropped   atomic.Int64
	started   atomic.Bool
	heartbeat atomic.Int64

	// after is the sleep seam used for restart backoff; tests replace it to
	// keep restart behavior deterministic. Must be set before Run.
	after func(time.Duration) <-chan time.Time
}

// New builds a Collector. Sources, stages, and sinks are registered separately
// so that daemon wiring can be conditional.
func New(log logr.Logger, bufferSize int, backoff time.Duration, m *metrics.Metrics) *Collector {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	if backoff <= 0 {
		backoff = DefaultRestartBackoff
	}
	return &Collector{
		log:        log,
		metrics:    m,
		bufferSize: bufferSize,
		backoff:    backoff,
		events:     make(chan taggedEvent, bufferSize),
		after:      time.After,
	}
}

// AddSource registers an event producer. Nil sources are ignored.
func (c *Collector) AddSource(src runtimeevent.Source) {
	if src == nil {
		return
	}
	c.sources = append(c.sources, src)
}

// AddStage appends a stage. Stages run in registration order, and the first
// one to return false drops the event.
func (c *Collector) AddStage(s Stage) {
	if s == nil {
		return
	}
	c.stages = append(c.stages, s)
}

// AddSink registers a consumer. Every sink sees every event that survives all
// stages; a panicking sink does not affect the others.
func (c *Collector) AddSink(s runtimeevent.Sink) {
	if s == nil {
		return
	}
	c.sinks = append(c.sinks, s)
}

// Dropped returns the total number of events dropped for any reason
// (buffer full, or rejected/panicked stage) since New.
func (c *Collector) Dropped() int64 { return c.dropped.Load() }

// Healthy reports whether the dispatch loop has ticked within maxAge. It is
// false before Run starts and after it stops, and detects a dispatch
// goroutine that is stuck rather than merely idle.
func (c *Collector) Healthy(maxAge time.Duration) bool {
	last := c.heartbeat.Load()
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) <= maxAge
}

// Run starts one goroutine per source plus a single dispatch goroutine, and
// blocks until ctx is cancelled. It returns nil on cancellation; a second
// call returns an error.
func (c *Collector) Run(ctx context.Context) error {
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("collector: Run already called")
	}

	c.log.V(2).Info("starting collector",
		"sources", len(c.sources), "stages", len(c.stages), "sinks", len(c.sinks),
		"bufferSize", c.bufferSize, "restartBackoff", c.backoff)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.dispatch(ctx)
	}()

	for _, src := range c.sources {
		// Two goroutines per source, joined by an unbuffered channel: runSource
		// keeps the source running and writes its events into in, forward tags
		// them with the source name and moves them into the shared c.events
		// buffer. The dispatch goroutine drains that buffer through process,
		// which is where stages enrich and sinks consume. The handoff is what
		// keeps a slow stage or sink from blocking a source's Run.
		in := make(chan runtimeevent.Event)
		src := src

		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runSource(ctx, src, in)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			c.forward(ctx, src.Name(), in)
		}()
	}

	wg.Wait()
	c.log.V(2).Info("collector stopped", "dropped", c.Dropped())
	return nil
}

// runSource runs one source, restarting it with backoff after a failure.
func (c *Collector) runSource(ctx context.Context, src runtimeevent.Source, out chan<- runtimeevent.Event) {
	name := src.Name()
	for {
		if ctx.Err() != nil {
			return
		}

		// Typically a poll source wrapping a single manager: it ticks on its
		// own interval, calls that manager's collect function and writes the
		// events it returns to out.
		err := utils.Guard("collector: source "+name, func() error {
			return src.Run(ctx, out)
		})

		switch {
		case ctx.Err() != nil:
			return
		case err == nil:
			c.log.V(2).Info("source finished", "source", name)
			return
		default:
			c.log.Error(err, "source failed; restarting after backoff",
				"source", name, "backoff", c.backoff)
		}

		select {
		case <-ctx.Done():
			return
		case <-c.after(c.backoff):
		}
	}
}

// forward takes the events runSource produced on in and hands them to the
// shared fan-in buffer, tagged with the source they came from.
func (c *Collector) forward(ctx context.Context, source string, in <-chan runtimeevent.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-in:
			// Non-blocking send: a full buffer drops the event instead of
			// stalling the source behind dispatch.
			select {
			case c.events <- taggedEvent{source: source, ev: ev}:
				if c.metrics != nil {
					c.metrics.EventsIngested.WithLabelValues(source, string(ev.Kind)).Inc()
				}
			default:
				c.drop(source, reasonBufferFull)
				c.log.V(2).Info("collector buffer full; dropping event",
					"source", source, "kind", string(ev.Kind), "bufferSize", c.bufferSize)
			}
		}
	}
}

// dispatch drains the fan-in buffer through stages, then sinks. It ticks the
// heartbeat on every wakeup, including idle ones, so Healthy reflects a live
// loop rather than event volume.
func (c *Collector) dispatch(ctx context.Context) {
ticker := time.NewTicker(time.Second)
defer ticker.Stop()
defer c.heartbeat.Store(0)

	c.heartbeat.Store(time.Now().UnixNano())
	for {
		select {
		case <-ctx.Done():
			return
		case te := <-c.events:
			c.process(te)
			c.heartbeat.Store(time.Now().UnixNano())
		case <-ticker.C:
			c.heartbeat.Store(time.Now().UnixNano())
		}
	}
}

// process enriches one event through the stages and, if it survives them all,
// hands it to every sink.
func (c *Collector) process(te taggedEvent) {
	ev := te.ev

	for _, st := range c.stages {
		name := st.Name()
		keep := false
		if err := utils.Guard("collector: stage "+name, func() error {
			keep = st.Process(&ev)
			return nil
		}); err != nil {
			c.log.Error(err, "stage panicked; dropping event", "stage", name, "source", te.source)
			keep = false
		}
		if !keep {
			c.drop(te.source, name)
			return
		}
	}

	for _, sk := range c.sinks {
		name := sk.Name()
		if err := utils.Guard("collector: sink "+name, func() error {
			sk.HandleEvent(ev)
			return nil
		}); err != nil {
			c.log.Error(err, "sink panicked; continuing", "sink", name, "source", te.source)
		}
	}
}

// drop records one dropped event.
func (c *Collector) drop(source, reason string) {
	c.dropped.Add(1)
	if c.metrics != nil {
		c.metrics.EventsDropped.WithLabelValues(source, reason).Inc()
	}
}
