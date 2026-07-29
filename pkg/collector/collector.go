// Package collector fans events in from every runtimeevent.Source, runs them
// through an ordered list of stages (attribution), and fans them out to every
// runtimeevent.Sink.
//
// The collector is the only place in kyverno-runtime where an event can be
// dropped without a policy decision, so every drop is counted:
// metrics.EventsDropped{source,reason} where reason is "buffer_full" or the
// name of the stage that rejected the event. Apparent quiet is never allowed
// to be indistinguishable from a stalled pipeline.
package collector

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/go-logr/logr"
)

// Defaults for the tunables exposed as Options.
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

	dropped atomic.Int64
	started atomic.Bool

	// after is the sleep seam used for restart backoff; tests replace it to
	// keep restart behavior deterministic. Must be set before Run.
	after func(time.Duration) <-chan time.Time
}

// Option customizes a Collector.
type Option func(*Collector)

// WithBufferSize sets the fan-in buffer depth (default DefaultBufferSize).
// Values < 1 are ignored.
func WithBufferSize(n int) Option {
	return func(c *Collector) {
		if n > 0 {
			c.bufferSize = n
		}
	}
}

// WithRestartBackoff sets how long a failed source waits before restarting
// (default DefaultRestartBackoff). Values <= 0 are ignored.
func WithRestartBackoff(d time.Duration) Option {
	return func(c *Collector) {
		if d > 0 {
			c.backoff = d
		}
	}
}

// WithMetrics attaches the shared metrics registry. Without it the collector
// still runs, but drops are only visible in logs.
func WithMetrics(m *metrics.Metrics) Option {
	return func(c *Collector) { c.metrics = m }
}

// New builds a Collector. Sources, stages, and sinks are registered
// separately so that daemon wiring can be conditional.
func New(log logr.Logger, opts ...Option) *Collector {
	c := &Collector{
		log:        log,
		bufferSize: DefaultBufferSize,
		backoff:    DefaultRestartBackoff,
		after:      time.After,
	}
	for _, o := range opts {
		if o != nil {
			o(c)
		}
	}
	c.events = make(chan taggedEvent, c.bufferSize)
	return c
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
		// Each source gets its own unbuffered channel; the forwarder tags
		// events with the source name and performs the non-blocking handoff
		// into the shared buffer, so a slow dispatch loop can never block a
		// source's Run for longer than one handoff.
		in := make(chan runtimeevent.Event)
		src := src

		wg.Add(1)
		go func() {
			defer wg.Done()
			c.forward(ctx, src.Name(), in)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runSource(ctx, src, in)
		}()
	}

	wg.Wait()
	c.log.V(2).Info("collector stopped", "dropped", c.Dropped())
	return nil
}

// runSource runs one source, restarting it with backoff after a failure. A
// source that reports runtimeevent.ErrSourceNotWired is logged once at V(0)
// and never restarted: its kernel bindings do not exist on this build, and
// retrying forever would only produce log noise.
func (c *Collector) runSource(ctx context.Context, src runtimeevent.Source, out chan<- runtimeevent.Event) {
	name := src.Name()
	for {
		if ctx.Err() != nil {
			return
		}

		err := utils.Guard("collector: source "+name, func() error {
			return src.Run(ctx, out)
		})

		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, runtimeevent.ErrSourceNotWired):
			c.log.V(0).Info("source is not wired on this platform; it will not be restarted",
				"source", name, "reason", err.Error())
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

// forward pumps one source's events into the shared fan-in buffer.
func (c *Collector) forward(ctx context.Context, source string, in <-chan runtimeevent.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-in:
			c.ingest(source, ev)
		}
	}
}

// ingest performs the non-blocking handoff into the fan-in buffer, counting
// the event as ingested or dropped. It reports whether the event was queued.
func (c *Collector) ingest(source string, ev runtimeevent.Event) bool {
	select {
	case c.events <- taggedEvent{source: source, ev: ev}:
		if c.metrics != nil {
			c.metrics.EventsIngested.WithLabelValues(source, string(ev.Kind)).Inc()
		}
		return true
	default:
		c.drop(source, reasonBufferFull)
		c.log.V(2).Info("collector buffer full; dropping event",
			"source", source, "kind", string(ev.Kind), "bufferSize", c.bufferSize)
		return false
	}
}

// dispatch drains the fan-in buffer through stages, then sinks.
func (c *Collector) dispatch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case te := <-c.events:
			c.process(te)
		}
	}
}

// process runs the stages and sinks for one event. Stages and sinks are
// third-party code from the collector's point of view, so each call is
// wrapped in utils.Guard: a panic must not take down the dispatch loop.
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
