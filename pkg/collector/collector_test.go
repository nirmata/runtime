package collector

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nirmata/runtime/pkg/metrics"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// testTimeout bounds every blocking receive in this file. It only turns a
// deadlock into a readable failure; no test depends on elapsed time.
const testTimeout = 5 * time.Second

// ---------- fakes ----------

type funcSource struct {
	name string
	run  func(ctx context.Context, out chan<- runtimeevent.Event) error
}

func (s *funcSource) Name() string { return s.name }
func (s *funcSource) Run(ctx context.Context, out chan<- runtimeevent.Event) error {
	return s.run(ctx, out)
}

type funcStage struct {
	name string
	fn   func(ev *runtimeevent.Event) bool
}

func (s funcStage) Name() string                        { return s.name }
func (s funcStage) Process(ev *runtimeevent.Event) bool { return s.fn(ev) }

type funcSink struct {
	name string
	fn   func(ev runtimeevent.Event)
}

func (s funcSink) Name() string                      { return s.name }
func (s funcSink) HandleEvent(ev runtimeevent.Event) { s.fn(ev) }

// chanSink records every event it sees on a buffered channel.
func chanSink(name string, got chan runtimeevent.Event) runtimeevent.Sink {
	return funcSink{name: name, fn: func(ev runtimeevent.Event) { got <- ev }}
}

// logEntry is one captured log line.
type logEntry struct {
	level int
	msg   string
	err   error
}

// recorder is a logr.LogSink that captures everything for assertions.
type recorder struct {
	mu      sync.Mutex
	entries []logEntry
}

func (r *recorder) Init(logr.RuntimeInfo) {}
func (r *recorder) Enabled(int) bool      { return true }
func (r *recorder) Info(level int, msg string, _ ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, logEntry{level: level, msg: msg})
}
func (r *recorder) Error(err error, msg string, _ ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, logEntry{level: -1, msg: msg, err: err})
}
func (r *recorder) WithValues(...any) logr.LogSink { return r }
func (r *recorder) WithName(string) logr.LogSink   { return r }

// errorsContaining returns captured Error() messages mentioning substr.
func (r *recorder) errorsContaining(substr string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.entries {
		if e.level == -1 && (strings.Contains(e.msg, substr) ||
			(e.err != nil && strings.Contains(e.err.Error(), substr))) {
			out = append(out, e.msg)
		}
	}
	return out
}

// ---------- helpers ----------

func recvEvent(t *testing.T, ch <-chan runtimeevent.Event) runtimeevent.Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for event")
		return runtimeevent.Event{}
	}
}

func recvInt(t *testing.T, ch <-chan int) int {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for int")
		return 0
	}
}

func recvDuration(t *testing.T, ch <-chan time.Duration) time.Duration {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for backoff")
		return 0
	}
}

// pumpForward runs c.forward over evs with nothing draining c.events, so the
// buffer state at each handoff is exact. It returns once forward has processed
// every event and exited.
func pumpForward(t *testing.T, c *Collector, source string, evs ...runtimeevent.Event) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	in := make(chan runtimeevent.Event)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forward(ctx, source, in)
	}()
	for _, ev := range evs {
		in <- ev
	}
	cancel()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("forward did not return after cancel")
	}
}

// runCollector starts c.Run and returns a func that cancels it and asserts a
// clean return.
func runCollector(t *testing.T, c *Collector) (context.Context, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	return ctx, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned %v, want nil", err)
			}
		case <-time.After(testTimeout):
			t.Fatal("Run did not return after cancel")
		}
	}
}

func netEvent(comm string) runtimeevent.Event {
	return runtimeevent.Event{Kind: runtimeevent.KindNet, Comm: comm, Net: &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.1.2.3")}}
}

// sliceSource emits the given events in order and then returns nil, so the
// collector treats it as finished and does not restart it.
func sliceSource(name string, events []runtimeevent.Event) runtimeevent.Source {
	return &funcSource{name: name, run: func(ctx context.Context, out chan<- runtimeevent.Event) error {
		for _, ev := range events {
			select {
			case <-ctx.Done():
				return nil
			case out <- ev:
			}
		}
		return nil
	}}
}

// ---------- tests ----------

func TestNewAppliesArgsAndFallsBackToDefaults(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	c := New(logr.Discard(), 7, time.Millisecond, m)
	if c.bufferSize != 7 || c.backoff != time.Millisecond || c.metrics != m {
		t.Errorf("got bufferSize=%d backoff=%v metrics=%v, want 7, 1ms and the registry",
			c.bufferSize, c.backoff, c.metrics != nil)
	}
	if got := cap(c.events); got != 7 {
		t.Errorf("buffer capacity = %d, want 7", got)
	}

	c = New(logr.Discard(), 0, -1, nil) // non-positive values fall back
	if c.bufferSize != DefaultBufferSize || c.backoff != DefaultRestartBackoff {
		t.Errorf("defaults: got bufferSize=%d backoff=%v, want %d and %v",
			c.bufferSize, c.backoff, DefaultBufferSize, DefaultRestartBackoff)
	}
	if got := cap(c.events); got != DefaultBufferSize {
		t.Errorf("buffer capacity = %d, want %d", got, DefaultBufferSize)
	}

	// Nil registrations are ignored rather than producing nil entries.
	c.AddSource(nil)
	c.AddStage(nil)
	c.AddSink(nil)
	if len(c.sources)+len(c.stages)+len(c.sinks) != 0 {
		t.Errorf("nil registrations were kept: %d/%d/%d", len(c.sources), len(c.stages), len(c.sinks))
	}
}

func TestStagesRunInRegistrationOrderBeforeSinks(t *testing.T) {
	var mu sync.Mutex
	var order []string

	c := New(logr.Discard(), 4, DefaultRestartBackoff, nil)
	for _, name := range []string{"a", "b", "c"} {
		name := name
		c.AddStage(funcStage{name: name, fn: func(ev *runtimeevent.Event) bool {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			ev.Comm += name
			return true
		}})
	}
	got := make(chan runtimeevent.Event, 1)
	c.AddSink(chanSink("sink", got))
	c.AddSource(sliceSource("synth", []runtimeevent.Event{netEvent("base:")}))

	_, stop := runCollector(t, c)
	ev := recvEvent(t, got)
	stop()

	mu.Lock()
	defer mu.Unlock()
	if diff := cmp.Diff([]string{"a", "b", "c"}, order); diff != "" {
		t.Errorf("stage order (-want +got):\n%s", diff)
	}
	if ev.Comm != "base:abc" {
		t.Errorf("sink saw Comm=%q, want %q (stage mutations must be visible)", ev.Comm, "base:abc")
	}
	if got := c.Dropped(); got != 0 {
		t.Errorf("Dropped() = %d, want 0", got)
	}
}

func TestStageReturningFalseDropsEventAndCountsByStageName(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	reached := make(chan int, 4)
	sinkSaw := make(chan runtimeevent.Event, 4)

	c := New(logr.Discard(), 4, DefaultRestartBackoff, m)
	c.AddStage(funcStage{name: "attribution", fn: func(*runtimeevent.Event) bool { return true }})
	c.AddStage(funcStage{name: "filter", fn: func(*runtimeevent.Event) bool {
		reached <- 1
		return false
	}})
	c.AddStage(funcStage{name: "never", fn: func(*runtimeevent.Event) bool {
		reached <- 99
		return true
	}})
	c.AddSink(chanSink("sink", sinkSaw))
	c.AddSource(sliceSource("synth", []runtimeevent.Event{netEvent("x")}))

	_, stop := runCollector(t, c)
	if got := recvInt(t, reached); got != 1 {
		t.Fatalf("reached = %d, want the dropping stage (1)", got)
	}
	stop()

	select {
	case ev := <-sinkSaw:
		t.Fatalf("sink saw dropped event %+v", ev)
	default:
	}
	select {
	case v := <-reached:
		t.Fatalf("stage after the dropping stage ran (%d)", v)
	default:
	}
	if got := c.Dropped(); got != 1 {
		t.Errorf("Dropped() = %d, want 1", got)
	}
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues("synth", "filter")); got != 1 {
		t.Errorf("EventsDropped{source=synth,reason=classifier} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.EventsIngested.WithLabelValues("synth", "net")); got != 1 {
		t.Errorf("EventsIngested{source=synth,kind=net} = %v, want 1", got)
	}
}

func TestForwardDropsWhenBufferFullAndCountsBufferFull(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	c := New(logr.Discard(), 2, DefaultRestartBackoff, m)

	pumpForward(t, c, "egress", netEvent("e"), netEvent("e"), netEvent("e"), netEvent("e"))

	if got := len(c.events); got != 2 {
		t.Errorf("buffered events = %d, want 2 (the buffer capacity)", got)
	}
	if got := c.Dropped(); got != 2 {
		t.Errorf("Dropped() = %d, want 2", got)
	}
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues("egress", reasonBufferFull)); got != 2 {
		t.Errorf("EventsDropped{source=egress,reason=buffer_full} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.EventsIngested.WithLabelValues("egress", "net")); got != 2 {
		t.Errorf("EventsIngested = %v, want 2", got)
	}
}

func TestBufferFullDropsAreCountedEndToEnd(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	release := make(chan struct{})
	blocked := make(chan int, 1)
	emitted := make(chan int, 1)
	var once sync.Once

	c := New(logr.Discard(), 1, DefaultRestartBackoff, m)
	c.AddSink(funcSink{name: "slow", fn: func(runtimeevent.Event) {
		// Hold the dispatch loop on the first event so the buffer fills.
		once.Do(func() {
			blocked <- 1
			<-release
		})
	}})

	const total = 32
	c.AddSource(&funcSource{name: "synth", run: func(ctx context.Context, out chan<- runtimeevent.Event) error {
		for i := 0; i < total; i++ {
			select {
			case <-ctx.Done():
				return nil
			case out <- netEvent("x"):
			}
		}
		emitted <- 1
		<-ctx.Done()
		return nil
	}})

	_, stop := runCollector(t, c)
	// Once every event has been handed to the forwarder while dispatch is
	// held on the first one, drops are arithmetically guaranteed: no sleep,
	// no polling.
	recvInt(t, blocked)
	recvInt(t, emitted)
	close(release)
	stop()

	dropped := c.Dropped()
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues("synth", reasonBufferFull)); got != float64(dropped) {
		t.Errorf("EventsDropped{buffer_full} = %v, want %d", got, dropped)
	}
	ingested := testutil.ToFloat64(m.EventsIngested.WithLabelValues("synth", "net"))
	if ingested+float64(dropped) != total {
		t.Errorf("ingested(%v) + dropped(%d) = %v, want %d: every event must be accounted for",
			ingested, dropped, ingested+float64(dropped), total)
	}
}

func TestPanickingStageDoesNotKillDispatchLoop(t *testing.T) {
	rec := &recorder{}
	m := metrics.New(prometheus.NewRegistry())
	got := make(chan runtimeevent.Event, 4)

	c := New(logr.New(rec), 8, DefaultRestartBackoff, m)
	c.AddStage(funcStage{name: "boomStage", fn: func(ev *runtimeevent.Event) bool {
		if ev.Comm == "bad" {
			panic("stage exploded")
		}
		return true
	}})
	c.AddSink(chanSink("sink", got))
	c.AddSource(sliceSource("synth", []runtimeevent.Event{netEvent("bad"), netEvent("good")}))

	_, stop := runCollector(t, c)
	if ev := recvEvent(t, got); ev.Comm != "good" {
		t.Errorf("sink saw %q, want the event after the panic (%q)", ev.Comm, "good")
	}
	stop()

	if n := len(rec.errorsContaining("stage panicked")); n != 1 {
		t.Errorf("logged %d stage-panic errors, want 1", n)
	}
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues("synth", "boomStage")); got != 1 {
		t.Errorf("EventsDropped{reason=boomStage} = %v, want 1 (a panicking stage drops its event)", got)
	}
}

func TestPanickingSinkDoesNotKillDispatchLoopOrOtherSinks(t *testing.T) {
	rec := &recorder{}
	good := make(chan runtimeevent.Event, 4)

	c := New(logr.New(rec), 8, DefaultRestartBackoff, nil)
	c.AddSink(funcSink{name: "boomSink", fn: func(runtimeevent.Event) { panic("sink exploded") }})
	c.AddSink(chanSink("goodSink", good))
	c.AddSource(sliceSource("synth", []runtimeevent.Event{netEvent("one"), netEvent("two")}))

	_, stop := runCollector(t, c)
	if ev := recvEvent(t, good); ev.Comm != "one" {
		t.Errorf("first event = %q, want one", ev.Comm)
	}
	if ev := recvEvent(t, good); ev.Comm != "two" {
		t.Errorf("second event = %q, want two (dispatch must survive the panic)", ev.Comm)
	}
	stop()

	if n := len(rec.errorsContaining("sink panicked")); n != 2 {
		t.Errorf("logged %d sink-panic errors, want 2", n)
	}
	if got := c.Dropped(); got != 0 {
		t.Errorf("Dropped() = %d, want 0: a panicking sink does not drop the event", got)
	}
}

func TestSourceRestartsWithBackoffAfterError(t *testing.T) {
	rec := &recorder{}
	runs := make(chan int, 8)
	backoffs := make(chan time.Duration, 8)
	fire := make(chan time.Time)

	const backoff = 42 * time.Millisecond
	c := New(logr.New(rec), 4, backoff, nil)
	c.after = func(d time.Duration) <-chan time.Time {
		backoffs <- d
		return fire
	}

	attempt := 0
	c.AddSource(&funcSource{name: "flaky", run: func(ctx context.Context, _ chan<- runtimeevent.Event) error {
		attempt++
		runs <- attempt
		if attempt == 1 {
			return errors.New("kernel map read failed")
		}
		<-ctx.Done()
		return nil
	}})

	_, stop := runCollector(t, c)
	if got := recvInt(t, runs); got != 1 {
		t.Fatalf("first run = %d, want 1", got)
	}
	if got := recvDuration(t, backoffs); got != backoff {
		t.Errorf("restart backoff = %v, want %v", got, backoff)
	}
	fire <- time.Now() // release the backoff wait deterministically
	if got := recvInt(t, runs); got != 2 {
		t.Fatalf("second run = %d, want 2 (source must be restarted)", got)
	}
	stop()

	if n := len(rec.errorsContaining("restarting after backoff")); n != 1 {
		t.Errorf("logged %d restart errors, want 1", n)
	}
}

func TestSourceReturningNilIsNotRestarted(t *testing.T) {
	runs := make(chan int, 8)
	c := New(logr.Discard(), 4, time.Millisecond, nil)
	c.after = func(time.Duration) <-chan time.Time {
		t.Error("backoff scheduled for a source that finished cleanly")
		ch := make(chan time.Time)
		return ch
	}
	attempt := 0
	c.AddSource(&funcSource{name: "oneshot", run: func(context.Context, chan<- runtimeevent.Event) error {
		attempt++
		runs <- attempt
		return nil
	}})
	blocked := make(chan int, 1)
	c.AddSource(&funcSource{name: "live", run: func(ctx context.Context, _ chan<- runtimeevent.Event) error {
		blocked <- 1
		<-ctx.Done()
		return nil
	}})

	_, stop := runCollector(t, c)
	if got := recvInt(t, runs); got != 1 {
		t.Fatalf("run count = %d, want 1", got)
	}
	recvInt(t, blocked)
	stop()

	select {
	case n := <-runs:
		t.Fatalf("finished source was restarted (run #%d)", n)
	default:
	}
}

func TestRunReturnsCleanlyOnContextCancel(t *testing.T) {
	c := New(logr.Discard(), 2, DefaultRestartBackoff, nil)
	c.AddSource(&funcSource{name: "blocking", run: func(ctx context.Context, _ chan<- runtimeevent.Event) error {
		<-ctx.Done()
		return ctx.Err()
	}})
	c.AddStage(funcStage{name: "keep", fn: func(*runtimeevent.Event) bool { return true }})
	c.AddSink(funcSink{name: "noop", fn: func(runtimeevent.Event) {}})

	_, stop := runCollector(t, c) // stop asserts Run returned nil
	stop()
}

func TestHealthyFalseBeforeRunAndTrueOnceStarted(t *testing.T) {
	c := New(logr.Discard(), DefaultBufferSize, DefaultRestartBackoff, nil)
	if c.Healthy(time.Second) {
		t.Error("Healthy() = true before Run, want false")
	}

	_, stop := runCollector(t, c)
	deadline := time.Now().Add(testTimeout)
	for !c.Healthy(time.Second) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !c.Healthy(time.Second) {
		t.Error("Healthy() = false while dispatch loop is running, want true")
	}
	stop()
}

func TestRunTwiceReturnsError(t *testing.T) {
	started := make(chan int, 1)
	c := New(logr.Discard(), DefaultBufferSize, DefaultRestartBackoff, nil)
	c.AddSource(&funcSource{name: "live", run: func(ctx context.Context, _ chan<- runtimeevent.Event) error {
		started <- 1
		<-ctx.Done()
		return nil
	}})

	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- c.Run(ctx) }()
	recvInt(t, started) // the first Run has definitely claimed the collector

	// Same ctx, so even a (buggy) blocking second Run is released by cancel.
	if err := c.Run(ctx); err == nil {
		t.Error("second Run returned nil, want an error")
	}

	cancel()
	select {
	case err := <-first:
		if err != nil {
			t.Errorf("first Run returned %v, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("first Run did not return after cancel")
	}
}

func TestCollectorWithoutMetricsStillCountsDrops(t *testing.T) {
	c := New(logr.Discard(), 1, DefaultRestartBackoff, nil)
	pumpForward(t, c, "s", netEvent("a"), netEvent("b"))
	if got := c.Dropped(); got != 1 {
		t.Errorf("Dropped() = %d, want 1", got)
	}
}
