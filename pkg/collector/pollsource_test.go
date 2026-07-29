package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
)

// fakeTicker is the injected clock seam for pollSource: the test decides when
// a tick happens, so no test waits on wall-clock time.
type fakeTicker struct {
	c        chan time.Time
	interval chan time.Duration
	stopped  chan int
}

func newFakeTicker() *fakeTicker {
	return &fakeTicker{
		c:        make(chan time.Time),
		interval: make(chan time.Duration, 1),
		stopped:  make(chan int, 1),
	}
}

func (f *fakeTicker) ticks(d time.Duration) (<-chan time.Time, func()) {
	f.interval <- d
	return f.c, func() { f.stopped <- 1 }
}

func newTestPollSource(name string, interval time.Duration, poll PollFunc, f *fakeTicker) *pollSource {
	return &pollSource{name: name, interval: interval, poll: poll, ticks: f.ticks}
}

func TestNewPollSourceNameAndIntervalDefault(t *testing.T) {
	src := NewPollSource("egress", 3*time.Second, func(context.Context) ([]runtimeevent.Event, error) {
		return nil, nil
	})
	if src.Name() != "egress" {
		t.Errorf("Name() = %q, want egress", src.Name())
	}
	ps, ok := src.(*pollSource)
	if !ok {
		t.Fatalf("NewPollSource returned %T, want *pollSource", src)
	}
	if ps.interval != 3*time.Second {
		t.Errorf("interval = %v, want 3s", ps.interval)
	}
	noop := func(context.Context) ([]runtimeevent.Event, error) { return nil, nil }
	zero := NewPollSource("z", 0, noop).(*pollSource)
	if zero.interval != time.Second {
		t.Errorf("non-positive interval = %v, want the 1s default", zero.interval)
	}
}

func TestPollSourceEmitsEveryEventOnEachTick(t *testing.T) {
	f := newFakeTicker()
	polls := make(chan int, 4)
	batches := [][]runtimeevent.Event{
		{netEvent("a"), netEvent("b")},
		{netEvent("c")},
		nil, // an empty poll must not stop the source
		{netEvent("d")},
	}
	n := 0
	ps := newTestPollSource("lsm", 30*time.Second, func(context.Context) ([]runtimeevent.Event, error) {
		batch := batches[n]
		n++
		polls <- n
		return batch, nil
	}, f)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan runtimeevent.Event, 8)
	done := make(chan error, 1)
	go func() { done <- ps.Run(ctx, out) }()

	if got := recvDuration(t, f.interval); got != 30*time.Second {
		t.Errorf("ticker interval = %v, want 30s", got)
	}
	// Nothing is emitted before the first tick.
	select {
	case ev := <-out:
		t.Fatalf("event %+v emitted before the first tick", ev)
	default:
	}

	var got []string
	for i := range batches {
		f.c <- time.Now()
		if p := recvInt(t, polls); p != i+1 {
			t.Fatalf("poll count = %d, want %d", p, i+1)
		}
		for range batches[i] {
			got = append(got, recvEvent(t, out).Comm)
		}
	}
	if diff := cmp.Diff([]string{"a", "b", "c", "d"}, got); diff != "" {
		t.Errorf("emitted events (-want +got):\n%s", diff)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v on cancel, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after cancel")
	}
	if recvInt(t, f.stopped) != 1 {
		t.Error("ticker was not stopped")
	}
}

func TestPollSourceReturnsPollError(t *testing.T) {
	f := newFakeTicker()
	sentinel := errors.New("map lookup failed")
	ps := newTestPollSource("lsm", time.Second, func(context.Context) ([]runtimeevent.Event, error) {
		return nil, sentinel
	}, f)

	done := make(chan error, 1)
	go func() { done <- ps.Run(context.Background(), make(chan runtimeevent.Event, 1)) }()
	recvDuration(t, f.interval)
	f.c <- time.Now()

	select {
	case err := <-done:
		if !errors.Is(err, sentinel) {
			t.Errorf("Run error = %v, want it to wrap %v", err, sentinel)
		}
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after a poll error")
	}
}

func TestNewPollSourceWithNilPollFuncPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewPollSource with a nil poll function did not panic")
		}
	}()
	NewPollSource("nowhere", time.Second, nil)
}

// TestPollSourceThroughCollectorWithShortInterval exercises the real
// time.Ticker path end to end with a sub-millisecond interval (no sleeps: the
// test blocks on the sink's channel).
func TestPollSourceThroughCollectorWithShortInterval(t *testing.T) {
	got := make(chan runtimeevent.Event, 16)
	c := New(logr.Discard(), 16, DefaultRestartBackoff, nil)
	c.AddSink(chanSink("sink", got))
	c.AddSource(NewPollSource("egress", time.Millisecond, func(context.Context) ([]runtimeevent.Event, error) {
		return []runtimeevent.Event{netEvent("poll")}, nil
	}))

	_, stop := runCollector(t, c)
	for i := 0; i < 3; i++ {
		if ev := recvEvent(t, got); ev.Comm != "poll" {
			t.Fatalf("event %d Comm = %q, want poll", i, ev.Comm)
		}
	}
	stop()
}
