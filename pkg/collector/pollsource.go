package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/nirmata/runtime/pkg/runtimeevent"
)

// PollFunc returns the events observed since the previous call. It is called
// once per interval and must not block indefinitely; returning an error stops
// the source, which the collector then restarts with backoff.
type PollFunc func(ctx context.Context) ([]runtimeevent.Event, error)

// pollSource adapts periodic counter scraping (egressmgr/openexecmgr map reads) to
// the runtimeevent.Source seam.
type pollSource struct {
	name     string
	interval time.Duration
	poll     PollFunc

	// ticks is the clock seam: it returns the tick channel and a stop func.
	// Tests inject a channel they drive themselves so no test sleeps.
	ticks func(time.Duration) (<-chan time.Time, func())
}

// NewPollSource builds a Source that calls poll every interval and emits
// whatever it returns. A non-positive interval defaults to one second; a nil
// poll function is a wiring bug and panics here rather than at the first tick.
func NewPollSource(name string, interval time.Duration, poll PollFunc) runtimeevent.Source {
	if poll == nil {
		panic("collector: NewPollSource " + name + ": nil poll function")
	}
	if interval <= 0 {
		interval = time.Second
	}
	return &pollSource{
		name:     name,
		interval: interval,
		poll:     poll,
		ticks: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
	}
}

// Name implements runtimeevent.Source.
func (p *pollSource) Name() string { return p.name }

// Run polls until ctx is done or poll returns an error.
func (p *pollSource) Run(ctx context.Context, out chan<- runtimeevent.Event) error {
	tick, stop := p.ticks(p.interval)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick:
			evs, err := p.poll(ctx)
			if err != nil {
				return fmt.Errorf("polling %s: %w", p.name, err)
			}
			for _, ev := range evs {
				select {
				case <-ctx.Done():
					return nil
				case out <- ev:
				}
			}
		}
	}
}
