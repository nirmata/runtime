package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// SyntheticSource replays a fixed slice of events once and then returns. It
// backs unit tests and the sample pipeline; nothing in it touches the kernel.
type SyntheticSource struct {
	name   string
	events []runtimeevent.Event
}

// NewSyntheticSource builds a source that emits events in order.
func NewSyntheticSource(name string, events []runtimeevent.Event) *SyntheticSource {
	return &SyntheticSource{name: name, events: events}
}

// Name implements runtimeevent.Source.
func (s *SyntheticSource) Name() string { return s.name }

// Run emits every event, then returns nil. Returning nil (rather than
// blocking on ctx) tells the collector the source is finished, so it is not
// restarted and the replay happens exactly once.
func (s *SyntheticSource) Run(ctx context.Context, out chan<- runtimeevent.Event) error {
	for _, ev := range s.events {
		select {
		case <-ctx.Done():
			return nil
		case out <- ev:
		}
	}
	return nil
}

// LoadEvents parses a JSON array of runtimeevent.Event. HTTP facts are
// re-redacted by runtimeevent.HTTPFacts.UnmarshalJSON, so a fixture cannot
// smuggle an unredacted secret header into the event plane.
func LoadEvents(r io.Reader) ([]runtimeevent.Event, error) {
	if r == nil {
		return nil, fmt.Errorf("loading events: nil reader")
	}
	dec := json.NewDecoder(r)
	var evs []runtimeevent.Event
	if err := dec.Decode(&evs); err != nil {
		return nil, fmt.Errorf("decoding events: %w", err)
	}
	// Reject trailing content so a truncated or concatenated fixture is an
	// error rather than a silently short event list.
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decoding events: unexpected trailing JSON content")
		}
		return nil, fmt.Errorf("decoding events: trailing content: %w", err)
	}
	return evs, nil
}
