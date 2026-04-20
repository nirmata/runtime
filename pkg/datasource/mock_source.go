package datasource

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

type MockSource struct {
	Events []runtimeevents.Event
}

func NewMockSource(events ...runtimeevents.Event) *MockSource {
	return &MockSource{Events: append([]runtimeevents.Event{}, events...)}
}

func (m *MockSource) Name() string {
	return "mock"
}

func (m *MockSource) EventsForPod(_ context.Context, _ *corev1.Pod, opts QueryOptions) ([]runtimeevents.Event, error) {
	if len(opts.EventTypes) == 0 {
		return append([]runtimeevents.Event{}, m.Events...), nil
	}

	allowed := make(map[string]struct{}, len(opts.EventTypes))
	for _, eventType := range opts.EventTypes {
		allowed[eventType] = struct{}{}
	}

	out := make([]runtimeevents.Event, 0, len(m.Events))
	for _, event := range m.Events {
		if _, ok := allowed[event.Type]; ok {
			out = append(out, event)
		}
	}
	return out, nil
}

// StreamEventsForPod immediately delivers all matching mock events to handler
// then blocks until ctx is cancelled. This makes it suitable for unit tests.
func (m *MockSource) StreamEventsForPod(ctx context.Context, _ *corev1.Pod, opts QueryOptions, handler EventHandler) error {
	allowed := make(map[string]struct{}, len(opts.EventTypes))
	for _, et := range opts.EventTypes {
		allowed[et] = struct{}{}
	}
	for _, ev := range m.Events {
		if _, ok := allowed[ev.Type]; ok || len(opts.EventTypes) == 0 {
			handler(ev)
		}
	}
	<-ctx.Done()
	return nil
}
