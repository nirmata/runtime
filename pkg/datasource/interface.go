package datasource

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

type QueryOptions struct {
	EventTypes []string
	Parameters map[string]string
}

type Source interface {
	Name() string
	EventsForPod(ctx context.Context, pod *corev1.Pod, opts QueryOptions) ([]runtimeevents.Event, error)
}

// EventHandler is called for each event received from a streaming source.
// It must be goroutine-safe. The context passed to StreamEventsForPod controls
// the lifetime of the stream; returning an error from the handler does not stop
// the stream.
type EventHandler func(event runtimeevents.Event)

// StreamingSource streams eBPF events continuously for a pod until the context
// is cancelled. It is the preferred collection path for production use because
// it captures every event in real-time rather than sampling a fixed window.
type StreamingSource interface {
	Source
	// StreamEventsForPod starts a continuous eBPF stream for the pod and calls
	// handler for every matching event. It blocks until ctx is cancelled or a
	// fatal error occurs, then returns.
	StreamEventsForPod(ctx context.Context, pod *corev1.Pod, opts QueryOptions, handler EventHandler) error
}
