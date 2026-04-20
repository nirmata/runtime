package pipeline

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// CollectorRequest is the input to event collection.
type CollectorRequest struct {
	Pod        *corev1.Pod
	EventTypes []string
	Parameters map[string]string
}

// Collector collects runtime events from a pod.
type Collector interface {
	// Collect collects runtime events from a pod.
	// If the pod is not on this node, returns empty slice with no error.
	Collect(ctx context.Context, req CollectorRequest) ([]runtimeevents.Event, error)
}
