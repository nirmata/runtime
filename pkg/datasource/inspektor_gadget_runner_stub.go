//go:build !linux

package datasource

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

type unsupportedGadgetCollector struct{}

func newDefaultGadgetCollector() GadgetCollector {
	return &unsupportedGadgetCollector{}
}

func (r *unsupportedGadgetCollector) Collect(_ context.Context, _ GadgetCollectRequest) ([]runtimeevents.Event, error) {
	return nil, fmt.Errorf("embedded Inspektor Gadget runtime is only supported on linux")
}

// StreamEventsForPod is not supported on non-linux platforms.
func (s *InspektorGadgetSource) StreamEventsForPod(_ context.Context, _ *corev1.Pod, _ QueryOptions, _ EventHandler) error {
	return fmt.Errorf("embedded Inspektor Gadget runtime is only supported on linux")
}
