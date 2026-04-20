package datasource

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

type GadgetCollectRequest struct {
	EventType      string
	Namespace      string
	Pod            string
	CollectTimeout time.Duration
	Parameters     map[string]string
}

type GadgetCollector interface {
	Collect(ctx context.Context, request GadgetCollectRequest) ([]runtimeevents.Event, error)
}

type InspektorGadgetSource struct {
	ExecTimeout    time.Duration
	CollectTimeout time.Duration
	Collector      GadgetCollector
}

const (
	defaultIGExecTimeout    = 8 * time.Second
	defaultIGCollectTimeout = 5 * time.Second
)

func NewInspektorGadgetSource(execTimeout, collectTimeout time.Duration) *InspektorGadgetSource {
	if execTimeout <= 0 {
		execTimeout = defaultIGExecTimeout
	}
	if collectTimeout <= 0 {
		collectTimeout = defaultIGCollectTimeout
	}
	return &InspektorGadgetSource{
		ExecTimeout:    execTimeout,
		CollectTimeout: collectTimeout,
		Collector:      newDefaultGadgetCollector(),
	}
}

func (s *InspektorGadgetSource) Name() string {
	return "inspektorgadget"
}

func (s *InspektorGadgetSource) EventsForPod(ctx context.Context, pod *corev1.Pod, opts QueryOptions) ([]runtimeevents.Event, error) {
	logger := log.FromContext(ctx).WithName("inspektor-gadget-source")
	if pod == nil {
		logger.V(2).Info("skipping collection for nil pod")
		return []runtimeevents.Event{}, nil
	}
	eventTypes := NormalizeEventTypes(opts.EventTypes)
	if len(eventTypes) == 0 {
		logger.V(2).Info("no event types requested", "pod", pod.Name, "namespace", pod.Namespace)
		return []runtimeevents.Event{}, nil
	}
	logger.V(1).Info("collecting events", "pod", pod.Name, "namespace", pod.Namespace, "eventTypes", eventTypes, "execTimeout", s.ExecTimeout.String(), "collectTimeout", s.CollectTimeout.String())

	events := make([]runtimeevents.Event, 0)
	for _, eventType := range eventTypes {
		tctx, cancel := context.WithTimeout(ctx, s.ExecTimeout)
		logger.V(2).Info("collecting event type", "pod", pod.Name, "namespace", pod.Namespace, "eventType", eventType)
		collected, runErr := s.Collector.Collect(tctx, GadgetCollectRequest{
			EventType:      eventType,
			Namespace:      pod.Namespace,
			Pod:            pod.Name,
			CollectTimeout: s.CollectTimeout,
			Parameters:     opts.Parameters,
		})
		cancel()
		if runErr != nil {
			logger.Error(runErr, "event collection failed", "pod", pod.Name, "namespace", pod.Namespace, "eventType", eventType)
			return nil, runErr
		}
		logger.V(2).Info("event type collected", "pod", pod.Name, "namespace", pod.Namespace, "eventType", eventType, "count", len(collected))
		events = append(events, collected...)
	}
	if len(events) == 0 {
		logger.Info("no runtime events collected", "pod", pod.Name, "namespace", pod.Namespace, "eventTypes", eventTypes, "hint", "verify kernel eBPF support and host tracefs mounts (/sys/kernel/debug and /sys/kernel/tracing)")
	}
	logger.V(1).Info("collection completed", "pod", pod.Name, "namespace", pod.Namespace, "totalEvents", len(events))

	return events, nil
}
