//go:build linux

package datasource

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	localruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"

	// Set environment to local for embedded gadget runtime.
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/environment/local"
)

func init() {
	// Register the OCI handler so gadget images can be pulled and parsed.
	// The ebpf and localmanager operators self-register via their init() functions
	// through the blank imports above.
	operators.RegisterDataOperator(ocihandler.OciHandler)
}

// gadgetOperators holds the initialized data operators, set up once.
var (
	gadgetOperators     []operators.DataOperator
	gadgetOperatorsOnce sync.Once
)

func getGadgetOperators() []operators.DataOperator {
	gadgetOperatorsOnce.Do(func() {
		logger := log.Log.WithName("gadget-operators")
		for name, op := range operators.GetDataOperators() {
			opParams := apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
			if err := op.Init(opParams); err != nil {
				logger.V(1).Info("skipping operator init", "operator", name, "error", err)
				continue
			}
			logger.V(1).Info("initialized operator", "operator", name)
			gadgetOperators = append(gadgetOperators, op)
		}
		logger.Info("gadget operators initialized", "count", len(gadgetOperators))
	})
	return gadgetOperators
}

type embeddedGadgetCollector struct{}

func newDefaultGadgetCollector() GadgetCollector {
	return &embeddedGadgetCollector{}
}

func (r *embeddedGadgetCollector) Collect(ctx context.Context, request GadgetCollectRequest) ([]runtimeevents.Event, error) {
	logger := log.FromContext(ctx).WithName("gadget-collector")

	runtime := localruntime.New()
	if err := runtime.Init(nil); err != nil {
		return nil, fmt.Errorf("initialize embedded runtime: %w", err)
	}
	defer runtime.Close()

	imageName, params, err := gadgetRunConfig(request)
	if err != nil {
		return nil, err
	}
	paramValues := api.ParamValues(params)

	ops := getGadgetOperators()

	events := make([]runtimeevents.Event, 0)
	var lock sync.Mutex
	var totalPackets int64

	// Create a simple subscriber operator that subscribes to all data sources
	// during the Run flow. This ensures subscriptions are on the SAME data source
	// objects that the eBPF operator writes to (not stale ones from GetGadgetInfo).
	subscriberOp := simple.New("kyverno-subscriber",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, ds := range gadgetCtx.GetDataSources() {
				dsName := ds.Name()
				logger.V(2).Info("subscribing to datasource", "name", dsName, "type", ds.Type())
				if err := ds.SubscribePacket(func(source datasource.DataSource, packet datasource.Packet) error {
					lock.Lock()
					totalPackets++
					lock.Unlock()

					collected := packetToRuntimeEvents(source, packet, request)
					if len(collected) > 0 {
						lock.Lock()
						events = append(events, collected...)
						lock.Unlock()
					}
					return nil
				}, 50); err != nil {
					return fmt.Errorf("subscribe gadget datasource %s: %w", dsName, err)
				}
			}
			return nil
		}),
		simple.WithPriority(50000), // Run after eBPF and OCI operators register data sources
	)
	subscriberOpParams := apihelpers.ToParamDescs(subscriberOp.GlobalParams()).ToParams()
	if err := subscriberOp.Init(subscriberOpParams); err != nil {
		return nil, fmt.Errorf("init subscriber operator: %w", err)
	}

	allOps := append(slices.Clone(ops), subscriberOp)

	// Use a cancellable context so all goroutines spawned by the gadget
	// (including perf buffer readers) are signalled to stop when we are done.
	collectCtx, collectCancel := context.WithCancel(ctx)
	defer collectCancel()

	gadgetCtx := gadgetcontext.New(
		collectCtx,
		imageName,
		gadgetcontext.WithTimeout(request.CollectTimeout),
		gadgetcontext.WithDataOperators(allOps...),
	)

	logger.V(1).Info("running gadget", "gadget", imageName, "timeout", request.CollectTimeout)
	if err := runtime.RunGadget(gadgetCtx, nil, paramValues); err != nil {
		return nil, fmt.Errorf("run gadget %s: %w", imageName, err)
	}

	// Explicitly cancel to stop any lingering goroutines from the gadget run.
	collectCancel()

	lock.Lock()
	defer lock.Unlock()
	logger.V(1).Info("gadget collection finished", "gadget", imageName, "totalPackets", totalPackets, "matchedEvents", len(events))
	return slices.Clone(events), nil
}

// streamGadget runs the named gadget with no built-in timeout, calling handler
// for every matching event. It blocks until ctx is cancelled or RunGadget
// returns (e.g. on fatal eBPF error).
func streamGadget(ctx context.Context, imageName string, paramValues api.ParamValues, request GadgetCollectRequest, handler EventHandler) error {
	logger := log.FromContext(ctx).WithName("gadget-stream")

	runtime := localruntime.New()
	if err := runtime.Init(nil); err != nil {
		return fmt.Errorf("initialize embedded runtime: %w", err)
	}
	defer runtime.Close()

	ops := getGadgetOperators()

	subscriberOp := simple.New("kyverno-stream-subscriber",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, ds := range gadgetCtx.GetDataSources() {
				dsName := ds.Name()
				logger.V(2).Info("subscribing to datasource (stream)", "name", dsName)
				if err := ds.SubscribePacket(func(source datasource.DataSource, packet datasource.Packet) error {
					for _, ev := range packetToRuntimeEvents(source, packet, request) {
						handler(ev)
					}
					return nil
				}, 50); err != nil {
					return fmt.Errorf("subscribe gadget datasource %s: %w", dsName, err)
				}
			}
			return nil
		}),
		simple.WithPriority(50000),
	)
	subscriberOpParams := apihelpers.ToParamDescs(subscriberOp.GlobalParams()).ToParams()
	if err := subscriberOp.Init(subscriberOpParams); err != nil {
		return fmt.Errorf("init stream subscriber operator: %w", err)
	}

	allOps := append(slices.Clone(ops), subscriberOp)

	// Run without a timeout — the gadget runs until ctx is cancelled.
	gadgetCtx := gadgetcontext.New(
		ctx,
		imageName,
		gadgetcontext.WithDataOperators(allOps...),
	)

	logger.V(1).Info("starting streaming gadget", "gadget", imageName)
	if err := runtime.RunGadget(gadgetCtx, nil, paramValues); err != nil {
		// context cancellation causes RunGadget to return; treat it as clean stop.
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("stream gadget %s: %w", imageName, err)
	}
	return nil
}

// StreamEventsForPod implements datasource.StreamingSource. It starts one
// long-running gadget per requested event type and delivers events to handler
// until ctx is cancelled.
func (s *InspektorGadgetSource) StreamEventsForPod(ctx context.Context, pod *corev1.Pod, opts QueryOptions, handler EventHandler) error {
	logger := log.FromContext(ctx).WithName("inspektor-gadget-source")
	if pod == nil {
		return nil
	}
	eventTypes := NormalizeEventTypes(opts.EventTypes)
	if len(eventTypes) == 0 {
		return nil
	}
	logger.V(1).Info("starting streaming collection", "pod", pod.Name, "namespace", pod.Namespace, "eventTypes", eventTypes)

	var wg sync.WaitGroup

	for _, eventType := range eventTypes {
		req := GadgetCollectRequest{
			EventType:      eventType,
			Namespace:      pod.Namespace,
			Pod:            pod.Name,
			CollectTimeout: 0, // no timeout for streaming
			Parameters:     opts.Parameters,
		}
		imageName, params, err := gadgetRunConfig(req)
		if err != nil {
			return err
		}
		paramValues := api.ParamValues(params)

		wg.Add(1)
		go func(req GadgetCollectRequest, imageName string, paramValues api.ParamValues) {
			defer wg.Done()
			if err := streamGadget(ctx, imageName, paramValues, req, handler); err != nil {
				logger.Error(err, "stream gadget failed", "pod", pod.Name, "namespace", pod.Namespace, "eventType", req.EventType)
				logger.Info("falling back to periodic collection", "pod", pod.Name, "namespace", pod.Namespace, "eventType", req.EventType, "collectTimeout", s.CollectTimeout.String())
				s.pollFallback(ctx, req, handler, logger)
			}
			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}(req, imageName, paramValues)
	}

	<-ctx.Done()
	wg.Wait()
	return nil
}

func (s *InspektorGadgetSource) pollFallback(ctx context.Context, req GadgetCollectRequest, handler EventHandler, logger logr.Logger) {
	collectWindow := s.CollectTimeout
	if collectWindow <= 0 {
		collectWindow = defaultIGCollectTimeout
	}
	for ctx.Err() == nil {
		tctx, cancel := context.WithTimeout(ctx, s.ExecTimeout)
		collected, err := s.Collector.Collect(tctx, GadgetCollectRequest{
			EventType:      req.EventType,
			Namespace:      req.Namespace,
			Pod:            req.Pod,
			CollectTimeout: collectWindow,
			Parameters:     req.Parameters,
		})
		cancel()
		if err != nil {
			logger.Error(err, "fallback collection failed", "eventType", req.EventType, "pod", req.Pod, "namespace", req.Namespace)
		} else {
			for _, ev := range collected {
				handler(ev)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(collectWindow):
		}
	}
}

func packetToRuntimeEvents(source datasource.DataSource, packet datasource.Packet, request GadgetCollectRequest) []runtimeevents.Event {
	fieldsByEvent := make([]map[string]string, 0)
	switch source.Type() {
	case datasource.TypeSingle:
		data, ok := packet.(datasource.Data)
		if !ok {
			return nil
		}
		fieldsByEvent = append(fieldsByEvent, extractPacketFields(source, data))
	case datasource.TypeArray:
		array, ok := packet.(datasource.DataArray)
		if !ok {
			return nil
		}
		for i := 0; i < array.Len(); i++ {
			fieldsByEvent = append(fieldsByEvent, extractPacketFields(source, array.Get(i)))
		}
	default:
		return nil
	}

	events := make([]runtimeevents.Event, 0, len(fieldsByEvent))
	for _, fields := range fieldsByEvent {
		if !matchesPod(fields, request.Namespace, request.Pod) {
			continue
		}
		// When collecting for a specific pod, skip events that have no k8s
		// metadata at all — they originate from unrelated system processes
		// captured by the node-wide eBPF program and would otherwise appear
		// in every pod's PolicyReport as noise.
		if request.Namespace != "" && !eventHasPodMetadata(fields) {
			continue
		}
		events = append(events, runtimeevents.Event{
			Type:      normalizePacketEventType(request.EventType, fields),
			Source:    "inspektorgadget",
			Namespace: coalesceField(fields, request.Namespace, "k8s.namespace", "namespace"),
			PodName:   coalesceField(fields, request.Pod, "k8s.podName", "k8s.podname", "pod", "podName"),
			Timestamp: time.Now().UTC(),
			Fields:    fields,
		})
	}
	return events
}

// eventHasPodMetadata returns true if the event fields include both a k8s
// namespace and a pod name. Events captured node-wide by eBPF (e.g. from
// system processes) typically lack these fields.
func eventHasPodMetadata(fields map[string]string) bool {
	ns := coalesceField(fields, "", "k8s.namespace", "namespace")
	pod := coalesceField(fields, "", "k8s.podName", "k8s.podname", "pod", "podName")
	return ns != "" && pod != ""
}

func extractPacketFields(source datasource.DataSource, data datasource.Data) map[string]string {
	fields := make(map[string]string)
	for _, accessor := range source.Accessors(false) {
		value, ok := fieldStringValue(accessor, data)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		fields[accessor.FullName()] = value
	}
	return fields
}

func fieldStringValue(accessor datasource.FieldAccessor, data datasource.Data) (string, bool) {
	switch accessor.Type() {
	case api.Kind_Bool:
		value, err := accessor.Bool(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatBool(value), true
	case api.Kind_Int8:
		value, err := accessor.Int8(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatInt(int64(value), 10), true
	case api.Kind_Int16:
		value, err := accessor.Int16(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatInt(int64(value), 10), true
	case api.Kind_Int32:
		value, err := accessor.Int32(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatInt(int64(value), 10), true
	case api.Kind_Int64:
		value, err := accessor.Int64(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatInt(value, 10), true
	case api.Kind_Uint8:
		value, err := accessor.Uint8(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatUint(uint64(value), 10), true
	case api.Kind_Uint16:
		value, err := accessor.Uint16(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatUint(uint64(value), 10), true
	case api.Kind_Uint32:
		value, err := accessor.Uint32(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatUint(uint64(value), 10), true
	case api.Kind_Uint64:
		value, err := accessor.Uint64(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatUint(value, 10), true
	case api.Kind_Float32:
		value, err := accessor.Float32(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatFloat(float64(value), 'f', -1, 32), true
	case api.Kind_Float64:
		value, err := accessor.Float64(data)
		if err != nil {
			return "", false
		}
		return strconv.FormatFloat(value, 'f', -1, 64), true
	case api.Kind_String, api.Kind_CString:
		value, err := accessor.String(data)
		if err != nil {
			return "", false
		}
		return value, true
	case api.Kind_Bytes:
		value, err := accessor.Bytes(data)
		if err != nil {
			return "", false
		}
		return string(value), true
	default:
		return "", false
	}
}
