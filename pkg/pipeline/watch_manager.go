package pipeline

import (
	"context"
	"sort"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// podWatchKey uniquely identifies a streaming watch for a pod and a set of event types.
type podWatchKey struct {
	namespace  string
	name       string
	eventTypes string // sorted, comma-joined
}

type podWatch struct {
	cancel context.CancelFunc
}

// WatchManager maintains long-running eBPF streaming watches for pods that
// match one or more RuntimePolicies. It starts a watch when a pod is first
// seen to match and cancels it when the pod or its matching policies are gone.
type WatchManager struct {
	source    datasource.StreamingSource
	evaluator Evaluator
	reporter  Reporter

	mu      sync.Mutex
	watches map[podWatchKey]*podWatch
}

// NewWatchManager creates a WatchManager backed by the given streaming source.
func NewWatchManager(source datasource.StreamingSource, evaluator Evaluator, reporter Reporter) *WatchManager {
	return &WatchManager{
		source:    source,
		evaluator: evaluator,
		reporter:  reporter,
		watches:   make(map[podWatchKey]*podWatch),
	}
}

// Sync ensures the right streaming watches are running for pod given the
// supplied set of matching policies. It starts watches that are missing and
// stops watches that are no longer needed.
func (w *WatchManager) Sync(ctx context.Context, pod *corev1.Pod, policies []*v1alpha1.RuntimePolicy) {
	logger := log.FromContext(ctx).WithName("watch-manager")

	// Build the desired set of (pod, eventTypes) watches from matched policies.
	// Group all event types across all matching policies so we run one watch per
	// unique set of event types.
	eventTypeSet := make(map[string]struct{})
	policyMap := make(map[string]*v1alpha1.RuntimePolicy, len(policies))
	for _, p := range policies {
		policyMap[p.Name] = p
		for _, et := range eventTypesForPolicy(p) {
			eventTypeSet[et] = struct{}{}
		}
	}

	if len(eventTypeSet) == 0 {
		// No matching policies — stop any existing watch.
		w.StopPod(pod)
		return
	}

	eventTypes := make([]string, 0, len(eventTypeSet))
	for et := range eventTypeSet {
		eventTypes = append(eventTypes, et)
	}
	sort.Strings(eventTypes)

	key := podWatchKey{
		namespace:  pod.Namespace,
		name:       pod.Name,
		eventTypes: strings.Join(eventTypes, ","),
	}

	w.mu.Lock()
	_, exists := w.watches[key]
	w.mu.Unlock()

	if exists {
		logger.V(2).Info("watch already running", "pod", pod.Name, "namespace", pod.Namespace)
		return
	}

	// Stop any previous watch with a different event-type set for this pod.
	w.StopPod(pod)

	// Reconcile request contexts are short-lived and cancelled when Reconcile
	// returns. Streaming watches must outlive a single reconcile call, so use
	// a dedicated background context and stop explicitly via StopPod/StopAll.
	watchCtx, cancel := context.WithCancel(context.Background())

	w.mu.Lock()
	w.watches[key] = &podWatch{cancel: cancel}
	w.mu.Unlock()

	logger.Info("starting streaming watch", "pod", pod.Name, "namespace", pod.Namespace, "eventTypes", eventTypes)

	// Capture values for the goroutine.
	podCopy := pod.DeepCopy()
	policiesCopy := make([]*v1alpha1.RuntimePolicy, len(policies))
	copy(policiesCopy, policies)

	go func() {
		defer func() {
			w.mu.Lock()
			delete(w.watches, key)
			w.mu.Unlock()
			logger.Info("streaming watch stopped", "pod", podCopy.Name, "namespace", podCopy.Namespace)
		}()

		err := w.source.StreamEventsForPod(watchCtx, podCopy, datasource.QueryOptions{EventTypes: eventTypes}, func(event runtimeevents.Event) {
			// Evaluate each matching policy immediately on every event.
			for _, p := range policiesCopy {
				result := w.evaluator.Evaluate(p, []runtimeevents.Event{event})
				if len(result.Findings) == 0 {
					continue
				}
				if repErr := w.reporter.Report(watchCtx, ReportRequest{
					Pod:      podCopy,
					Policy:   p,
					Findings: result.Findings,
				}); repErr != nil {
					logger.Error(repErr, "failed to write report", "pod", podCopy.Name, "namespace", podCopy.Namespace, "policy", p.Name)
				}
			}
		})
		if err != nil && watchCtx.Err() == nil {
			logger.Error(err, "streaming watch error", "pod", podCopy.Name, "namespace", podCopy.Namespace)
		}
	}()
}

// StopAll cancels all active streaming watches.
func (w *WatchManager) StopAll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for key, pw := range w.watches {
		pw.cancel()
		delete(w.watches, key)
	}
}

// StopPod cancels any active watch for the given pod regardless of event types.
func (w *WatchManager) StopPod(pod *corev1.Pod) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for key, pw := range w.watches {
		if key.namespace == pod.Namespace && key.name == pod.Name {
			pw.cancel()
			delete(w.watches, key)
			return
		}
	}
}
