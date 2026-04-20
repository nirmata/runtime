package pipeline

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

// Manager orchestrates the evaluation pipeline for a pod against a set of policies.
type Manager struct {
	matcher   Matcher
	collector Collector
	evaluator Evaluator
	reporter  Reporter
}

// NewManager creates a new pipeline manager with the given components.
func NewManager(matcher Matcher, collector Collector, evaluator Evaluator, reporter Reporter) *Manager {
	return &Manager{
		matcher:   matcher,
		collector: collector,
		evaluator: evaluator,
		reporter:  reporter,
	}
}

// ProcessPod evaluates all matching policies for a pod and writes reports.
func (m *Manager) ProcessPod(ctx context.Context, pod *corev1.Pod, policies []v1alpha1.RuntimePolicy, nsLabels map[string]string) error {
	logger := log.FromContext(ctx)
	logger.V(1).Info("processing pod", "pod", pod.Name, "namespace", pod.Namespace, "policies", len(policies))

	for i := range policies {
		p := &policies[i]

		// Check if policy matches this pod
		match, err := m.matcher.Matches(p, pod, nsLabels)
		if err != nil {
			logger.Error(err, "policy matching failed", "policy", p.Name)
			return err
		}
		if !match {
			logger.V(2).Info("policy did not match pod", "policy", p.Name, "pod", pod.Name, "namespace", pod.Namespace)
			continue
		}

		logger.V(1).Info("policy matched pod", "policy", p.Name, "pod", pod.Name, "namespace", pod.Namespace)

		// Collect events for this policy
		eventTypes := eventTypesForPolicy(p)
		if len(eventTypes) == 0 {
			logger.V(2).Info("policy has no event types", "policy", p.Name)
			continue // No event types to collect
		}
		logger.V(2).Info("collecting events", "policy", p.Name, "eventTypes", eventTypes)

		events, err := m.collector.Collect(ctx, CollectorRequest{
			Pod:        pod,
			EventTypes: eventTypes,
			Parameters: p.Spec.Monitor.Parameters,
		})
		if err != nil {
			logger.Error(err, "event collection failed", "policy", p.Name)
			return err
		}

		logger.V(1).Info("events collected", "policy", p.Name, "count", len(events))

		// Evaluate policy against collected events
		result := m.evaluator.Evaluate(p, events)
		logger.V(1).Info("policy evaluated", "policy", p.Name, "findings", len(result.Findings))

		// Write report
		if err := m.reporter.Report(ctx, ReportRequest{
			Pod:      pod,
			Policy:   p,
			Findings: result.Findings,
		}); err != nil {
			logger.Error(err, "report write failed", "policy", p.Name)
			return err
		}
	}
	logger.V(1).Info("pod processing completed", "pod", pod.Name, "namespace", pod.Namespace)

	return nil
}

// eventTypesForPolicy extracts the set of unique event types from a policy.
func eventTypesForPolicy(policy *v1alpha1.RuntimePolicy) []string {
	eventTypes := make(map[string]bool)
	for _, val := range policy.Spec.Validations {
		if val.Event != "" {
			eventTypes[val.Event] = true
		}
	}
	result := make([]string, 0, len(eventTypes))
	for et := range eventTypes {
		result = append(result, et)
	}
	return result
}
