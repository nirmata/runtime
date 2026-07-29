// Package metrics defines the Prometheus collectors shared across
// kyverno-runtime's collector, attribution, monitor, and reporter packages,
// plus a small HTTP server helper to expose them.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "kyverno_runtime"

// Metrics holds every Prometheus collector registered by kyverno-runtime.
type Metrics struct {
	// EventsIngested counts runtime events ingested by the collector,
	// labeled by source and kind.
	EventsIngested *prometheus.CounterVec
	// EventsDropped counts events dropped by the collector, labeled by
	// source and reason (buffer_full|unattributed|rate_limited).
	EventsDropped *prometheus.CounterVec
	// AttributionMisses counts events that could not be attributed to a
	// pod (see pkg/attribution.Index.Annotate).
	AttributionMisses prometheus.Counter
	// FindingsEmitted counts findings emitted to the reporter, labeled by
	// policy, behavior, and severity.
	FindingsEmitted *prometheus.CounterVec
	// ReportWrites counts OpenReports write attempts, labeled by result
	// (ok|error|skipped).
	ReportWrites *prometheus.CounterVec
}

// New creates and registers all collectors against reg. Passing a fresh
// *prometheus.Registry (rather than the global DefaultRegisterer) keeps
// tests and repeated daemon.go wiring free of "duplicate metrics
// collector registration" panics.
func New(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)

	return &Metrics{
		EventsIngested: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "events_ingested_total",
			Help:      "Total number of runtime events ingested, by source and kind.",
		}, []string{"source", "kind"}),

		EventsDropped: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "events_dropped_total",
			Help:      "Total number of runtime events dropped, by source and reason (buffer_full|unattributed|rate_limited).",
		}, []string{"source", "reason"}),

		AttributionMisses: f.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "attribution_misses_total",
			Help:      "Total number of events that could not be attributed to a pod.",
		}),

		FindingsEmitted: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "findings_emitted_total",
			Help:      "Total number of findings emitted, by policy, behavior, and severity.",
		}, []string{"policy", "behavior", "severity"}),

		ReportWrites: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "report_writes_total",
			Help:      "Total number of OpenReports write attempts, by result (ok|error|skipped).",
		}, []string{"result"}),
	}
}
