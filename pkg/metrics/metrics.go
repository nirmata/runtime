// Package metrics defines the Prometheus collectors shared across
// kyverno-runtime's collector, attribution, monitor, and reporter packages,
// plus a small HTTP server helper to expose them.
package metrics

import (
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "nirmata_runtime"

// Metrics holds every Prometheus collector registered by kyverno-runtime.
type Metrics struct {
	// EventsIngested counts runtime events ingested by the collector,
	// labeled by source and kind.
	EventsIngested *prometheus.CounterVec
	// EventsDropped counts events dropped by the collector, labeled by
	// source and reason.
	EventsDropped *prometheus.CounterVec
	// SourceAvailable reports whether a source has announced readiness.
	SourceAvailable *prometheus.GaugeVec
	// SourceFailures counts source lifecycle failures by stable reason.
	SourceFailures *prometheus.CounterVec
	// AttributionMisses counts events that could not be attributed to a
	// pod (see pkg/attribution.Index.Annotate).
	AttributionMisses prometheus.Counter
	// MonitorFilterEvalErrors counts monitorFilter expressions that failed to
	// evaluate, labeled by policy and expression name. A failure reports the
	// finding anyway, so this counts filters that are not narrowing.
	MonitorFilterEvalErrors *prometheus.CounterVec
	// FindingsEmitted counts findings emitted to the reporter, labeled by
	// policy and behavior.
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
			Help:      "Total number of runtime events dropped, by source and reason.",
		}, []string{"source", "reason"}),

		SourceAvailable: f.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "source_available",
			Help:      "Whether a runtime event source is available (1) or unavailable (0).",
		}, []string{"source"}),

		SourceFailures: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "source_failures_total",
			Help:      "Total runtime event source failures, by source and reason.",
		}, []string{"source", "reason"}),

		AttributionMisses: f.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "attribution_misses_total",
			Help:      "Total number of events that could not be attributed to a pod.",
		}),

		MonitorFilterEvalErrors: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "monitor_filter_eval_errors_total",
			Help:      "Total number of monitorFilter expression evaluation failures, by policy and expression name. The finding is reported anyway.",
		}, []string{"policy", "expression"}),

		FindingsEmitted: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "findings_emitted_total",
			Help:      "Total number of findings emitted, by policy and behavior.",
		}, []string{"policy", "behavior"}),

		ReportWrites: f.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "report_writes_total",
			Help:      "Total number of OpenReports write attempts, by result (ok|error|skipped).",
		}, []string{"result"}),
	}
}

// RecordSourceStatus updates the source lifecycle metrics. It accepts the
// source status seam directly so all production lifecycle writes share one
// path.
func (m *Metrics) RecordSourceStatus(source string, state runtimeevent.SourceState, reason string) {
	if state == runtimeevent.SourceStateAvailable {
		m.SourceAvailable.WithLabelValues(source).Set(1)
	} else {
		m.SourceAvailable.WithLabelValues(source).Set(0)
	}
	if state == runtimeevent.SourceStateUnavailable {
		m.SourceFailures.WithLabelValues(source, reason).Inc()
	}
}
