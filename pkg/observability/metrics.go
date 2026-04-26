package observability

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	metrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	registerMetricsOnce sync.Once

	datasourceDroppedNoMetadata = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "datasource",
			Name:      "events_dropped_no_metadata_total",
			Help:      "Number of runtime events dropped due to missing pod metadata.",
		},
		[]string{"event_type"},
	)

	datasourceEventsCollected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "datasource",
			Name:      "events_collected_total",
			Help:      "Number of runtime events collected from datasources.",
		},
		[]string{"event_type"},
	)

	reporterResultsTruncated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "reporter",
			Name:      "results_truncated_total",
			Help:      "Total number of PolicyReport results dropped due to max result limits.",
		},
	)

	reporterUpdatesSkipped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "reporter",
			Name:      "updates_skipped_total",
			Help:      "Number of PolicyReport update operations skipped to reduce API churn.",
		},
		[]string{"reason"},
	)

	reporterWrites = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "reporter",
			Name:      "writes_total",
			Help:      "Number of PolicyReport write operations partitioned by operation and result.",
		},
		[]string{"operation", "result"},
	)

	reporterFindingsSuppressed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "reporter",
			Name:      "findings_suppressed_total",
			Help:      "Number of duplicate findings suppressed by cooldown/burst limits.",
		},
		[]string{"reason"},
	)

	reporterOutputLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "reporter",
			Name:      "output_latency_seconds",
			Help:      "Latency of persisted report writes.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	reporterEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "reporter",
			Name:      "events_total",
			Help:      "Kubernetes runtime events partitioned by result class.",
		},
		[]string{"result"},
	)

	evaluatorLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "evaluator",
			Name:      "latency_seconds",
			Help:      "Latency of policy evaluation paths.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"engine"},
	)

	evaluatorCompileErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "evaluator",
			Name:      "compile_errors_total",
			Help:      "Number of CEL compilation errors encountered during watch activation.",
		},
		[]string{"policy"},
	)

	sinkFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "output",
			Name:      "sink_failures_total",
			Help:      "Number of failed writes to runtime output sinks.",
		},
		[]string{"sink"},
	)

	alertsEmitted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "reporter",
			Name:      "alerts_emitted_total",
			Help:      "Number of runtime findings emitted to persisted reports.",
		},
	)

	baselineCompletionRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "baseline",
			Name:      "completion_ratio",
			Help:      "Completed RuntimeBehavior profiles divided by total profiles in a namespace.",
		},
		[]string{"namespace"},
	)

	baselineObservedOverflow = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "kyverno_runtime",
			Subsystem: "baseline",
			Name:      "observed_overflow_total",
			Help:      "Number of times baseline observed dimensions hit compaction caps.",
		},
		[]string{"dimension"},
	)
)

func init() {
	registerMetricsOnce.Do(func() {
		metrics.Registry.MustRegister(
			datasourceDroppedNoMetadata,
			datasourceEventsCollected,
			reporterResultsTruncated,
			reporterUpdatesSkipped,
			reporterWrites,
			reporterFindingsSuppressed,
			reporterOutputLatency,
			reporterEvents,
			evaluatorLatency,
			evaluatorCompileErrors,
			sinkFailures,
			alertsEmitted,
			baselineCompletionRatio,
			baselineObservedOverflow,
		)
	})
}

func IncDatasourceDroppedNoMetadata(eventType string) {
	datasourceDroppedNoMetadata.WithLabelValues(normalizeLabel(eventType)).Inc()
}

func IncDatasourceEventCollected(eventType string) {
	datasourceEventsCollected.WithLabelValues(normalizeLabel(eventType)).Inc()
}

func AddReporterResultsTruncated(dropped int) {
	if dropped <= 0 {
		return
	}
	reporterResultsTruncated.Add(float64(dropped))
}

func IncReporterUpdateSkipped(reason string) {
	reporterUpdatesSkipped.WithLabelValues(normalizeLabel(reason)).Inc()
}

func IncReporterWrite(operation, result string) {
	reporterWrites.WithLabelValues(normalizeLabel(operation), normalizeLabel(result)).Inc()
}

func AddReporterFindingsSuppressed(reason string, count int) {
	if count <= 0 {
		return
	}
	reporterFindingsSuppressed.WithLabelValues(normalizeLabel(reason)).Add(float64(count))
}

func ObserveReporterOutputLatency(operation string, seconds float64) {
	if seconds < 0 {
		return
	}
	reporterOutputLatency.WithLabelValues(normalizeLabel(operation)).Observe(seconds)
}

func IncReporterEvent(result string) {
	reporterEvents.WithLabelValues(normalizeLabel(result)).Inc()
}

func ObserveEvaluatorLatency(engine string, seconds float64) {
	if seconds < 0 {
		return
	}
	evaluatorLatency.WithLabelValues(normalizeLabel(engine)).Observe(seconds)
}

func IncSinkFailure(sink string) {
	sinkFailures.WithLabelValues(normalizeLabel(sink)).Inc()
}

func IncEvaluatorCompileError(policy string) {
	evaluatorCompileErrors.WithLabelValues(normalizeLabel(policy)).Inc()
}

func AddAlertsEmitted(count int) {
	if count <= 0 {
		return
	}
	alertsEmitted.Add(float64(count))
}

func SetBaselineCompletionRatio(namespace string, ratio float64) {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	baselineCompletionRatio.WithLabelValues(normalizeLabel(namespace)).Set(ratio)
}

func IncBaselineObservedOverflow(dimension string) {
	baselineObservedOverflow.WithLabelValues(normalizeLabel(dimension)).Inc()
}

func normalizeLabel(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "unknown"
	}
	return v
}
