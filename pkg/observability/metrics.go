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
)

func init() {
	registerMetricsOnce.Do(func() {
		metrics.Registry.MustRegister(
			datasourceDroppedNoMetadata,
			reporterResultsTruncated,
			reporterUpdatesSkipped,
			reporterWrites,
		)
	})
}

func IncDatasourceDroppedNoMetadata(eventType string) {
	datasourceDroppedNoMetadata.WithLabelValues(normalizeLabel(eventType)).Inc()
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

func normalizeLabel(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "unknown"
	}
	return v
}
