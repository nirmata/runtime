package metrics

import (
	"testing"

	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNew_CountersIncrement(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	cases := []struct {
		name string
		inc  func()
		coll prometheus.Collector
	}{
		{
			name: "EventsIngested",
			inc:  func() { m.EventsIngested.WithLabelValues("egress-observe", "net").Inc() },
			coll: m.EventsIngested,
		},
		{
			name: "EventsDropped",
			inc:  func() { m.EventsDropped.WithLabelValues("lsm-observe", "buffer_full").Inc() },
			coll: m.EventsDropped,
		},
		{
			name: "SourceAvailable",
			inc: func() {
				m.RecordSourceStatus("dnsquery", runtimeevent.SourceStateAvailable, runtimeevent.SourceReasonReady)
			},
			coll: m.SourceAvailable,
		},
		{
			name: "SourceFailures",
			inc: func() {
				m.RecordSourceStatus("dnsquery", runtimeevent.SourceStateUnavailable, runtimeevent.SourceReasonReaderFailed)
			},
			coll: m.SourceFailures,
		},
		{
			name: "FindingsEmitted",
			inc:  func() { m.FindingsEmitted.WithLabelValues("deny-egress", "network").Inc() },
			coll: m.FindingsEmitted,
		},
		{
			name: "ReportWrites",
			inc:  func() { m.ReportWrites.WithLabelValues("ok").Inc() },
			coll: m.ReportWrites,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := testutil.CollectAndCount(tc.coll)
			tc.inc()
			after := testutil.CollectAndCount(tc.coll)
			if after != before+1 {
				t.Errorf("%s: CollectAndCount = %d before, %d after Inc; want +1", tc.name, before, after)
			}
		})
	}
}

func TestNew_AttributionMissesIsPlainCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	if got := testutil.ToFloat64(m.AttributionMisses); got != 0 {
		t.Fatalf("AttributionMisses initial value = %v, want 0", got)
	}

	m.AttributionMisses.Inc()
	m.AttributionMisses.Inc()

	if got := testutil.ToFloat64(m.AttributionMisses); got != 2 {
		t.Fatalf("AttributionMisses after 2 Inc = %v, want 2", got)
	}
}

func TestNew_MetricsAreRegisteredAgainstProvidedRegisterer(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	// Nothing registered yet reports zero families with data until a
	// label combination is observed; force one on every vec plus the
	// plain counter, then confirm the registry gathers every family.
	m.EventsIngested.WithLabelValues("s", "k").Inc()
	m.EventsDropped.WithLabelValues("s", "buffer_full").Inc()
	m.RecordSourceStatus("s", runtimeevent.SourceStateStarting, runtimeevent.SourceReasonStarting)
	m.RecordSourceStatus("s", runtimeevent.SourceStateUnavailable, runtimeevent.SourceReasonReaderFailed)
	m.AttributionMisses.Inc()
	m.FindingsEmitted.WithLabelValues("p", "network").Inc()
	m.ReportWrites.WithLabelValues("ok").Inc()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	want := map[string]bool{
		namespace + "_events_ingested_total":    false,
		namespace + "_events_dropped_total":     false,
		namespace + "_source_available":         false,
		namespace + "_source_failures_total":    false,
		namespace + "_attribution_misses_total": false,
		namespace + "_findings_emitted_total":   false,
		namespace + "_report_writes_total":      false,
	}
	for _, mf := range mfs {
		if _, ok := want[mf.GetName()]; ok {
			want[mf.GetName()] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("expected metric family %q to be registered on reg, not found", name)
		}
	}
}

func TestRecordSourceStatusTracksAvailabilityAndFailures(t *testing.T) {
	m := New(prometheus.NewRegistry())

	m.RecordSourceStatus("exec-trace", runtimeevent.SourceStateStarting, runtimeevent.SourceReasonStarting)
	if got := testutil.ToFloat64(m.SourceAvailable.WithLabelValues("exec-trace")); got != 0 {
		t.Fatalf("SourceAvailable while starting = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.SourceFailures.WithLabelValues("exec-trace", runtimeevent.SourceReasonStarting)); got != 0 {
		t.Fatalf("SourceFailures while starting = %v, want 0", got)
	}

	m.RecordSourceStatus("exec-trace", runtimeevent.SourceStateAvailable, runtimeevent.SourceReasonReady)
	m.RecordSourceStatus("exec-trace", runtimeevent.SourceStateUnavailable, runtimeevent.SourceReasonReaderFailed)
	if got := testutil.ToFloat64(m.SourceAvailable.WithLabelValues("exec-trace")); got != 0 {
		t.Errorf("SourceAvailable after failure = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.SourceFailures.WithLabelValues("exec-trace", runtimeevent.SourceReasonReaderFailed)); got != 1 {
		t.Errorf("SourceFailures after failure = %v, want 1", got)
	}
}
