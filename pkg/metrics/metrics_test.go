package metrics

import (
	"testing"

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
	// plain counter, then confirm the registry gathers all five.
	m.EventsIngested.WithLabelValues("s", "k").Inc()
	m.EventsDropped.WithLabelValues("s", "buffer_full").Inc()
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
