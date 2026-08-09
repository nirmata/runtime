package monitor

import (
	"context"
	"fmt"
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/reporter"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// countingSink keeps no findings: fakeSink appends every one, which over a
// benchmark's iteration count measures slice growth rather than the event path.
type countingSink struct{ n int }

func (c *countingSink) Report(reporter.Finding) { c.n++ }

func benchMonitor() (*Monitor, *countingSink) {
	sink := &countingSink{}
	return New(logr.Discard(), sink, metrics.New(prometheus.NewRegistry())), sink
}

func benchPodTarget() compiler.PodTarget {
	s, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"app": "ai"}})
	if err != nil {
		panic(err)
	}
	return compiler.PodTarget{Pod: s, Namespace: labels.Everything()}
}

// benchPolicy is a monitor-mode policy that selects the benchmark pod and denies
// every open, so every policy in the loop reaches the reporting path.
func benchPolicy(i int) *compiler.EvaluationResult {
	return &compiler.EvaluationResult{
		UID:       fmt.Sprintf("uid-%d", i),
		Name:      fmt.Sprintf("p-%d", i),
		Open:      denyEverything(),
		AppliesTo: benchPodTarget(),
		Mode:      compiler.ModeMonitor,
	}
}

// benchFilters compiles n independent single-expression monitorFilters through
// the real compiler, so each policy carries its own cel.Program the way a
// cluster's policies do.
func benchFilters(b *testing.B, n int) []*compiler.MonitorFilter {
	b.Helper()
	c, err := compiler.NewCompiler(dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()), noServices{})
	if err != nil {
		b.Fatalf("NewCompiler: %v", err)
	}
	mode := v1alpha1.PolicyModeMonitor
	out := make([]*compiler.MonitorFilter, 0, n)
	for range n {
		compiled, err := c.Compile(v1alpha1.RuntimePolicy{Spec: v1alpha1.RuntimePolicySpec{
			Mode: &mode,
			MonitorFilter: &v1alpha1.MonitorFilter{Expressions: []v1alpha1.MonitorFilterExpression{
				cond("open-only", `has(event.open)`),
			}},
		}})
		if err != nil {
			b.Fatalf("Compile: %v", err)
		}
		res, err := compiled.Evaluate(context.Background())
		if err != nil {
			b.Fatalf("Evaluate: %v", err)
		}
		if res.MonitorFilter == nil {
			b.Fatal("Evaluate produced no monitor filter")
		}
		out = append(out, res.MonitorFilter)
	}
	return out
}

// One event fans out to every tracked policy, so the per-event cost that does
// not scale with the policy count has to stay off the loop.
func BenchmarkHandleEventPolicyScaling(b *testing.B) {
	for _, policies := range []int{1, 8, 64, 256} {
		b.Run(fmt.Sprintf("policies=%d", policies), func(b *testing.B) {
			m, sink := benchMonitor()
			for i := range policies {
				if err := m.RuntimePolicyEvent(benchPolicy(i), events.EventTypeCreate); err != nil {
					b.Fatalf("RuntimePolicyEvent: %v", err)
				}
			}
			if got := m.Len(); got != policies {
				b.Fatalf("tracked %d policies, want %d", got, policies)
			}
			ev := openEvent("/etc/shadow")

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				m.HandleEvent(ev)
			}
			b.StopTimer()

			if want := policies * b.N; sink.n != want {
				b.Fatalf("findings = %d, want %d (every policy must reach the sink)", sink.n, want)
			}
		})
	}
}

// The activation depends on the event alone, so a filtered fan-out builds it
// once per event rather than once per policy.
func BenchmarkHandleEventMonitorFilterActivation(b *testing.B) {
	const policies = 64
	m, sink := benchMonitor()
	filters := benchFilters(b, policies)
	for i := range policies {
		rp := benchPolicy(i)
		rp.MonitorFilter = filters[i]
		if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
			b.Fatalf("RuntimePolicyEvent: %v", err)
		}
	}
	ev := openEvent("/etc/shadow")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		m.HandleEvent(ev)
	}
	b.StopTimer()

	if want := policies * b.N; sink.n != want {
		b.Fatalf("findings = %d, want %d (every filter must pass)", sink.n, want)
	}
}
