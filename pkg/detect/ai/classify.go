package ai

import (
	"sync/atomic"

	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// StageName is the collector stage name of the classifier.
const StageName = "ai-classifier"

// Classifier turns normalized runtime events into AIFacts.
//
// Classify is a PURE function of (catalog, event): no I/O, no network, no
// clock, no goroutines, and it never mutates the event it inspects. The only
// mutable state is the catalog pointer, swapped atomically by SetCatalog when
// the ai-provider-catalog ConfigMap changes, so a reload is visible to
// in-flight classification without locking.
type Classifier struct {
	cat     atomic.Pointer[Catalog]
	metrics *metrics.Metrics
}

// Option configures a Classifier.
type Option func(*Classifier)

// WithMetrics records classified events in metrics.AIClassified. Counting
// happens in Process (the collector stage), never in Classify, so Classify
// stays side-effect free.
func WithMetrics(m *metrics.Metrics) Option {
	return func(c *Classifier) { c.metrics = m }
}

// NewClassifier returns a classifier over cat. A nil catalog falls back to the
// embedded default rather than disabling detection silently.
func NewClassifier(cat *Catalog, opts ...Option) *Classifier {
	c := &Classifier{}
	if cat == nil {
		cat = DefaultCatalog()
	}
	c.cat.Store(cat)
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// SetCatalog swaps the catalog used by subsequent classifications. A nil
// catalog is ignored: a bad ConfigMap must never blind the classifier.
func (c *Classifier) SetCatalog(cat *Catalog) {
	if cat == nil {
		return
	}
	c.cat.Store(cat)
}

// Catalog returns the catalog currently in effect.
func (c *Classifier) Catalog() *Catalog { return c.cat.Load() }

// classifiers are tried in order; the highest-confidence verdict wins and the
// order breaks ties. MCP and A2A come first because they are the more specific
// protocols: an event that satisfies both an MCP signature and a generic LLM
// host match is reported as MCP.
var classifiers = []func(*Catalog, *runtimeevent.Event) *runtimeevent.AIFacts{
	classifyMCP,
	classifyA2A,
	classifyLLM,
}

// Classify returns the AI facts for ev, or nil when ev is not AI traffic.
func (c *Classifier) Classify(ev *runtimeevent.Event) *runtimeevent.AIFacts {
	if ev == nil {
		return nil
	}
	cat := c.cat.Load()
	if cat == nil {
		return nil
	}

	var best *runtimeevent.AIFacts
	for _, fn := range classifiers {
		facts := fn(cat, ev)
		if facts == nil || facts.Confidence <= 0 {
			continue
		}
		if best == nil || facts.Confidence > best.Confidence {
			best = facts
		}
	}
	return best
}

// Name implements the collector stage interface.
func (c *Classifier) Name() string { return StageName }

// Process implements the collector stage interface: it sets ev.AI (which may
// stay nil) and never drops an event. Non-AI traffic still matters to every
// other sink, so filtering here would be a bug.
func (c *Classifier) Process(ev *runtimeevent.Event) bool {
	if ev == nil {
		return true
	}
	ev.AI = c.Classify(ev)
	if ev.AI != nil && c.metrics != nil {
		c.metrics.AIClassified.WithLabelValues(string(ev.AI.Class), ev.AI.Provider).Inc()
	}
	return true
}
