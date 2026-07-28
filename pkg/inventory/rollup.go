// Package inventory turns classified AI events into the discover-mode rollup
// that answers "what AI is my cluster using".
//
// A Rollup is the per-node, in-memory aggregate: one entry per workload (owner
// object, or the bare pod), with deduplicated class/provider/model/endpoint-kind
// /transport sets, first and last seen timestamps and event counts. A Syncer
// (syncer.go) periodically publishes that aggregate as this node's shard of the
// cluster-scoped AIInventory singleton.
//
// Discover mode deliberately emits no per-event findings — on a large cluster
// that would be tens of thousands of Reports — so the inventory is the only
// place discovery is visible. That makes the collector's drop count part of the
// payload rather than a footnote: a node whose ring buffers are overflowing
// reports DroppedEvents > 0 in its own shard, because silence must never be
// readable as safety (proposal §2.9).
package inventory

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Bounds on what a single workload entry may contribute to the AIInventory
// object. Model names (and, for self-hosted endpoints, endpoint kinds) are
// derived from request bodies, so they are attacker-influenced: without a cap a
// pod looping over random model names would grow the singleton until the API
// server rejects it, taking every other node's shard down with it.
const (
	// maxSetEntries is the per-field cap on distinct values kept per workload.
	maxSetEntries = 64
	// maxValueLen bounds a single value's length in bytes.
	maxValueLen = 128
)

// kindBarePod is the Kind reported for a pod with no owner reference.
const kindBarePod = "Pod"

// WorkloadKey identifies the workload an observation is attributed to: the
// pod's owner (Deployment, StatefulSet, ...) or the bare pod itself.
type WorkloadKey struct {
	Namespace string
	Kind      string
	Name      string
}

// acc is the mutable accumulator behind one WorkloadKey.
type acc struct {
	classes       *stringSet
	providers     *stringSet
	models        *stringSet
	endpointKinds *stringSet
	transports    *stringSet

	eventCount      int64
	ungovernedCount int64

	firstSeen time.Time
	lastSeen  time.Time
}

func newAcc() *acc {
	return &acc{
		classes:       newStringSet(),
		providers:     newStringSet(),
		models:        newStringSet(),
		endpointKinds: newStringSet(),
		transports:    newStringSet(),
	}
}

// Rollup aggregates classified events per workload. It is safe for concurrent
// use: Record runs on the collector's sink goroutine while Snapshot runs on the
// Syncer's.
type Rollup struct {
	log   logr.Logger
	clock func() time.Time
	// dropped reports the collector's cumulative drop count; nil means the
	// rollup has no visibility into drops and reports 0.
	dropped func() int64

	mu         sync.Mutex
	byWorkload map[WorkloadKey]*acc
	// truncated records the fields that hit maxSetEntries, so the V(0) log
	// happens once per (workload, field) instead of once per event.
	truncated map[string]struct{}
}

// Option customizes a Rollup.
type Option func(*Rollup)

// WithClock replaces the time source used for events that carry no timestamp.
// Tests inject a fake clock; nil is ignored.
func WithClock(fn func() time.Time) Option {
	return func(r *Rollup) {
		if fn != nil {
			r.clock = fn
		}
	}
}

// WithDroppedCounter wires the collector's drop count into every node shard
// this rollup produces (pass collector.Collector.Dropped). nil is ignored.
func WithDroppedCounter(fn func() int64) Option {
	return func(r *Rollup) {
		if fn != nil {
			r.dropped = fn
		}
	}
}

// New builds an empty Rollup.
func New(log logr.Logger, opts ...Option) *Rollup {
	r := &Rollup{
		log:        log.WithName("inventory"),
		clock:      time.Now,
		byWorkload: make(map[WorkloadKey]*acc),
		truncated:  make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// keyFor derives the workload identity of an event. It reports false when the
// event carries no usable attribution, which cannot be rolled up into an
// inventory addressed by namespace/kind/name.
func keyFor(ev *runtimeevent.Event) (WorkloadKey, bool) {
	if ev.Pod.Namespace == "" {
		return WorkloadKey{}, false
	}
	kind, name := ev.Pod.OwnerKind, ev.Pod.OwnerName
	if kind == "" || name == "" {
		kind, name = kindBarePod, ev.Pod.Name
	}
	if name == "" {
		return WorkloadKey{}, false
	}
	return WorkloadKey{Namespace: ev.Pod.Namespace, Kind: kind, Name: name}, true
}

// Record folds one classified event into the rollup. Events with no AI facts
// (not AI traffic, or not classified) and events with no pod attribution are
// ignored: the collector already counts the latter as an attribution miss.
//
// Record implements the inventory sink consumed by pkg/detect (discover mode).
func (r *Rollup) Record(ev runtimeevent.Event) {
	if ev.AI == nil {
		return
	}
	key, ok := keyFor(&ev)
	if !ok {
		r.log.V(4).Info("dropping an unattributed AI event from the inventory",
			"kind", string(ev.Kind), "class", string(ev.AI.Class))
		return
	}

	// A poll-sourced event stands for Count kernel occurrences.
	count := int64(ev.Count)
	if count < 1 {
		count = 1
	}

	when := ev.Time
	if when.IsZero() {
		when = r.clock()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	a, ok := r.byWorkload[key]
	if !ok {
		a = newAcc()
		r.byWorkload[key] = a
		a.firstSeen = when
		a.lastSeen = when
	}

	r.addLocked(key, "classes", a.classes, string(ev.AI.Class))
	r.addLocked(key, "providers", a.providers, ev.AI.Provider)
	r.addLocked(key, "models", a.models, ev.AI.Model)
	r.addLocked(key, "endpointKinds", a.endpointKinds, ev.AI.EndpointKind)
	r.addLocked(key, "transports", a.transports, ev.AI.Transport)

	a.eventCount += count
	if ev.Net != nil && ev.Net.Governed != nil && !*ev.Net.Governed {
		// Governed == nil means "unknown" (resolver disabled or a kind with no
		// destination); only a definite false is a proxy bypass.
		a.ungovernedCount += count
	}

	if when.Before(a.firstSeen) {
		a.firstSeen = when
	}
	if when.After(a.lastSeen) {
		a.lastSeen = when
	}
}

// addLocked inserts a value into one of a workload's sets, enforcing the size
// and length bounds. Hitting the cap is an operator-visible event, logged once
// per workload and field. Callers hold r.mu.
func (r *Rollup) addLocked(key WorkloadKey, field string, set *stringSet, value string) {
	if value == "" {
		return
	}
	if len(value) > maxValueLen {
		value = value[:maxValueLen]
	}
	if set.has(value) {
		return
	}
	if set.len() >= maxSetEntries {
		tk := key.Namespace + "/" + key.Kind + "/" + key.Name + "#" + field
		if _, seen := r.truncated[tk]; !seen {
			r.truncated[tk] = struct{}{}
			r.log.V(0).Info("AI inventory field is truncated: too many distinct values",
				"namespace", key.Namespace, "kind", key.Kind, "name", key.Name,
				"field", field, "cap", maxSetEntries)
		}
		return
	}
	set.add(value)
}

// Dropped reports the collector's cumulative drop count, or 0 when no counter
// was wired.
func (r *Rollup) Dropped() int64 {
	if r.dropped == nil {
		return 0
	}
	return r.dropped()
}

// Snapshot returns the per-workload inventory, sorted by namespace, then kind,
// then name, with every value list sorted and deduplicated. The result is a
// deep copy: callers may retain and mutate it while Record keeps running, and
// two snapshots of the same observations are byte-identical.
//
// Timestamps are normalized to whole UTC seconds, which is the precision
// metav1.Time survives a JSON round trip with. Without that, every sync would
// look like a change and every node would rewrite the singleton on every tick.
func (r *Rollup) Snapshot() []v1alpha1.AIWorkloadInventory {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]v1alpha1.AIWorkloadInventory, 0, len(r.byWorkload))
	for key, a := range r.byWorkload {
		out = append(out, v1alpha1.AIWorkloadInventory{
			Namespace:       key.Namespace,
			Kind:            key.Kind,
			Name:            key.Name,
			Classes:         a.classes.sorted(),
			Providers:       a.providers.sorted(),
			EndpointKinds:   a.endpointKinds.sorted(),
			Models:          a.models.sorted(),
			Transports:      a.transports.sorted(),
			EventCount:      a.eventCount,
			UngovernedCount: a.ungovernedCount,
			FirstSeen:       apiTime(a.firstSeen),
			LastSeen:        apiTime(a.lastSeen),
		})
	}
	sort.Slice(out, func(i, j int) bool { return lessWorkload(out[i], out[j]) })
	return out
}

// Providers returns the deduplicated, sorted provider names this node has
// observed. It exists so callers do not have to walk a Snapshot to answer the
// headline question.
func (r *Rollup) Providers() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := newStringSet()
	for _, a := range r.byWorkload {
		for _, p := range a.providers.sorted() {
			seen.add(p)
		}
	}
	return seen.sorted()
}

// lessWorkload is the total order used for every workload list in this package
// (node shards and the summary), so the API object never churns on ordering.
func lessWorkload(a, b v1alpha1.AIWorkloadInventory) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Name < b.Name
}

// apiTime normalizes a timestamp to the precision the API round-trips.
func apiTime(t time.Time) metav1.Time {
	if t.IsZero() {
		return metav1.Time{}
	}
	return metav1.NewTime(t.UTC().Truncate(time.Second))
}

// stringSet is an insertion-tracked set with a sorted, copied read-out.
type stringSet struct {
	m map[string]struct{}
}

func newStringSet() *stringSet { return &stringSet{m: make(map[string]struct{})} }

func (s *stringSet) add(v string)      { s.m[v] = struct{}{} }
func (s *stringSet) len() int          { return len(s.m) }
func (s *stringSet) has(v string) bool { _, ok := s.m[v]; return ok }

// sorted returns nil (not an empty slice) for an empty set: the API fields are
// omitempty, and nil keeps encoded output and cmp.Diff results stable.
func (s *stringSet) sorted() []string {
	if len(s.m) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.m))
	for v := range s.m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// joinProviders renders a provider set as the summary's comma-separated string.
func joinProviders(set *stringSet) string {
	return strings.Join(set.sorted(), ",")
}
