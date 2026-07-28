package inventory

import (
	"context"
	"fmt"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	v1alpha1client "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"

	"github.com/go-logr/logr"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

const (
	// SingletonName is the name of the one cluster-scoped AIInventory object
	// every daemon shares. `kubectl get aiinventory cluster` is the "what AI is
	// my cluster using" answer.
	SingletonName = "cluster"

	// DefaultSyncInterval is the publish cadence used when NewSyncer is given a
	// non-positive interval.
	DefaultSyncInterval = time.Minute

	// finalSyncTimeout bounds the shutdown write, which must not inherit the
	// already-cancelled context.
	finalSyncTimeout = 10 * time.Second
)

// Metrics result labels for metrics.InventorySyncs.
const (
	resultOK      = "ok"
	resultError   = "error"
	resultSkipped = "skipped"
)

// Syncer publishes a Rollup as this node's shard of the AIInventory singleton.
//
// Every daemon in the DaemonSet writes the same cluster-scoped object, so a
// sync re-reads it under RetryOnConflict and replaces ONLY the entry whose
// nodeName matches this node, then recomputes the cluster summary from the full
// (post-replacement) list. No node ever needs to know what the others observed,
// and no always-on control-plane component is needed.
type Syncer struct {
	client   v1alpha1client.Interface
	nodeName string
	rollup   *Rollup
	interval time.Duration
	log      logr.Logger

	// clock and metrics are injectable seams.
	clock   func() time.Time
	metrics *metrics.Metrics
}

// SyncerOption customizes a Syncer.
type SyncerOption func(*Syncer)

// WithSyncerClock replaces the timestamp source for status.nodes[].updatedAt.
// nil is ignored.
func WithSyncerClock(fn func() time.Time) SyncerOption {
	return func(s *Syncer) {
		if fn != nil {
			s.clock = fn
		}
	}
}

// WithMetrics wires metrics.InventorySyncs. nil is ignored.
func WithMetrics(m *metrics.Metrics) SyncerOption {
	return func(s *Syncer) {
		if m != nil {
			s.metrics = m
		}
	}
}

// NewSyncer builds the syncer for this node. A non-positive interval falls back
// to DefaultSyncInterval.
func NewSyncer(client v1alpha1client.Interface, nodeName string, r *Rollup, interval time.Duration, log logr.Logger, opts ...SyncerOption) *Syncer {
	if interval <= 0 {
		interval = DefaultSyncInterval
	}
	s := &Syncer{
		client:   client,
		nodeName: nodeName,
		rollup:   r,
		interval: interval,
		log:      log.WithName("inventory-syncer"),
		clock:    time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Run ensures the singleton exists, then syncs this node's shard every interval
// and once more when ctx is cancelled, so the last observations of a draining
// daemon are not lost.
func (s *Syncer) Run(ctx context.Context) error {
	if err := s.Ensure(ctx); err != nil {
		// A missing object is recoverable: the next Sync creates it. Report it
		// loudly and keep running rather than taking the daemon down.
		s.log.V(0).Info("could not ensure the AIInventory singleton exists; will retry on the next sync",
			"name", SingletonName, "err", err.Error())
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalSyncTimeout)
			defer cancel()
			if err := s.Sync(final); err != nil {
				s.log.Error(err, "final AI inventory sync failed")
			}
			return nil
		case <-ticker.C:
			if err := s.Sync(ctx); err != nil {
				s.log.Error(err, "AI inventory sync failed")
			}
		}
	}
}

// Ensure creates the AIInventory singleton if it does not exist yet. Any node
// may create it; losing the race is success.
func (s *Syncer) Ensure(ctx context.Context) error {
	c := s.client.RuntimeV1alpha1().AIInventories()
	if _, err := c.Get(ctx, SingletonName, metav1.GetOptions{}); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("getting AIInventory %s: %w", SingletonName, err)
	}

	obj := &v1alpha1.AIInventory{ObjectMeta: metav1.ObjectMeta{Name: SingletonName}}
	if _, err := c.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// another daemon got there first
			return nil
		}
		return fmt.Errorf("creating AIInventory %s: %w", SingletonName, err)
	}
	s.log.V(2).Info("created the AIInventory singleton", "name", SingletonName)
	return nil
}

// Sync publishes this node's shard. It is exported so the daemon (and tests)
// can force a publish without waiting for the interval.
func (s *Syncer) Sync(ctx context.Context) error {
	shard := v1alpha1.AINodeInventory{
		NodeName:      s.nodeName,
		UpdatedAt:     apiTime(s.clock()),
		DroppedEvents: s.rollup.Dropped(),
		Workloads:     s.rollup.Snapshot(),
	}

	if err := s.syncShard(ctx, shard); err != nil {
		s.record(resultError)
		return err
	}
	return nil
}

func (s *Syncer) syncShard(ctx context.Context, shard v1alpha1.AINodeInventory) error {
	c := s.client.RuntimeV1alpha1().AIInventories()

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cur, err := c.Get(ctx, SingletonName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			// First writer in the cluster, or the object was deleted between
			// Ensure and now.
			if err := s.Ensure(ctx); err != nil {
				return err
			}
			cur, err = c.Get(ctx, SingletonName, metav1.GetOptions{})
		}
		if err != nil {
			return fmt.Errorf("getting AIInventory %s: %w", SingletonName, err)
		}

		// Two independent copies: setNodeShard mutates the Nodes slice in
		// place, so a struct copy of the status would be mutated with it and
		// the no-op check below would always report "changed".
		baseline, okBase := cur.DeepCopyObject().(*v1alpha1.AIInventory)
		updated, okUpd := cur.DeepCopyObject().(*v1alpha1.AIInventory)
		if !okBase || !okUpd {
			return fmt.Errorf("deep copy of AIInventory %s returned an unexpected type", SingletonName)
		}

		setNodeShard(&updated.Status, shard)
		recomputeSummary(&updated.Status)

		if apiequality.Semantic.DeepEqual(baseline.Status, updated.Status) {
			// Nothing new since the last tick; every daemon skipping the write
			// is what keeps a 500-node DaemonSet off the API server's back.
			s.record(resultSkipped)
			return nil
		}

		if _, err := c.UpdateStatus(ctx, updated, metav1.UpdateOptions{}); err != nil {
			// Conflicts are returned unwrapped: RetryOnConflict must be able to
			// recognize them.
			if apierrors.IsConflict(err) {
				return err
			}
			return fmt.Errorf("updating AIInventory %s status: %w", SingletonName, err)
		}
		s.record(resultOK)
		s.log.V(2).Info("published this node's AI inventory shard",
			"node", s.nodeName, "workloads", len(shard.Workloads), "droppedEvents", shard.DroppedEvents)
		return nil
	})
}

func (s *Syncer) record(result string) {
	if s.metrics == nil || s.metrics.InventorySyncs == nil {
		return
	}
	s.metrics.InventorySyncs.WithLabelValues(result).Inc()
}

// setNodeShard replaces this node's entry in status.nodes and leaves every other
// node's entry untouched. Entries stay sorted by node name so concurrent
// writers do not reorder the list.
func setNodeShard(status *v1alpha1.AIInventoryStatus, shard v1alpha1.AINodeInventory) {
	for i := range status.Nodes {
		if status.Nodes[i].NodeName == shard.NodeName {
			status.Nodes[i] = shard
			return
		}
	}
	idx := len(status.Nodes)
	for i := range status.Nodes {
		if status.Nodes[i].NodeName > shard.NodeName {
			idx = i
			break
		}
	}
	status.Nodes = append(status.Nodes, v1alpha1.AINodeInventory{})
	copy(status.Nodes[idx+1:], status.Nodes[idx:])
	status.Nodes[idx] = shard
}

// recomputeSummary derives the cluster-wide rollup from every node shard.
// Workloads are deduplicated across nodes: a Deployment with pods on ten nodes
// is one workload, not ten.
func recomputeSummary(status *v1alpha1.AIInventoryStatus) {
	workloads := make(map[WorkloadKey]struct{})
	providers := newStringSet()

	for _, node := range status.Nodes {
		for _, w := range node.Workloads {
			workloads[WorkloadKey{Namespace: w.Namespace, Kind: w.Kind, Name: w.Name}] = struct{}{}
			for _, p := range w.Providers {
				providers.add(p)
			}
		}
	}

	status.Summary = v1alpha1.AIInventorySummary{
		Workloads: int32(len(workloads)),
		Providers: joinProviders(providers),
	}
}
