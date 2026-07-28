package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	fakeversioned "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned/fake"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func newTestSyncer(t *testing.T, nodeName string, r *Rollup, objs ...runtime.Object) (*Syncer, *fakeversioned.Clientset, *metrics.Metrics) {
	t.Helper()
	client := fakeversioned.NewSimpleClientset(objs...)
	m := metrics.New(prometheus.NewRegistry())
	s := NewSyncer(client, nodeName, r, time.Hour, logr.Discard(),
		WithSyncerClock(func() time.Time { return baseTime }),
		WithMetrics(m))
	return s, client, m
}

func getInventory(t *testing.T, c *fakeversioned.Clientset) *v1alpha1.AIInventory {
	t.Helper()
	got, err := c.RuntimeV1alpha1().AIInventories().Get(context.Background(), SingletonName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting AIInventory %s: %v", SingletonName, err)
	}
	return got
}

// rollupWith returns a rollup holding one workload with the given provider.
func rollupWith(t *testing.T, ns, kind, name, provider string) *Rollup {
	t.Helper()
	r := New(logr.Discard(), WithClock(func() time.Time { return baseTime }))
	r.Record(aiEvent(ns, kind, name, &runtimeevent.AIFacts{
		Class: runtimeevent.AIClassLLM, Provider: provider, Transport: "https",
	}))
	return r
}

// TestSyncCreatesTheSingleton covers the cold-start path: no object exists, and
// the syncer must create it before writing its shard.
func TestSyncCreatesTheSingleton(t *testing.T) {
	s, client, m := newTestSyncer(t, "node-a", rollupWith(t, "default", "Deployment", "agent", "openai"))

	if _, err := client.RuntimeV1alpha1().AIInventories().Get(context.Background(), SingletonName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("precondition: AIInventory should not exist, got err=%v", err)
	}
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	got := getInventory(t, client)
	if len(got.Status.Nodes) != 1 || got.Status.Nodes[0].NodeName != "node-a" {
		t.Fatalf("status.nodes = %+v, want a single node-a shard", got.Status.Nodes)
	}
	if got.Status.Summary.Workloads != 1 || got.Status.Summary.Providers != "openai" {
		t.Errorf("summary = %+v, want {Workloads:1 Providers:openai}", got.Status.Summary)
	}
	if c := testutil.ToFloat64(m.InventorySyncs.WithLabelValues(resultOK)); c != 1 {
		t.Errorf("InventorySyncs{result=ok} = %v, want 1", c)
	}
}

// TestEnsureIsIdempotentAcrossDaemons: every node calls Ensure, only the first
// creates, and losing the race is not an error.
func TestEnsureIsIdempotentAcrossDaemons(t *testing.T) {
	s, client, _ := newTestSyncer(t, "node-a", New(logr.Discard()))

	for i := 0; i < 3; i++ {
		if err := s.Ensure(context.Background()); err != nil {
			t.Fatalf("Ensure #%d: %v", i, err)
		}
	}
	list, err := client.RuntimeV1alpha1().AIInventories().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Errorf("AIInventory count = %d, want 1", len(list.Items))
	}
}

// TestSyncReplacesOnlyThisNodesShard is the DaemonSet-safety property: node-b's
// entry must survive node-a's write untouched, and the shard list stays sorted.
func TestSyncReplacesOnlyThisNodesShard(t *testing.T) {
	nodeB := v1alpha1.AINodeInventory{
		NodeName:      "node-b",
		UpdatedAt:     metav1.NewTime(baseTime.Add(-time.Hour)),
		DroppedEvents: 5,
		Workloads: []v1alpha1.AIWorkloadInventory{{
			Namespace: "other", Kind: "Deployment", Name: "chatbot",
			Classes: []string{"llm"}, Providers: []string{"anthropic"},
			EventCount: 3,
			FirstSeen:  metav1.NewTime(baseTime.Add(-time.Hour)),
			LastSeen:   metav1.NewTime(baseTime.Add(-time.Hour)),
		}},
	}
	existing := &v1alpha1.AIInventory{
		ObjectMeta: metav1.ObjectMeta{Name: SingletonName},
		Status: v1alpha1.AIInventoryStatus{
			Nodes: []v1alpha1.AINodeInventory{
				nodeB,
				{NodeName: "node-z", Workloads: []v1alpha1.AIWorkloadInventory{{
					Namespace: "z", Kind: "Pod", Name: "zz", Providers: []string{"vertex"},
				}}},
			},
		},
	}

	s, client, _ := newTestSyncer(t, "node-a", rollupWith(t, "default", "Deployment", "agent", "openai"), existing)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	got := getInventory(t, client)
	var names []string
	for _, n := range got.Status.Nodes {
		names = append(names, n.NodeName)
	}
	if diff := cmp.Diff([]string{"node-a", "node-b", "node-z"}, names); diff != "" {
		t.Errorf("status.nodes order (-want +got):\n%s", diff)
	}
	for _, n := range got.Status.Nodes {
		if n.NodeName != "node-b" {
			continue
		}
		if diff := cmp.Diff(nodeB, n); diff != "" {
			t.Errorf("node-b's shard was modified by node-a's write (-want +got):\n%s", diff)
		}
	}
}

// TestSyncRecomputesSummaryAcrossShards asserts the summary is derived from all
// shards, dedupes a workload that has pods on several nodes, and merges the
// provider list.
func TestSyncRecomputesSummaryAcrossShards(t *testing.T) {
	// node-b already reports the SAME workload node-a is about to report, plus
	// one of its own.
	existing := &v1alpha1.AIInventory{
		ObjectMeta: metav1.ObjectMeta{Name: SingletonName},
		Status: v1alpha1.AIInventoryStatus{
			Summary: v1alpha1.AIInventorySummary{Workloads: 99, Providers: "stale"},
			Nodes: []v1alpha1.AINodeInventory{{
				NodeName: "node-b",
				Workloads: []v1alpha1.AIWorkloadInventory{
					{Namespace: "default", Kind: "Deployment", Name: "agent", Providers: []string{"anthropic"}},
					{Namespace: "other", Kind: "Pod", Name: "solo", Providers: []string{"openai", "vertex"}},
				},
			}},
		},
	}

	s, client, _ := newTestSyncer(t, "node-a", rollupWith(t, "default", "Deployment", "agent", "openai"), existing)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	want := v1alpha1.AIInventorySummary{Workloads: 2, Providers: "anthropic,openai,vertex"}
	if diff := cmp.Diff(want, getInventory(t, client).Status.Summary); diff != "" {
		t.Errorf("summary (-want +got):\n%s", diff)
	}
}

// TestSyncCarriesDroppedEventsIntoTheShard is the "coverage incomplete" signal:
// a node whose collector is dropping events says so in its own shard rather
// than letting the silence read as safety (proposal §2.9).
func TestSyncCarriesDroppedEventsIntoTheShard(t *testing.T) {
	var drops int64 = 137
	r := New(logr.Discard(),
		WithClock(func() time.Time { return baseTime }),
		WithDroppedCounter(func() int64 { return drops }))

	s, client, _ := newTestSyncer(t, "node-a", r)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	got := getInventory(t, client)
	if len(got.Status.Nodes) != 1 {
		t.Fatalf("status.nodes = %+v, want this node's shard even with no workloads", got.Status.Nodes)
	}
	if got.Status.Nodes[0].DroppedEvents != 137 {
		t.Errorf("droppedEvents = %d, want 137", got.Status.Nodes[0].DroppedEvents)
	}
	if !got.Status.Nodes[0].UpdatedAt.Time.Equal(baseTime) {
		t.Errorf("updatedAt = %v, want the injected clock's %v", got.Status.Nodes[0].UpdatedAt, baseTime)
	}
}

// TestSyncRetriesOnConflict injects a conflict on the first status update, the
// way another node's concurrent write would, and asserts the shard still lands.
func TestSyncRetriesOnConflict(t *testing.T) {
	s, client, m := newTestSyncer(t, "node-a", rollupWith(t, "default", "Deployment", "agent", "openai"),
		&v1alpha1.AIInventory{ObjectMeta: metav1.ObjectMeta{Name: SingletonName}})

	var updates int
	client.PrependReactor("update", "aiinventories", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		if updates == 1 {
			return true, nil, apierrors.NewConflict(
				action.GetResource().GroupResource(), SingletonName, context.DeadlineExceeded)
		}
		return false, nil, nil
	})

	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync should have retried the conflict: %v", err)
	}
	if updates < 2 {
		t.Fatalf("update was attempted %d times, want a retry after the conflict", updates)
	}
	got := getInventory(t, client)
	if len(got.Status.Nodes) != 1 || got.Status.Nodes[0].NodeName != "node-a" {
		t.Errorf("status.nodes = %+v, want this node's shard written after the retry", got.Status.Nodes)
	}
	if c := testutil.ToFloat64(m.InventorySyncs.WithLabelValues(resultOK)); c != 1 {
		t.Errorf("InventorySyncs{result=ok} = %v, want 1", c)
	}
}

// TestSyncConflictReReadsOtherNodesShard proves the retry re-reads: the conflict
// reactor mutates the stored object to add node-c, and node-c must still be
// present after node-a's retry succeeds.
func TestSyncConflictReReadsOtherNodesShard(t *testing.T) {
	s, client, _ := newTestSyncer(t, "node-a", rollupWith(t, "default", "Deployment", "agent", "openai"),
		&v1alpha1.AIInventory{ObjectMeta: metav1.ObjectMeta{Name: SingletonName}})

	var updates int
	client.PrependReactor("update", "aiinventories", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		if updates != 1 {
			return false, nil, nil
		}
		// simulate node-c winning the race
		cur, err := client.Tracker().Get(action.GetResource(), "", SingletonName)
		if err != nil {
			return true, nil, err
		}
		inv, ok := cur.(*v1alpha1.AIInventory)
		if !ok {
			t.Fatalf("tracker returned %T, want *v1alpha1.AIInventory", cur)
		}
		inv.Status.Nodes = append(inv.Status.Nodes, v1alpha1.AINodeInventory{
			NodeName:  "node-c",
			Workloads: []v1alpha1.AIWorkloadInventory{{Namespace: "c", Kind: "Pod", Name: "cc", Providers: []string{"bedrock"}}},
		})
		if err := client.Tracker().Update(action.GetResource(), inv, ""); err != nil {
			return true, nil, err
		}
		return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), SingletonName, context.DeadlineExceeded)
	})

	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	got := getInventory(t, client)
	var names []string
	for _, n := range got.Status.Nodes {
		names = append(names, n.NodeName)
	}
	if diff := cmp.Diff([]string{"node-a", "node-c"}, names); diff != "" {
		t.Errorf("status.nodes after the retry (-want +got):\n%s", diff)
	}
	if got.Status.Summary.Providers != "bedrock,openai" {
		t.Errorf("summary providers = %q, want %q", got.Status.Summary.Providers, "bedrock,openai")
	}
}

// TestSyncSkipsNoOpWrites keeps every daemon in a large DaemonSet from
// rewriting an identical status on every tick.
func TestSyncSkipsNoOpWrites(t *testing.T) {
	s, client, m := newTestSyncer(t, "node-a", rollupWith(t, "default", "Deployment", "agent", "openai"),
		&v1alpha1.AIInventory{ObjectMeta: metav1.ObjectMeta{Name: SingletonName}})

	var updates int
	client.PrependReactor("update", "aiinventories", func(k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		return false, nil, nil
	})

	for i := 0; i < 3; i++ {
		if err := s.Sync(context.Background()); err != nil {
			t.Fatalf("Sync #%d: %v", i, err)
		}
	}
	if updates != 1 {
		t.Errorf("issued %d updates for 3 identical syncs, want 1", updates)
	}
	if c := testutil.ToFloat64(m.InventorySyncs.WithLabelValues(resultSkipped)); c != 2 {
		t.Errorf("InventorySyncs{result=skipped} = %v, want 2", c)
	}
}

// TestSyncReportsErrorsAndCountsThem: a non-conflict API failure must surface,
// not be swallowed.
func TestSyncReportsErrorsAndCountsThem(t *testing.T) {
	s, client, m := newTestSyncer(t, "node-a", rollupWith(t, "default", "Deployment", "agent", "openai"),
		&v1alpha1.AIInventory{ObjectMeta: metav1.ObjectMeta{Name: SingletonName}})

	client.PrependReactor("update", "aiinventories", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewInternalError(context.DeadlineExceeded)
	})

	if err := s.Sync(context.Background()); err == nil {
		t.Fatal("Sync returned nil, want the API error")
	}
	if c := testutil.ToFloat64(m.InventorySyncs.WithLabelValues(resultError)); c != 1 {
		t.Errorf("InventorySyncs{result=error} = %v, want 1", c)
	}
}

// TestRunSyncsOnceMoreOnShutdown: the last observations of a draining daemon
// must reach the API even though the context is already cancelled.
func TestRunSyncsOnceMoreOnShutdown(t *testing.T) {
	s, client, _ := newTestSyncer(t, "node-a", rollupWith(t, "default", "Deployment", "agent", "openai"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}

	got := getInventory(t, client)
	if len(got.Status.Nodes) != 1 || got.Status.Nodes[0].NodeName != "node-a" {
		t.Errorf("status.nodes = %+v, want the final shutdown flush", got.Status.Nodes)
	}
}

// TestNewSyncerDefaultsTheInterval guards the wiring against a zero interval
// panicking time.NewTicker.
func TestNewSyncerDefaultsTheInterval(t *testing.T) {
	s := NewSyncer(fakeversioned.NewSimpleClientset(), "node-a", New(logr.Discard()), 0, logr.Discard())
	if s.interval != DefaultSyncInterval {
		t.Errorf("interval = %v, want %v", s.interval, DefaultSyncInterval)
	}
}

// TestSetNodeShardInsertsInSortedPosition is a direct table over the shard
// splice, including the replace-in-place case.
func TestSetNodeShardInsertsInSortedPosition(t *testing.T) {
	tests := []struct {
		name    string
		initial []string
		shard   string
		want    []string
	}{
		{name: "empty", initial: nil, shard: "node-b", want: []string{"node-b"}},
		{name: "front", initial: []string{"node-b", "node-c"}, shard: "node-a", want: []string{"node-a", "node-b", "node-c"}},
		{name: "middle", initial: []string{"node-a", "node-c"}, shard: "node-b", want: []string{"node-a", "node-b", "node-c"}},
		{name: "back", initial: []string{"node-a", "node-b"}, shard: "node-c", want: []string{"node-a", "node-b", "node-c"}},
		{name: "replace", initial: []string{"node-a", "node-b"}, shard: "node-b", want: []string{"node-a", "node-b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := &v1alpha1.AIInventoryStatus{}
			for _, n := range tc.initial {
				status.Nodes = append(status.Nodes, v1alpha1.AINodeInventory{NodeName: n})
			}
			setNodeShard(status, v1alpha1.AINodeInventory{NodeName: tc.shard, DroppedEvents: 9})

			var got []string
			for _, n := range status.Nodes {
				got = append(got, n.NodeName)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("node names (-want +got):\n%s", diff)
			}
			for _, n := range status.Nodes {
				if n.NodeName == tc.shard && n.DroppedEvents != 9 {
					t.Errorf("shard %s was not written: %+v", tc.shard, n)
				}
			}
		})
	}
}
