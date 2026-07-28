package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	fakeversioned "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned/fake"
	v1alpha1informers "github.com/nirmata/kyverno-runtime/pkg/client/informers/externalversions"
	v1alpha1listers "github.com/nirmata/kyverno-runtime/pkg/client/listers/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

func rp(name, uid string, interval *time.Duration) *v1alpha1.RuntimePolicy {
	out := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)},
	}
	if interval != nil {
		out.Spec.EvaluationInterval = &metav1.Duration{Duration: *interval}
	}
	return out
}

func dur(d time.Duration) *time.Duration { return &d }

// newRpQueue returns a real rate limiting queue with all delays set to zero so
// requeues land back in the queue synchronously.
func newRpQueue() workqueue.TypedRateLimitingInterface[queueKey] {
	return workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[queueKey](0, 0),
	)
}

// newLister builds a real lister over the generated fake clientset's informer
// indexer, seeded with the supplied policies. The informer is never started so
// the indexer content is fully deterministic.
func newLister(t *testing.T, objs ...*v1alpha1.RuntimePolicy) (v1alpha1listers.RuntimePolicyLister, cache.Indexer) {
	t.Helper()
	client := fakeversioned.NewSimpleClientset()
	factory := v1alpha1informers.NewSharedInformerFactory(client, 0)
	informer := factory.Runtime().V1alpha1().RuntimePolicies()
	for _, o := range objs {
		if err := informer.Informer().GetIndexer().Add(o); err != nil {
			t.Fatal(err)
		}
	}
	return informer.Lister(), informer.Informer().GetIndexer()
}

func newTestRpMgr(t *testing.T, c compiler.Compiler, hs []events.EventIface, seed ...*v1alpha1.RuntimePolicy) (*RuntimePolicyMgr, cache.Indexer) {
	t.Helper()
	lister, indexer := newLister(t, seed...)
	m := &RuntimePolicyMgr{
		rpThreadMap:   make(map[string]*rpWatch),
		tombstones:    make(map[string]*v1alpha1.RuntimePolicy),
		eventHandlers: hs,
		compiler:      c,
		queue:         newRpQueue(),
		lister:        lister,
		log:           logr.Discard(),
	}
	t.Cleanup(func() {
		m.threadMu.Lock()
		for _, w := range m.rpThreadMap {
			if w.cancel != nil {
				w.cancel()
			}
		}
		m.threadMu.Unlock()
		m.queue.ShutDown()
	})
	return m, indexer
}

func TestRpProcessNextWorkItemRequeuesThenDropsAfterMaxRequeues(t *testing.T) {
	boom := errors.New("compile boom")
	c := &fakeCompiler{err: boom}
	m, _ := newTestRpMgr(t, c, handlers(&recordingHandler{}), rp("p", "uid-1", nil))

	key := queueKey{Type: events.EventTypeCreate, Key: "p"}
	m.queue.Add(key)

	// requeues 0..4 must all put the item back on the queue
	for i := 0; i < maxRequeues; i++ {
		if got := m.queue.NumRequeues(key); got != i {
			t.Fatalf("iteration %d: NumRequeues = %d, want %d", i, got, i)
		}
		if !m.processNextWorkItem(context.Background()) {
			t.Fatalf("iteration %d: processNextWorkItem returned false", i)
		}
		if got := m.queue.Len(); got != 1 {
			t.Fatalf("iteration %d: queue len = %d, want the item requeued", i, got)
		}
	}

	// the next attempt sees maxRequeues requeues and must give up
	if got := m.queue.NumRequeues(key); got != maxRequeues {
		t.Fatalf("NumRequeues = %d, want %d", got, maxRequeues)
	}
	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := m.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the item dropped", got)
	}
	if got := m.queue.NumRequeues(key); got != 0 {
		t.Fatalf("NumRequeues after Forget = %d, want 0", got)
	}
	if got := c.callCount(); got != maxRequeues+1 {
		t.Fatalf("compiler called %d times, want %d", got, maxRequeues+1)
	}
}

// TestRpRequeueCapSurvivesPointerChange_Issue59 is the #59 regression for the
// policy queue. The lister hands back a different object on every attempt; the
// requeue cap must still bound retries because the queue key no longer contains
// the object.
func TestRpRequeueCapSurvivesPointerChange_Issue59(t *testing.T) {
	c := &fakeCompiler{err: errors.New("compile boom")}
	m, indexer := newTestRpMgr(t, c, handlers(&recordingHandler{}), rp("p", "uid-1", nil))

	key := queueKey{Type: events.EventTypeUpdate, Key: "p"}
	m.queue.Add(key)

	distinct := map[*v1alpha1.RuntimePolicy]struct{}{}
	for i := 0; i < maxRequeues; i++ {
		if got := m.queue.NumRequeues(key); got != i {
			t.Fatalf("attempt %d: NumRequeues = %d, want %d; the cap is counting revisions, not retries", i, got, i)
		}
		if !m.processNextWorkItem(context.Background()) {
			t.Fatalf("attempt %d: processNextWorkItem returned false", i)
		}
		if got := m.queue.Len(); got != 1 {
			t.Fatalf("attempt %d: queue len = %d, want the item requeued", i, got)
		}

		// a genuine spec update lands mid-retry: same name and uid, new pointer
		fresh := rp("p", "uid-1", dur(time.Duration(i+1)*time.Minute))
		fresh.ResourceVersion = string(rune('a' + i))
		if err := indexer.Update(fresh); err != nil {
			t.Fatal(err)
		}
		distinct[fresh] = struct{}{}
	}

	if len(distinct) != maxRequeues {
		t.Fatalf("the test did not actually change the lister's pointer: %d distinct objects", len(distinct))
	}

	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := m.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the item dropped after %d requeues despite the pointer churn", got, maxRequeues)
	}
	if got := c.callCount(); got != maxRequeues+1 {
		t.Fatalf("compiler called %d times, want %d; retries are not bounded", got, maxRequeues+1)
	}

	// and each attempt compiled the revision the lister held at that moment
	revisions := map[string]struct{}{}
	for _, p := range c.compiledPolicies() {
		revisions[p.ResourceVersion] = struct{}{}
	}
	if len(revisions) < 2 {
		t.Errorf("compiler only saw %d distinct revisions, so the lister fetch is not happening at processing time", len(revisions))
	}
}

// TestRpProcessNextWorkItemFetchesObjectFromLister proves objects are read at
// processing time rather than carried on the queue.
func TestRpProcessNextWorkItemFetchesObjectFromLister(t *testing.T) {
	current := rp("p", "uid-1", dur(time.Hour))
	current.ResourceVersion = "99"
	c := &fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}}
	m, _ := newTestRpMgr(t, c, handlers(&recordingHandler{}), current)

	m.queue.Add(queueKey{Type: events.EventTypeUpdate, Key: "p"})
	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}

	compiled := c.compiledPolicies()
	if len(compiled) != 1 {
		t.Fatalf("compiler called %d times, want 1", len(compiled))
	}
	if compiled[0].ResourceVersion != "99" {
		t.Errorf("compiled resourceVersion = %q, want the lister's object (%q)", compiled[0].ResourceVersion, "99")
	}
}

func TestRpProcessNextWorkItemListerMissDropsEvent(t *testing.T) {
	c := &fakeCompiler{err: errors.New("compile boom")}
	// nothing seeded in the lister: the fetch misses
	m, _ := newTestRpMgr(t, c, handlers(&recordingHandler{}))

	key := queueKey{Type: events.EventTypeUpdate, Key: "gone"}
	m.queue.Add(key)

	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := m.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the event dropped instead of requeued", got)
	}
	if got := m.queue.NumRequeues(key); got != 0 {
		t.Fatalf("NumRequeues = %d, want the event forgotten", got)
	}
	if got := c.callCount(); got != 0 {
		t.Fatalf("compiler called %d times for a policy that no longer exists, want 0", got)
	}
}

func TestRpProcessNextWorkItemForgetsOnSuccess(t *testing.T) {
	c := &fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}}
	h := &recordingHandler{name: "h"}
	m, _ := newTestRpMgr(t, c, handlers(h), rp("p", "uid-1", nil))

	m.queue.Add(queueKey{Type: events.EventTypeCreate, Key: "p"})
	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := m.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want 0 after a successful handle", got)
	}
	if got := len(h.runtimePolicyCalls()); got != 1 {
		t.Fatalf("handler got %d events, want 1", got)
	}
}

func TestRpProcessNextWorkItemReturnsFalseAfterShutdown(t *testing.T) {
	m, _ := newTestRpMgr(t, &fakeCompiler{}, nil)
	m.queue.ShutDown()
	if m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem must return false once the queue is shut down")
	}
}

func TestRpEnqueueStashesTombstonesForDeletesOnly(t *testing.T) {
	m, _ := newTestRpMgr(t, &fakeCompiler{}, nil)

	m.enqueue(rp("p", "uid-1", nil), events.EventTypeUpdate)
	if len(m.tombstones) != 0 {
		t.Errorf("tombstones = %+v, want empty after an update", m.tombstones)
	}
	m.enqueue(rp("p", "uid-1", nil), events.EventTypeDelete)
	if m.tombstone("p") == nil {
		t.Fatal("no tombstone stashed for a delete event")
	}

	want := []queueKey{
		{Type: events.EventTypeUpdate, Key: "p"},
		{Type: events.EventTypeDelete, Key: "p"},
	}
	var got []queueKey
	for range want {
		k, _ := m.queue.Get()
		m.queue.Done(k)
		got = append(got, k)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("queued keys mismatch (-want +got):\n%s", diff)
	}
}

// TestRpDeleteIsServedFromTombstone proves a delete does not need the lister:
// the object is gone from it by the time the worker runs.
func TestRpDeleteIsServedFromTombstone(t *testing.T) {
	h := &recordingHandler{name: "h"}
	m, _ := newTestRpMgr(t, &fakeCompiler{}, handlers(h))

	m.enqueue(rp("p", "uid-1", nil), events.EventTypeDelete)
	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := m.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want 0", got)
	}
	calls := h.runtimePolicyCalls()
	if len(calls) != 1 {
		t.Fatalf("handler got %d events, want 1", len(calls))
	}
	if calls[0].evType != events.EventTypeDelete {
		t.Errorf("event type = %q, want delete", calls[0].evType)
	}
	if calls[0].res.UID != "uid-1" {
		t.Errorf("result UID = %q, want uid-1", calls[0].res.UID)
	}
	if m.tombstone("p") != nil {
		t.Error("the tombstone was not released after the delete was handled")
	}
}

func TestRpProcessNextWorkItemDeleteWithoutTombstoneIsDropped(t *testing.T) {
	h := &recordingHandler{name: "h"}
	m, _ := newTestRpMgr(t, &fakeCompiler{}, handlers(h))

	m.queue.Add(queueKey{Type: events.EventTypeDelete, Key: "p"})
	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := m.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the event dropped", got)
	}
	if got := len(h.runtimePolicyCalls()); got != 0 {
		t.Fatalf("handler got %d events, want 0 when there is nothing to report", got)
	}
}

// TestRpFanOutConvertsHandlerPanicToError pins the panic barrier on the policy
// stream: a panicking handler becomes an error on the work item.
func TestRpFanOutConvertsHandlerPanicToError(t *testing.T) {
	boom := &recordingHandler{name: "boom", rpPanic: "handler exploded"}
	healthy := &recordingHandler{name: "healthy"}
	m, _ := newTestRpMgr(t, &fakeCompiler{}, handlers(boom, healthy))

	err := m.fanOut(&compiler.EvaluationResult{UID: "uid-1", Name: "p"}, events.EventTypeCreate)
	if err == nil {
		t.Fatal("a panicking handler produced no error")
	}
	if !errors.Is(err, utils.ErrPanic) {
		t.Errorf("err = %v, want it to wrap utils.ErrPanic", err)
	}
	if got := len(healthy.runtimePolicyCalls()); got != 1 {
		t.Errorf("healthy handler got %d events, want 1", got)
	}
}

// TestRpProcessNextWorkItemSurvivesHandlerPanic drives the panic through the
// worker: the item is requeued and the worker keeps going.
func TestRpProcessNextWorkItemSurvivesHandlerPanic(t *testing.T) {
	boom := &recordingHandler{name: "boom", rpPanic: errors.New("handler exploded")}
	m, _ := newTestRpMgr(t,
		&fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}},
		handlers(boom), rp("p", "uid-1", nil))

	m.queue.Add(queueKey{Type: events.EventTypeCreate, Key: "p"})
	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false after a handler panic")
	}
	if got := m.queue.Len(); got != 1 {
		t.Fatalf("queue len = %d, want the item requeued after the panic", got)
	}
}

func TestHandleCreateCompileErrorPropagates(t *testing.T) {
	boom := errors.New("compile boom")
	h := &recordingHandler{name: "h"}
	m, _ := newTestRpMgr(t, &fakeCompiler{err: boom}, handlers(h))

	err := m.handleCreate(context.Background(), rp("p", "uid-1", nil))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if got := len(h.runtimePolicyCalls()); got != 0 {
		t.Errorf("handler was called %d times on a compile failure, want 0", got)
	}
}

func TestHandleCreateFansOutToAllHandlers(t *testing.T) {
	compiled := &compiler.CompiledRuntimePolicy{UID: "uid-1"}
	h1 := &recordingHandler{name: "h1"}
	h2 := &recordingHandler{name: "h2"}
	h3 := &recordingHandler{name: "h3"}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(h1, h2, h3))

	if err := m.handleCreate(context.Background(), rp("p", "uid-1", nil)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var first *compiler.EvaluationResult
	for _, h := range []*recordingHandler{h1, h2, h3} {
		calls := h.runtimePolicyCalls()
		if len(calls) != 1 {
			t.Fatalf("%s got %d events, want 1", h.name, len(calls))
		}
		if calls[0].evType != events.EventTypeCreate {
			t.Errorf("%s event type = %q, want create", h.name, calls[0].evType)
		}
		if calls[0].res.UID != "uid-1" {
			t.Errorf("%s result UID = %q, want uid-1", h.name, calls[0].res.UID)
		}
		if first == nil {
			first = calls[0].res
		} else if calls[0].res != first {
			t.Errorf("%s received a different evaluation result than the first handler", h.name)
		}
	}
	if len(m.rpThreadMap) != 0 {
		t.Errorf("rpThreadMap = %v, want empty when no evaluation interval is set", m.rpThreadMap)
	}
}

func TestHandleCreateJoinsAllHandlerErrors(t *testing.T) {
	errA := errors.New("handler a failed")
	errB := errors.New("handler b failed")
	h1 := &recordingHandler{name: "h1", rpErr: errA}
	h2 := &recordingHandler{name: "h2", rpErr: errB}
	h3 := &recordingHandler{name: "h3"}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}}, handlers(h1, h2, h3))

	err := m.handleCreate(context.Background(), rp("p", "uid-1", nil))
	if err == nil {
		t.Fatal("expected an aggregated error")
	}
	if !errors.Is(err, errA) {
		t.Errorf("aggregated error is missing errA: %v", err)
	}
	if !errors.Is(err, errB) {
		t.Errorf("aggregated error is missing errB: %v", err)
	}
	// the healthy handler still received the event
	if got := len(h3.runtimePolicyCalls()); got != 1 {
		t.Errorf("h3 got %d events, want 1 despite the other handlers failing", got)
	}
}

func TestHandleCreateRegistersIntervalThread(t *testing.T) {
	compiled := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)}
	h := &recordingHandler{name: "h"}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(h))

	if err := m.handleCreate(context.Background(), rp("p", "uid-1", dur(time.Hour))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	watch, ok := m.rpThreadMap["uid-1"]
	if !ok {
		t.Fatalf("rpThreadMap has no entry for uid-1: %v", m.rpThreadMap)
	}
	if watch.compiled != compiled {
		t.Error("rpThreadMap entry does not hold the compiled policy")
	}
	if watch.cancel == nil {
		t.Error("rpThreadMap entry has no cancel func")
	}
}

// TestHandleUpdateNilEvaluationIntervalDoesNotPanic pins the nil dereference
// that used to happen when a tracked policy dropped its evaluationInterval:
// handleUpdate read rp.Spec.EvaluationInterval.Duration unconditionally.
func TestHandleUpdateNilEvaluationIntervalDoesNotPanic(t *testing.T) {
	compiled := &compiler.CompiledRuntimePolicy{UID: "uid-1"}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	cancelled := false
	m.rpThreadMap["uid-1"] = &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)},
		cancel:   func() { cancelled = true },
	}

	// the incoming policy no longer carries an evaluation interval
	if err := m.handleUpdate(context.Background(), rp("p", "uid-1", nil)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cancelled {
		t.Error("the previous interval thread was not cancelled")
	}
	if _, ok := m.rpThreadMap["uid-1"]; ok {
		t.Error("rpThreadMap still tracks a policy that has no evaluation interval")
	}
}

// The mirror case: the tracked entry has no interval but the new policy does.
// This dereferenced currentRb.compiled.ReevalInterval.
func TestHandleUpdateNilTrackedIntervalDoesNotPanic(t *testing.T) {
	compiled := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	cancelled := false
	m.rpThreadMap["uid-1"] = &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"},
		cancel:   func() { cancelled = true },
	}

	if err := m.handleUpdate(context.Background(), rp("p", "uid-1", dur(time.Hour))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cancelled {
		t.Error("the previous interval thread was not cancelled")
	}
	watch, ok := m.rpThreadMap["uid-1"]
	if !ok {
		t.Fatal("rpThreadMap lost the entry for a policy that gained an interval")
	}
	if watch.compiled != compiled {
		t.Error("rpThreadMap entry was not replaced with the newly compiled policy")
	}
	if watch.cancel == nil {
		t.Error("rpThreadMap entry has no cancel func")
	}
}

func TestHandleUpdateReplacesThreadWhenIntervalChanges(t *testing.T) {
	compiled := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(2 * time.Hour)}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	cancelled := false
	old := &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)},
		cancel:   func() { cancelled = true },
	}
	m.rpThreadMap["uid-1"] = old

	if err := m.handleUpdate(context.Background(), rp("p", "uid-1", dur(2*time.Hour))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cancelled {
		t.Error("the interval thread for the previous interval was not cancelled")
	}
	watch := m.rpThreadMap["uid-1"]
	if watch == old {
		t.Error("rpThreadMap entry was not replaced")
	}
	if watch.compiled != compiled {
		t.Error("rpThreadMap entry does not hold the newly compiled policy")
	}
}

func TestHandleUpdateKeepsThreadWhenIntervalUnchanged(t *testing.T) {
	m, _ := newTestRpMgr(t,
		&fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)}},
		handlers(&recordingHandler{name: "h"}))

	cancelled := false
	old := &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)},
		cancel:   func() { cancelled = true },
	}
	m.rpThreadMap["uid-1"] = old

	if err := m.handleUpdate(context.Background(), rp("p", "uid-1", dur(time.Hour))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cancelled {
		t.Error("the interval thread was cancelled even though the interval did not change")
	}
	if m.rpThreadMap["uid-1"] != old {
		t.Error("rpThreadMap entry was replaced even though the interval did not change")
	}
}

// TestHandleUpdateRefreshesCompiledWhenIntervalUnchanged pins the stale policy
// bug: when the interval did not change, handleUpdate kept the existing rpWatch
// but left its old compiled pointer in place. evaluateForInterval reads compiled
// from that entry on every tick, so interval re-evaluations kept applying the
// pre-update policy until the interval happened to change.
func TestHandleUpdateRefreshesCompiledWhenIntervalUnchanged(t *testing.T) {
	fresh := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: fresh}, handlers(&recordingHandler{name: "h"}))

	stale := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)}
	m.rpThreadMap["uid-1"] = &rpWatch{compiled: stale, cancel: func() {}}

	if err := m.handleUpdate(context.Background(), rp("p", "uid-1", dur(time.Hour))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := m.rpThreadMap["uid-1"].compiled
	if got == stale {
		t.Error("rpThreadMap entry still holds the pre-update compiled policy; interval ticks would evaluate a stale policy")
	}
	if got != fresh {
		t.Errorf("compiled = %p, want the freshly compiled policy %p", got, fresh)
	}
}

// TestHandleUpdateStartsThreadWhenPolicyGainsInterval covers a policy created
// without spec.evaluationInterval (so no thread was registered) that later gains
// one.
func TestHandleUpdateStartsThreadWhenPolicyGainsInterval(t *testing.T) {
	compiled := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	if len(m.rpThreadMap) != 0 {
		t.Fatalf("precondition failed, rpThreadMap = %v", m.rpThreadMap)
	}

	if err := m.handleUpdate(context.Background(), rp("p", "uid-1", dur(time.Hour))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	watch, ok := m.rpThreadMap["uid-1"]
	if !ok {
		t.Fatal("no interval thread was registered for a policy that gained an evaluationInterval")
	}
	if watch.compiled != compiled {
		t.Error("registered entry does not hold the compiled policy")
	}
	if watch.cancel == nil {
		t.Error("registered entry has no cancel func, so the thread can never be stopped")
	}
}

// TestHandleUpdateNoIntervalStaysUntracked is the counterpart: a policy with no
// interval, not already tracked, must not start a goroutine.
func TestHandleUpdateNoIntervalStaysUntracked(t *testing.T) {
	m, _ := newTestRpMgr(t,
		&fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}},
		handlers(&recordingHandler{name: "h"}))

	if err := m.handleUpdate(context.Background(), rp("p", "uid-1", nil)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(m.rpThreadMap) != 0 {
		t.Errorf("rpThreadMap = %v, want empty for a policy with no evaluationInterval", m.rpThreadMap)
	}
}

// TestIntervalThreadConcurrentWithUpdates exercises rpThreadMap from an
// evaluateForInterval goroutine while the worker updates and deletes the same
// entry. Meant to be run under -race.
func TestIntervalThreadConcurrentWithUpdates(t *testing.T) {
	compiled := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Millisecond)}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	threadCtx, threadCancel := context.WithCancel(ctx)
	m.rpThreadMap["uid-1"] = &rpWatch{compiled: compiled, cancel: threadCancel}
	go m.evaluateForInterval(threadCtx, 20*time.Microsecond, "uid-1")

	for i := 0; i < 2000; i++ {
		if err := m.handleUpdate(ctx, rp("p", "uid-1", dur(time.Millisecond))); err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
	}

	if err := m.handleDelete(rp("p", "uid-1", dur(time.Millisecond))); err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}

	m.threadMu.Lock()
	remaining := len(m.rpThreadMap)
	m.threadMu.Unlock()
	if remaining != 0 {
		t.Errorf("rpThreadMap has %d entries after delete, want 0", remaining)
	}
}

func TestHandleUpdateFansOutAndJoinsErrors(t *testing.T) {
	errA := errors.New("handler a failed")
	errB := errors.New("handler b failed")
	h1 := &recordingHandler{name: "h1", rpErr: errA}
	h2 := &recordingHandler{name: "h2", rpErr: errB}
	m, _ := newTestRpMgr(t, &fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}}, handlers(h1, h2))

	err := m.handleUpdate(context.Background(), rp("p", "uid-1", nil))
	if err == nil {
		t.Fatal("expected an aggregated error")
	}
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Errorf("aggregated error is missing one of the handler errors: %v", err)
	}
	for _, h := range []*recordingHandler{h1, h2} {
		calls := h.runtimePolicyCalls()
		if len(calls) != 1 || calls[0].evType != events.EventTypeUpdate {
			t.Errorf("%s calls = %+v, want a single update event", h.name, calls)
		}
	}
}

func TestHandleDeleteCancelsThreadAndSendsUIDOnly(t *testing.T) {
	h1 := &recordingHandler{name: "h1"}
	h2 := &recordingHandler{name: "h2"}
	m, _ := newTestRpMgr(t, &fakeCompiler{}, handlers(h1, h2))

	cancelled := false
	m.rpThreadMap["uid-1"] = &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)},
		cancel:   func() { cancelled = true },
	}

	if err := m.handleDelete(rp("p", "uid-1", nil)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cancelled {
		t.Error("the interval thread was not cancelled on delete")
	}
	if _, ok := m.rpThreadMap["uid-1"]; ok {
		t.Error("rpThreadMap still has an entry after delete")
	}
	if got := m.compiler.(*fakeCompiler).callCount(); got != 0 {
		t.Errorf("compiler called %d times on delete, want 0", got)
	}

	for _, h := range []*recordingHandler{h1, h2} {
		calls := h.runtimePolicyCalls()
		if len(calls) != 1 {
			t.Fatalf("%s got %d events, want 1", h.name, len(calls))
		}
		if calls[0].evType != events.EventTypeDelete {
			t.Errorf("%s event type = %q, want delete", h.name, calls[0].evType)
		}
		res := calls[0].res
		if res.UID != "uid-1" || res.Name != "p" {
			t.Errorf("%s result identity = (%q, %q), want (uid-1, p)", h.name, res.UID, res.Name)
		}
		if res.IPs != nil || res.Open != nil || res.Exec != nil || res.Selector != nil || res.Mode != "" {
			t.Errorf("%s delete result carries data beyond the identity: %+v", h.name, res)
		}
	}
}

func TestHandleDeleteUnknownUIDStillFansOut(t *testing.T) {
	errA := errors.New("handler a failed")
	h1 := &recordingHandler{name: "h1", rpErr: errA}
	h2 := &recordingHandler{name: "h2"}
	m, _ := newTestRpMgr(t, &fakeCompiler{}, handlers(h1, h2))

	err := m.handleDelete(rp("p", "never-seen", nil))
	if !errors.Is(err, errA) {
		t.Fatalf("err = %v, want it to contain %v", err, errA)
	}
	if got := len(h2.runtimePolicyCalls()); got != 1 {
		t.Errorf("h2 got %d events, want 1", got)
	}
}
