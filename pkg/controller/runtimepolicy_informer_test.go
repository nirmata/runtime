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

	"github.com/go-logr/logr"
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
func newRpQueue() workqueue.TypedRateLimitingInterface[events.Event[*v1alpha1.RuntimePolicy]] {
	return workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[events.Event[*v1alpha1.RuntimePolicy]](0, 0),
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

func newTestRpMgr(t *testing.T, c compiler.Compiler, hs []events.EventIface, seed ...*v1alpha1.RuntimePolicy) *RuntimePolicyMgr {
	t.Helper()
	lister, _ := newLister(t, seed...)
	m := &RuntimePolicyMgr{
		rpThreadMap:   make(map[string]*rpWatch),
		eventHandlers: hs,
		compiler:      c,
		queue:         newRpQueue(),
		lister:        lister,
		log:           logr.Discard(),
	}
	t.Cleanup(func() {
		for _, w := range m.rpThreadMap {
			if w.cancel != nil {
				w.cancel()
			}
		}
		m.queue.ShutDown()
	})
	return m
}

func TestProcessNextWorkItemRequeuesThenDropsAfterMaxRequeues(t *testing.T) {
	boom := errors.New("compile boom")
	c := &fakeCompiler{err: boom}
	m := newTestRpMgr(t, c, handlers(&recordingHandler{}))

	ev := events.Event[*v1alpha1.RuntimePolicy]{Obj: rp("p", "uid-1", nil), Type: events.EventTypeCreate}
	m.queue.Add(ev)

	// requeues 0..4 must all put the item back on the queue
	for i := 0; i < 5; i++ {
		if got := m.queue.NumRequeues(ev); got != i {
			t.Fatalf("iteration %d: NumRequeues = %d, want %d", i, got, i)
		}
		if !m.processNextWorkItem(context.Background()) {
			t.Fatalf("iteration %d: processNextWorkItem returned false", i)
		}
		if got := m.queue.Len(); got != 1 {
			t.Fatalf("iteration %d: queue len = %d, want the item requeued", i, got)
		}
	}

	// the 6th attempt sees 5 requeues and must give up
	if got := m.queue.NumRequeues(ev); got != 5 {
		t.Fatalf("NumRequeues = %d, want 5", got)
	}
	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := m.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the item dropped", got)
	}
	if got := m.queue.NumRequeues(ev); got != 0 {
		t.Fatalf("NumRequeues after Forget = %d, want 0", got)
	}
	if got := c.callCount(); got != 6 {
		t.Fatalf("compiler called %d times, want 6", got)
	}
}

func TestProcessNextWorkItemUpdateRefetchesFromLister(t *testing.T) {
	current := rp("p", "uid-1", dur(time.Hour))
	c := &fakeCompiler{err: errors.New("compile boom")}
	m := newTestRpMgr(t, c, handlers(&recordingHandler{}), current)

	// the queued object is a stale copy of the same policy
	stale := rp("p", "uid-1", nil)
	m.queue.Add(events.Event[*v1alpha1.RuntimePolicy]{Obj: stale, Type: events.EventTypeUpdate})

	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := m.queue.Len(); got != 1 {
		t.Fatalf("queue len = %d, want the update requeued", got)
	}

	requeued, _ := m.queue.Get()
	if requeued.Obj != current {
		t.Errorf("requeued object = %p, want the lister object %p", requeued.Obj, current)
	}
	if requeued.Obj == stale {
		t.Error("requeued object is the stale object from the original event")
	}
	if requeued.Type != events.EventTypeUpdate {
		t.Errorf("requeued type = %q, want update", requeued.Type)
	}
}

func TestProcessNextWorkItemUpdateListerMissDropsEvent(t *testing.T) {
	c := &fakeCompiler{err: errors.New("compile boom")}
	// nothing seeded in the lister: the refetch misses
	m := newTestRpMgr(t, c, handlers(&recordingHandler{}))

	ev := events.Event[*v1alpha1.RuntimePolicy]{Obj: rp("gone", "uid-1", nil), Type: events.EventTypeUpdate}
	m.queue.Add(ev)

	if !m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := m.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the event dropped instead of requeued", got)
	}
	if got := m.queue.NumRequeues(ev); got != 0 {
		t.Fatalf("NumRequeues = %d, want the event forgotten", got)
	}
}

func TestProcessNextWorkItemForgetsOnSuccess(t *testing.T) {
	c := &fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}}
	h := &recordingHandler{name: "h"}
	m := newTestRpMgr(t, c, handlers(h))

	ev := events.Event[*v1alpha1.RuntimePolicy]{Obj: rp("p", "uid-1", nil), Type: events.EventTypeCreate}
	m.queue.Add(ev)

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

func TestProcessNextWorkItemReturnsFalseAfterShutdown(t *testing.T) {
	m := newTestRpMgr(t, &fakeCompiler{}, nil)
	m.queue.ShutDown()
	if m.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem must return false once the queue is shut down")
	}
}

func TestHandleCreateCompileErrorPropagates(t *testing.T) {
	boom := errors.New("compile boom")
	h := &recordingHandler{name: "h"}
	m := newTestRpMgr(t, &fakeCompiler{err: boom}, handlers(h))

	err := m.handleCreate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", nil), Type: events.EventTypeCreate,
	})
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
	m := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(h1, h2, h3))

	if err := m.handleCreate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", nil), Type: events.EventTypeCreate,
	}); err != nil {
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
	m := newTestRpMgr(t, &fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}}, handlers(h1, h2, h3))

	err := m.handleCreate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", nil), Type: events.EventTypeCreate,
	})
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
	m := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(h))

	if err := m.handleCreate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", dur(time.Hour)), Type: events.EventTypeCreate,
	}); err != nil {
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
	m := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	cancelled := false
	m.rpThreadMap["uid-1"] = &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)},
		cancel:   func() { cancelled = true },
	}

	// the incoming policy no longer carries an evaluation interval
	if err := m.handleUpdate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", nil), Type: events.EventTypeUpdate,
	}); err != nil {
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
	m := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	cancelled := false
	m.rpThreadMap["uid-1"] = &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"},
		cancel:   func() { cancelled = true },
	}

	if err := m.handleUpdate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", dur(time.Hour)), Type: events.EventTypeUpdate,
	}); err != nil {
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
	m := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	cancelled := false
	old := &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)},
		cancel:   func() { cancelled = true },
	}
	m.rpThreadMap["uid-1"] = old

	if err := m.handleUpdate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", dur(2*time.Hour)), Type: events.EventTypeUpdate,
	}); err != nil {
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
	m := newTestRpMgr(t,
		&fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)}},
		handlers(&recordingHandler{name: "h"}))

	cancelled := false
	old := &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)},
		cancel:   func() { cancelled = true },
	}
	m.rpThreadMap["uid-1"] = old

	if err := m.handleUpdate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", dur(time.Hour)), Type: events.EventTypeUpdate,
	}); err != nil {
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
	m := newTestRpMgr(t, &fakeCompiler{compiled: fresh}, handlers(&recordingHandler{name: "h"}))

	stale := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)}
	m.rpThreadMap["uid-1"] = &rpWatch{compiled: stale, cancel: func() {}}

	if err := m.handleUpdate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", dur(time.Hour)), Type: events.EventTypeUpdate,
	}); err != nil {
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
// without spec.evaluationInterval (so handleCreate registered no thread) that
// later gains one. handleUpdate used to only reconcile policies already present
// in rpThreadMap, so no re-evaluation goroutine was ever started.
func TestHandleUpdateStartsThreadWhenPolicyGainsInterval(t *testing.T) {
	compiled := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)}
	m := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	// nothing tracked: the policy was created without an interval
	if len(m.rpThreadMap) != 0 {
		t.Fatalf("precondition failed, rpThreadMap = %v", m.rpThreadMap)
	}

	if err := m.handleUpdate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", dur(time.Hour)), Type: events.EventTypeUpdate,
	}); err != nil {
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
	m := newTestRpMgr(t,
		&fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}},
		handlers(&recordingHandler{name: "h"}))

	if err := m.handleUpdate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", nil), Type: events.EventTypeUpdate,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(m.rpThreadMap) != 0 {
		t.Errorf("rpThreadMap = %v, want empty for a policy with no evaluationInterval", m.rpThreadMap)
	}
}

// TestIntervalThreadConcurrentWithUpdates exercises rpThreadMap from an
// evaluateForInterval goroutine while the worker updates and deletes the same
// entry. Meant to be run under -race: the map was previously read by every
// interval goroutine with no lock while handleUpdate wrote to it.
func TestIntervalThreadConcurrentWithUpdates(t *testing.T) {
	compiled := &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Millisecond)}
	m := newTestRpMgr(t, &fakeCompiler{compiled: compiled}, handlers(&recordingHandler{name: "h"}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// register the entry and start the ticking goroutine the way handleCreate does
	threadCtx, threadCancel := context.WithCancel(ctx)
	m.rpThreadMap["uid-1"] = &rpWatch{compiled: compiled, cancel: threadCancel}
	go m.evaluateForInterval(threadCtx, 20*time.Microsecond, "uid-1")

	for i := 0; i < 2000; i++ {
		if err := m.handleUpdate(ctx, events.Event[*v1alpha1.RuntimePolicy]{
			Obj: rp("p", "uid-1", dur(time.Millisecond)), Type: events.EventTypeUpdate,
		}); err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
	}

	if err := m.handleDelete(events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", dur(time.Millisecond)), Type: events.EventTypeDelete,
	}); err != nil {
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
	m := newTestRpMgr(t, &fakeCompiler{compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1"}}, handlers(h1, h2))

	err := m.handleUpdate(context.Background(), events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", nil), Type: events.EventTypeUpdate,
	})
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
	m := newTestRpMgr(t, &fakeCompiler{}, handlers(h1, h2))

	cancelled := false
	m.rpThreadMap["uid-1"] = &rpWatch{
		compiled: &compiler.CompiledRuntimePolicy{UID: "uid-1", ReevalInterval: dur(time.Hour)},
		cancel:   func() { cancelled = true },
	}

	if err := m.handleDelete(events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "uid-1", nil), Type: events.EventTypeDelete,
	}); err != nil {
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
		if res.UID != "uid-1" {
			t.Errorf("%s result UID = %q, want uid-1", h.name, res.UID)
		}
		if res.IPs != nil || res.Open != nil || res.Exec != nil || res.Selector != nil || res.Mode != "" {
			t.Errorf("%s delete result carries data beyond the UID: %+v", h.name, res)
		}
	}
}

func TestHandleDeleteUnknownUIDStillFansOut(t *testing.T) {
	errA := errors.New("handler a failed")
	h1 := &recordingHandler{name: "h1", rpErr: errA}
	h2 := &recordingHandler{name: "h2"}
	m := newTestRpMgr(t, &fakeCompiler{}, handlers(h1, h2))

	err := m.handleDelete(events.Event[*v1alpha1.RuntimePolicy]{
		Obj: rp("p", "never-seen", nil), Type: events.EventTypeDelete,
	})
	if !errors.Is(err, errA) {
		t.Fatalf("err = %v, want it to contain %v", err, errA)
	}
	if got := len(h2.runtimePolicyCalls()); got != 1 {
		t.Errorf("h2 got %d events, want 1", got)
	}
}
