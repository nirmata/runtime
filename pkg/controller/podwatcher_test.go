package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// pod builds a pod with no container statuses so containers.ResolveCgInfos
// resolves an empty set without touching the host cgroup filesystem.
func pod(ns, name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)},
	}
}

func newPodQueue() workqueue.TypedRateLimitingInterface[queueKey] {
	return workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[queueKey](0, 0),
	)
}

func newTestPodWatcher(t *testing.T, hs []events.PodEventHandler, seed ...*corev1.Pod) (*podWatcher, cache.Indexer) {
	t.Helper()
	client := k8sfake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, 0)
	pods := factory.Core().V1().Pods()
	for _, p := range seed {
		if err := pods.Informer().GetIndexer().Add(p); err != nil {
			t.Fatal(err)
		}
	}
	w := &podWatcher{
		factory:       factory,
		informer:      pods.Informer(),
		lister:        pods.Lister(),
		queue:         newPodQueue(),
		nodeName:      "node-1",
		eventHandlers: hs,
		log:           logr.Discard(),
	}
	t.Cleanup(w.queue.ShutDown)
	return w, pods.Informer().GetIndexer()
}

func TestPodHandleCreateFansOutToAllHandlers(t *testing.T) {
	h1 := &recordingPodHandler{name: "h1"}
	h2 := &recordingPodHandler{name: "h2"}
	w, _ := newTestPodWatcher(t, podHandlers(h1, h2))

	p := pod("ns", "p", "uid-1")
	if err := w.handleCreateOrUpdate(p, events.EventTypeCreate); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, h := range []*recordingPodHandler{h1, h2} {
		calls := h.podEventCalls()
		if len(calls) != 1 {
			t.Fatalf("%s got %d pod events, want 1", h.name, len(calls))
		}
		if calls[0].evType != events.EventTypeCreate {
			t.Errorf("%s event type = %q, want create", h.name, calls[0].evType)
		}
		if calls[0].pod.UID != p.UID {
			t.Errorf("%s pod uid = %q, want %q", h.name, calls[0].pod.UID, p.UID)
		}
		if len(calls[0].cgInfos) != 0 {
			t.Errorf("%s cgInfos = %+v, want empty for a pod with no container statuses", h.name, calls[0].cgInfos)
		}
	}
}

func TestPodHandleCreateJoinsHandlerErrors(t *testing.T) {
	errA := errors.New("handler a failed")
	errB := errors.New("handler b failed")
	h1 := &recordingPodHandler{name: "h1", podErr: errA}
	h2 := &recordingPodHandler{name: "h2", podErr: errB}
	w, _ := newTestPodWatcher(t, podHandlers(h1, h2))

	err := w.handleCreateOrUpdate(pod("ns", "p", "uid-1"), events.EventTypeCreate)
	if err == nil {
		t.Fatal("expected an aggregated error")
	}
	if !errors.Is(err, errA) {
		t.Errorf("aggregated error is missing errA: %v", err)
	}
	if !errors.Is(err, errB) {
		t.Errorf("aggregated error is missing errB: %v", err)
	}
}

func TestPodHandleUpdateFansOutAndJoinsErrors(t *testing.T) {
	errA := errors.New("handler a failed")
	h1 := &recordingPodHandler{name: "h1", podErr: errA}
	h2 := &recordingPodHandler{name: "h2"}
	w, _ := newTestPodWatcher(t, podHandlers(h1, h2))

	err := w.handleCreateOrUpdate(pod("ns", "p", "uid-1"), events.EventTypeUpdate)
	if !errors.Is(err, errA) {
		t.Fatalf("err = %v, want it to contain %v", err, errA)
	}
	calls := h2.podEventCalls()
	if len(calls) != 1 || calls[0].evType != events.EventTypeUpdate {
		t.Fatalf("h2 calls = %+v, want a single update event", calls)
	}
}

// TestPodFanOutConvertsHandlerPanicToError pins the panic barrier: a handler
// that panics must not take the informer worker down with it, it must surface
// as an error on the work item like any other failure.
func TestPodFanOutConvertsHandlerPanicToError(t *testing.T) {
	boom := &recordingPodHandler{name: "boom", podPanic: "handler exploded"}
	healthy := &recordingPodHandler{name: "healthy"}
	w, _ := newTestPodWatcher(t, podHandlers(boom, healthy))

	err := w.handleCreateOrUpdate(pod("ns", "p", "uid-1"), events.EventTypeCreate)
	if err == nil {
		t.Fatal("a panicking handler produced no error")
	}
	if !errors.Is(err, utils.ErrPanic) {
		t.Errorf("err = %v, want it to wrap utils.ErrPanic", err)
	}
	// the panic must not have stopped the other handler from being called
	if got := len(healthy.podEventCalls()); got != 1 {
		t.Errorf("healthy handler got %d events, want 1", got)
	}
}

// TestPodDeleteFanOutConvertsHandlerPanicToError is the same barrier on the
// delete path, which dispatches PodDeleted rather than PodEvent.
func TestPodDeleteFanOutConvertsHandlerPanicToError(t *testing.T) {
	boom := &recordingPodHandler{name: "boom", podPanic: "handler exploded"}
	healthy := &recordingPodHandler{name: "healthy"}
	w, _ := newTestPodWatcher(t, podHandlers(boom, healthy))

	err := w.handleDelete("uid-1")
	if err == nil {
		t.Fatal("a panicking handler produced no error")
	}
	if !errors.Is(err, utils.ErrPanic) {
		t.Errorf("err = %v, want it to wrap utils.ErrPanic", err)
	}
	if got := len(healthy.podDeletedCalls()); got != 1 {
		t.Errorf("healthy handler got %d deletes, want 1", got)
	}
}

// TestPodProcessNextWorkItemSurvivesHandlerPanic drives the panic through the
// worker loop: the item is requeued and the worker keeps running.
func TestPodProcessNextWorkItemSurvivesHandlerPanic(t *testing.T) {
	boom := &recordingPodHandler{name: "boom", podPanic: errors.New("handler exploded")}
	p := pod("ns", "p", "uid-1")
	w, _ := newTestPodWatcher(t, podHandlers(boom), p)

	w.queue.Add(queueKey{Type: events.EventTypeCreate, Key: "ns/p"})
	if !w.processNextWorkItem() {
		t.Fatal("processNextWorkItem returned false after a handler panic")
	}
	if got := w.queue.Len(); got != 1 {
		t.Fatalf("queue len = %d, want the item requeued after the panic", got)
	}
}

// TestPodHandleDeleteFansOutUIDToAllHandlers: deletes deliver the UID and
// nothing else, through PodDeleted rather than PodEvent.
func TestPodHandleDeleteFansOutUIDToAllHandlers(t *testing.T) {
	h1 := &recordingPodHandler{name: "h1"}
	h2 := &recordingPodHandler{name: "h2"}
	w, _ := newTestPodWatcher(t, podHandlers(h1, h2))

	if err := w.handleDelete("uid-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, h := range []*recordingPodHandler{h1, h2} {
		deletes := h.podDeletedCalls()
		if len(deletes) != 1 {
			t.Fatalf("%s got %d deletes, want 1", h.name, len(deletes))
		}
		if deletes[0] != "uid-1" {
			t.Errorf("%s deleted uid = %q, want uid-1", h.name, deletes[0])
		}
		if got := len(h.podEventCalls()); got != 0 {
			t.Errorf("%s got %d pod events for a delete, want 0", h.name, got)
		}
	}
}

// nextKey returns the next item the queue hands out, failing the test rather
// than blocking forever when nothing is queued.
func nextKey(t *testing.T, q workqueue.TypedRateLimitingInterface[queueKey]) queueKey {
	t.Helper()
	got := make(chan queueKey, 1)
	go func() {
		k, shutdown := q.Get()
		if shutdown {
			return
		}
		q.Done(k)
		got <- k
	}()
	select {
	case k := <-got:
		return k
	case <-time.After(10 * time.Second):
		t.Fatal("nothing was queued")
		return queueKey{}
	}
}

// TestPodInformerQueuesKeysByEventType drives the informer's own callbacks:
// creates and updates queue the namespaced key, deletes queue the pod UID
// because the lister cannot serve the object by the time the worker runs.
func TestPodInformerQueuesKeysByEventType(t *testing.T) {
	client := k8sfake.NewSimpleClientset(pod("ns", "p", "uid-1"))
	w := NewPodWatcher(client, "node-1", nil)
	t.Cleanup(w.queue.ShutDown)

	stop := make(chan struct{})
	defer close(stop)
	w.factory.Start(stop)
	if !cache.WaitForCacheSync(stop, w.informer.HasSynced) {
		t.Fatal("informer never synced")
	}

	want := queueKey{Type: events.EventTypeCreate, Key: "ns/p"}
	if got := nextKey(t, w.queue); got != want {
		t.Errorf("queued key = %+v, want %+v", got, want)
	}

	if err := client.CoreV1().Pods("ns").Delete(context.Background(), "p", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	want = queueKey{Type: events.EventTypeDelete, Key: "uid-1"}
	if got := nextKey(t, w.queue); got != want {
		t.Errorf("queued key = %+v, want %+v", got, want)
	}
}

// TestPodProcessNextWorkItemFetchesObjectFromLister is the other half of the
// stable-key design: the queue carries only a key, so the object handlers see
// is whatever the lister holds at processing time.
func TestPodProcessNextWorkItemFetchesObjectFromLister(t *testing.T) {
	current := pod("ns", "p", "uid-1")
	current.Labels = map[string]string{"app": "fresh"}
	h := &recordingPodHandler{name: "h"}
	w, _ := newTestPodWatcher(t, podHandlers(h), current)

	w.queue.Add(queueKey{Type: events.EventTypeUpdate, Key: "ns/p"})
	if !w.processNextWorkItem() {
		t.Fatal("processNextWorkItem returned false")
	}

	calls := h.podEventCalls()
	if len(calls) != 1 {
		t.Fatalf("handler got %d events, want 1", len(calls))
	}
	if got := calls[0].pod.Labels["app"]; got != "fresh" {
		t.Errorf("pod labels[app] = %q, want the lister's object (%q)", got, "fresh")
	}
}

func TestPodProcessNextWorkItemRequeuesThenDrops(t *testing.T) {
	h := &recordingPodHandler{name: "h", podErr: errors.New("handler boom")}
	p := pod("ns", "p", "uid-1")
	w, _ := newTestPodWatcher(t, podHandlers(h), p)

	key := queueKey{Type: events.EventTypeCreate, Key: "ns/p"}
	w.queue.Add(key)

	for i := 0; i < maxRequeues; i++ {
		if got := w.queue.NumRequeues(key); got != i {
			t.Fatalf("iteration %d: NumRequeues = %d, want %d", i, got, i)
		}
		if !w.processNextWorkItem() {
			t.Fatalf("iteration %d: processNextWorkItem returned false", i)
		}
		if got := w.queue.Len(); got != 1 {
			t.Fatalf("iteration %d: queue len = %d, want the item requeued", i, got)
		}
	}

	if !w.processNextWorkItem() {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := w.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the item dropped after %d requeues", got, maxRequeues)
	}
	if got := w.queue.NumRequeues(key); got != 0 {
		t.Fatalf("NumRequeues after Forget = %d, want 0", got)
	}
	if got := len(h.podEventCalls()); got != maxRequeues+1 {
		t.Fatalf("handler was called %d times, want %d (the initial attempt plus %d requeues)",
			got, maxRequeues+1, maxRequeues)
	}
}

// TestPodRequeueCapSurvivesPointerChange pins the requeue cap for the pod
// queue: the lister returns a different pod pointer on every attempt, the way
// an informer resync or a mid-retry update does, and retries must still be
// bounded.
func TestPodRequeueCapSurvivesPointerChange(t *testing.T) {
	h := &recordingPodHandler{name: "h", podErr: errors.New("handler boom")}
	w, indexer := newTestPodWatcher(t, podHandlers(h), pod("ns", "p", "uid-1"))

	key := queueKey{Type: events.EventTypeCreate, Key: "ns/p"}
	w.queue.Add(key)

	seen := map[*corev1.Pod]struct{}{}
	for i := 0; i < maxRequeues; i++ {
		if got := w.queue.NumRequeues(key); got != i {
			t.Fatalf("attempt %d: NumRequeues = %d, want %d; the cap is counting revisions, not retries", i, got, i)
		}
		if !w.processNextWorkItem() {
			t.Fatalf("attempt %d: processNextWorkItem returned false", i)
		}
		if got := w.queue.Len(); got != 1 {
			t.Fatalf("attempt %d: queue len = %d, want the item requeued", i, got)
		}

		// swap in a brand new pointer with the same identity, the way a resync
		// or a concurrent update would
		fresh := pod("ns", "p", "uid-1")
		fresh.ResourceVersion = string(rune('a' + i))
		if err := indexer.Update(fresh); err != nil {
			t.Fatal(err)
		}
		seen[fresh] = struct{}{}
	}

	if len(seen) != maxRequeues {
		t.Fatalf("the test did not actually change the lister's pointer: %d distinct objects", len(seen))
	}

	// the cap must still fire even though the object changed on every attempt
	if !w.processNextWorkItem() {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := w.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the item dropped after %d requeues despite the pointer churn", got, maxRequeues)
	}
	if got := len(h.podEventCalls()); got != maxRequeues+1 {
		t.Fatalf("handler was called %d times, want %d; retries are not bounded", got, maxRequeues+1)
	}

	// every attempt handled the object the lister held at that moment
	pointers := map[string]struct{}{}
	for _, c := range h.podEventCalls() {
		pointers[c.pod.ResourceVersion] = struct{}{}
	}
	if len(pointers) < 2 {
		t.Errorf("handler only ever saw %d distinct revisions, so the lister fetch is not happening at processing time", len(pointers))
	}
}

func TestPodProcessNextWorkItemListerMissDropsEvent(t *testing.T) {
	h := &recordingPodHandler{name: "h", podErr: errors.New("handler boom")}
	w, _ := newTestPodWatcher(t, podHandlers(h))

	key := queueKey{Type: events.EventTypeCreate, Key: "ns/gone"}
	w.queue.Add(key)

	if !w.processNextWorkItem() {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := w.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the event dropped on a lister miss", got)
	}
	if got := w.queue.NumRequeues(key); got != 0 {
		t.Fatalf("NumRequeues = %d, want the event forgotten", got)
	}
	if got := len(h.podEventCalls()); got != 0 {
		t.Fatalf("handler was called %d times for a pod missing from the lister, want 0", got)
	}
}

// TestPodDeleteUIDSurvivesRequeues checks that a requeued delete still reaches
// the handlers with its UID, which the lister cannot supply.
func TestPodDeleteUIDSurvivesRequeues(t *testing.T) {
	h := &recordingPodHandler{name: "h", podErr: errors.New("handler boom")}
	w, _ := newTestPodWatcher(t, podHandlers(h))

	key := queueKey{Type: events.EventTypeDelete, Key: "uid-1"}
	w.queue.Add(key)

	if !w.processNextWorkItem() {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := w.queue.Len(); got != 1 {
		t.Fatalf("queue len = %d, want the delete requeued", got)
	}

	// let it succeed this time
	h.podErr = nil
	if !w.processNextWorkItem() {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := w.queue.NumRequeues(key); got != 0 {
		t.Errorf("NumRequeues = %d, want the item forgotten", got)
	}
	deletes := h.podDeletedCalls()
	if len(deletes) != 2 {
		t.Fatalf("handler got %d deletes, want 2 (one failed, one successful)", len(deletes))
	}
	for i, uid := range deletes {
		if uid != "uid-1" {
			t.Errorf("delete %d carried uid %q, want uid-1", i, uid)
		}
	}
}

func TestPodProcessNextWorkItemForgetsOnSuccessAndDispatchesByType(t *testing.T) {
	p := pod("ns", "p", "uid-1")
	h := &recordingPodHandler{name: "h"}
	w, _ := newTestPodWatcher(t, podHandlers(h), p)

	w.queue.Add(queueKey{Type: events.EventTypeCreate, Key: "ns/p"})
	w.queue.Add(queueKey{Type: events.EventTypeUpdate, Key: "ns/p"})
	w.queue.Add(queueKey{Type: events.EventTypeDelete, Key: "uid-1"})

	for i := 0; i < 3; i++ {
		if !w.processNextWorkItem() {
			t.Fatalf("iteration %d: processNextWorkItem returned false", i)
		}
	}
	if got := w.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want 0", got)
	}

	var got []string
	for _, c := range h.podEventCalls() {
		got = append(got, c.evType)
	}
	want := []string{events.EventTypeCreate, events.EventTypeUpdate}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("dispatched event types mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"uid-1"}, h.podDeletedCalls()); diff != "" {
		t.Errorf("dispatched deletes mismatch (-want +got):\n%s", diff)
	}
}

func TestPodProcessNextWorkItemReturnsFalseAfterShutdown(t *testing.T) {
	w, _ := newTestPodWatcher(t, nil)
	w.queue.ShutDown()
	if w.processNextWorkItem() {
		t.Fatal("processNextWorkItem must return false once the queue is shut down")
	}
}

// containers.ResolveCgInfos reports partial success, so a failure that still
// yielded cgroups must not be retryable and the partial result must not be
// discarded.
func TestResolveRetryableOnlyWhenNothingResolved(t *testing.T) {
	boom := errors.New("one container is not started yet")
	partial := []*containers.ContainerCgroupInfo{{ID: 1, Path: "/sys/fs/cgroup/a", Name: "c1"}}

	tests := []struct {
		name    string
		cgInfos []*containers.ContainerCgroupInfo
		err     error
		want    bool
	}{
		{name: "clean resolve", cgInfos: partial, err: nil, want: false},
		{name: "nothing resolved and no error", cgInfos: nil, err: nil, want: false},
		{name: "partial success keeps the result and does not requeue", cgInfos: partial, err: boom, want: false},
		{name: "total failure is retryable", cgInfos: nil, err: boom, want: true},
		{name: "empty non-nil slice with error is retryable", cgInfos: []*containers.ContainerCgroupInfo{}, err: boom, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveRetryable(tc.cgInfos, tc.err); got != tc.want {
				t.Errorf("resolveRetryable(%d infos, err=%v) = %v, want %v", len(tc.cgInfos), tc.err, got, tc.want)
			}
		})
	}
}

// TestPodHandleCreateOrUpdateFansOutPartialCgInfos proves the partial result
// reaches the handlers rather than being dropped on the floor with the error.
func TestPodHandleCreateOrUpdateFansOutPartialCgInfos(t *testing.T) {
	h := &recordingPodHandler{name: "h"}
	w, _ := newTestPodWatcher(t, podHandlers(h))

	partial := []*containers.ContainerCgroupInfo{{ID: 7, Path: "/sys/fs/cgroup/x", Name: "c1"}}
	if err := w.fanOut(pod("ns", "p", "uid-1"), partial, events.EventTypeCreate); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calls := h.podEventCalls()
	if len(calls) != 1 {
		t.Fatalf("handler got %d events, want 1", len(calls))
	}
	if diff := cmp.Diff(partial, calls[0].cgInfos); diff != "" {
		t.Errorf("cgInfos mismatch (-want +got):\n%s", diff)
	}
}

// TestPodUnresolvableContainerIsRetried covers the retryable branch end to end:
// a pod whose only container reports an unresolvable id resolves nothing, so the
// event is requeued rather than silently accepted.
func TestPodUnresolvableContainerIsRetried(t *testing.T) {
	p := pod("ns", "p", "uid-1")
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "c1", ContainerID: ""}}
	h := &recordingPodHandler{name: "h"}
	w, _ := newTestPodWatcher(t, podHandlers(h), p)

	err := w.handleCreateOrUpdate(p, events.EventTypeCreate)
	if err == nil {
		t.Fatal("a pod with no resolvable containers produced no error, so the event would never be retried")
	}
	// the handlers still saw the event, with an empty set
	calls := h.podEventCalls()
	if len(calls) != 1 {
		t.Fatalf("handler got %d events, want 1", len(calls))
	}
	if len(calls[0].cgInfos) != 0 {
		t.Errorf("cgInfos = %+v, want empty", calls[0].cgInfos)
	}
}
