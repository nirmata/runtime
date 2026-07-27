package controller

import (
	"errors"
	"reflect"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
)

// pod builds a pod with no container statuses so containers.ResolveCgInfos
// resolves an empty set without touching the host cgroup filesystem.
func pod(ns, name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)},
	}
}

func newTestPodWatcher(t *testing.T, hs []events.EventIface, seed ...*corev1.Pod) *podWatcher {
	t.Helper()
	client := k8sfake.NewSimpleClientset()
	factory := informers.NewSharedInformerFactory(client, 0)
	podInformer := factory.Core().V1().Pods()
	for _, p := range seed {
		if err := podInformer.Informer().GetIndexer().Add(p); err != nil {
			t.Fatal(err)
		}
	}
	w := &podWatcher{
		factory:       factory,
		informer:      podInformer.Informer(),
		podCgInfos:    make(map[string][]*containers.ContainerCgroupInfo),
		queue:         workqueue.NewTypedRateLimitingQueue(workqueue.NewTypedItemExponentialFailureRateLimiter[events.Event[*corev1.Pod]](0, 0)),
		nodeName:      "node-1",
		eventHandlers: hs,
		log:           logr.Discard(),
	}
	t.Cleanup(w.queue.ShutDown)
	return w
}

func TestPodHandleCreateFansOutToAllHandlers(t *testing.T) {
	h1 := &recordingHandler{name: "h1"}
	h2 := &recordingHandler{name: "h2"}
	w := newTestPodWatcher(t, handlers(h1, h2))

	p := pod("ns", "p", "uid-1")
	if err := w.handleCreate(events.Event[*corev1.Pod]{Obj: p, Type: events.EventTypeCreate}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, h := range []*recordingHandler{h1, h2} {
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
	// nothing resolved means nothing is stashed
	if len(w.podCgInfos) != 0 {
		t.Errorf("podCgInfos = %+v, want empty", w.podCgInfos)
	}
}

func TestPodHandleCreateJoinsHandlerErrors(t *testing.T) {
	errA := errors.New("handler a failed")
	errB := errors.New("handler b failed")
	h1 := &recordingHandler{name: "h1", podErr: errA}
	h2 := &recordingHandler{name: "h2", podErr: errB}
	w := newTestPodWatcher(t, handlers(h1, h2))

	err := w.handleCreate(events.Event[*corev1.Pod]{Obj: pod("ns", "p", "uid-1"), Type: events.EventTypeCreate})
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
	h1 := &recordingHandler{name: "h1", podErr: errA}
	h2 := &recordingHandler{name: "h2"}
	w := newTestPodWatcher(t, handlers(h1, h2))

	err := w.handleUpdate(events.Event[*corev1.Pod]{Obj: pod("ns", "p", "uid-1"), Type: events.EventTypeUpdate})
	if !errors.Is(err, errA) {
		t.Fatalf("err = %v, want it to contain %v", err, errA)
	}
	calls := h2.podEventCalls()
	if len(calls) != 1 || calls[0].evType != events.EventTypeUpdate {
		t.Fatalf("h2 calls = %+v, want a single update event", calls)
	}
}

func TestPodHandleDeleteUsesStashedCgInfosAndClearsThem(t *testing.T) {
	h1 := &recordingHandler{name: "h1"}
	h2 := &recordingHandler{name: "h2"}
	w := newTestPodWatcher(t, handlers(h1, h2))

	stashed := []*containers.ContainerCgroupInfo{
		{ID: 111, Path: "/sys/fs/cgroup/a"},
		{ID: 222, Path: "/sys/fs/cgroup/b"},
	}
	w.podCgInfos["uid-1"] = stashed
	w.podCgInfos["uid-2"] = []*containers.ContainerCgroupInfo{{ID: 333, Path: "/sys/fs/cgroup/c"}}

	p := pod("ns", "p", "uid-1")
	if err := w.handleDelete(events.Event[*corev1.Pod]{Obj: p, Type: events.EventTypeDelete}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, h := range []*recordingHandler{h1, h2} {
		calls := h.podEventCalls()
		if len(calls) != 1 {
			t.Fatalf("%s got %d pod events, want 1", h.name, len(calls))
		}
		if calls[0].evType != events.EventTypeDelete {
			t.Errorf("%s event type = %q, want delete", h.name, calls[0].evType)
		}
		if !reflect.DeepEqual(calls[0].cgInfos, stashed) {
			t.Errorf("%s cgInfos = %+v, want the stashed infos %+v", h.name, calls[0].cgInfos, stashed)
		}
	}

	if _, ok := w.podCgInfos["uid-1"]; ok {
		t.Error("the stash entry for the deleted pod was not removed")
	}
	if _, ok := w.podCgInfos["uid-2"]; !ok {
		t.Error("the stash entry for an unrelated pod was removed")
	}
}

func TestPodHandleDeleteWithNoStashedCgInfos(t *testing.T) {
	h := &recordingHandler{name: "h"}
	w := newTestPodWatcher(t, handlers(h))

	if err := w.handleDelete(events.Event[*corev1.Pod]{Obj: pod("ns", "p", "unknown"), Type: events.EventTypeDelete}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calls := h.podEventCalls()
	if len(calls) != 1 {
		t.Fatalf("handler got %d pod events, want 1", len(calls))
	}
	if calls[0].cgInfos != nil {
		t.Errorf("cgInfos = %+v, want nil for a pod that was never stashed", calls[0].cgInfos)
	}
}

func TestPodProcessNextWorkItemRequeuesThenDrops(t *testing.T) {
	h := &recordingHandler{name: "h", podErr: errors.New("handler boom")}
	w := newTestPodWatcher(t, handlers(h))

	ev := events.Event[*corev1.Pod]{Obj: pod("ns", "p", "uid-1"), Type: events.EventTypeCreate}
	w.queue.Add(ev)

	for i := 0; i < 5; i++ {
		if got := w.queue.NumRequeues(ev); got != i {
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
		t.Fatalf("queue len = %d, want the item dropped after 5 requeues", got)
	}
	if got := w.queue.NumRequeues(ev); got != 0 {
		t.Fatalf("NumRequeues after Forget = %d, want 0", got)
	}
}

func TestPodProcessNextWorkItemUpdateRefetchesFromLister(t *testing.T) {
	current := pod("ns", "p", "uid-1")
	current.Status.Phase = corev1.PodRunning
	h := &recordingHandler{name: "h", podErr: errors.New("handler boom")}
	w := newTestPodWatcher(t, handlers(h), current)

	stale := pod("ns", "p", "uid-1")
	w.queue.Add(events.Event[*corev1.Pod]{Obj: stale, Type: events.EventTypeUpdate})

	if !w.processNextWorkItem() {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := w.queue.Len(); got != 1 {
		t.Fatalf("queue len = %d, want the update requeued", got)
	}
	requeued, _ := w.queue.Get()
	if requeued.Obj != current {
		t.Errorf("requeued pod = %p, want the lister pod %p", requeued.Obj, current)
	}
}

func TestPodProcessNextWorkItemUpdateListerMissDropsEvent(t *testing.T) {
	h := &recordingHandler{name: "h", podErr: errors.New("handler boom")}
	w := newTestPodWatcher(t, handlers(h))

	ev := events.Event[*corev1.Pod]{Obj: pod("ns", "gone", "uid-1"), Type: events.EventTypeUpdate}
	w.queue.Add(ev)

	if !w.processNextWorkItem() {
		t.Fatal("processNextWorkItem returned false")
	}
	if got := w.queue.Len(); got != 0 {
		t.Fatalf("queue len = %d, want the event dropped on a lister miss", got)
	}
	if got := w.queue.NumRequeues(ev); got != 0 {
		t.Fatalf("NumRequeues = %d, want the event forgotten", got)
	}
}

func TestPodProcessNextWorkItemForgetsOnSuccessAndDispatchesByType(t *testing.T) {
	h := &recordingHandler{name: "h"}
	w := newTestPodWatcher(t, handlers(h))

	for _, evType := range []string{events.EventTypeCreate, events.EventTypeUpdate, events.EventTypeDelete} {
		w.queue.Add(events.Event[*corev1.Pod]{Obj: pod("ns", "p", "uid-1"), Type: evType})
		if !w.processNextWorkItem() {
			t.Fatalf("%s: processNextWorkItem returned false", evType)
		}
		if got := w.queue.Len(); got != 0 {
			t.Fatalf("%s: queue len = %d, want 0", evType, got)
		}
	}

	calls := h.podEventCalls()
	if len(calls) != 3 {
		t.Fatalf("handler got %d events, want 3", len(calls))
	}
	want := []string{events.EventTypeCreate, events.EventTypeUpdate, events.EventTypeDelete}
	for i, c := range calls {
		if c.evType != want[i] {
			t.Errorf("call %d type = %q, want %q", i, c.evType, want[i])
		}
	}
}

func TestPodProcessNextWorkItemReturnsFalseAfterShutdown(t *testing.T) {
	w := newTestPodWatcher(t, nil)
	w.queue.ShutDown()
	if w.processNextWorkItem() {
		t.Fatal("processNextWorkItem must return false once the queue is shut down")
	}
}
