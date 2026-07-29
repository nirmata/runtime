package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
)

// maxRequeues bounds retries of a single logical queue item. Because both
// queues key on a stable queueKey rather than on the object itself, the
// cap counts retries of the item and no longer resets when the object the
// lister hands back changes between attempts.
const maxRequeues = 5

// queueKey identifies a logical work item. It deliberately carries no object
// pointer: objects are fetched from the lister at processing time and deletes
// are served from a key-to-UID map, so NumRequeues counts retries of the item
// rather than retries of one particular revision of it.
type queueKey struct {
	// Type is one of events.EventTypeCreate|Update|Delete.
	Type string
	// Key is "<namespace>/<name>" for namespaced objects and "<name>" for
	// cluster-scoped ones.
	Key string
}

func (k queueKey) String() string { return k.Type + " " + k.Key }

type podWatcher struct {
	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer
	lister   corev1listers.PodLister
	queue    workqueue.TypedRateLimitingInterface[queueKey]

	// mu guards deletedUIDs, which is written by the informer's handler
	// goroutine and read by the worker.
	mu sync.Mutex
	// deletedUIDs maps the informer key ("ns/name") of a queued delete to the
	// pod's UID. Handlers only need the UID on delete, and the lister no
	// longer holds the object by the time the worker picks the key up.
	deletedUIDs map[string]string

	nodeName      string
	eventHandlers []events.PodEventHandler
	log           logr.Logger
}

func (w *podWatcher) Start(ctx context.Context) error {
	defer w.queue.ShutDown()

	w.factory.Start(ctx.Done())

	timeOut, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	if !cache.WaitForCacheSync(timeOut.Done(), w.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for cache sync")
	}

	go wait.Until(w.runWorker, time.Second, ctx.Done())

	<-ctx.Done()
	return nil
}

func NewPodWatcher(client kubernetes.Interface, nodeName string, eventHandlers []events.PodEventHandler) *podWatcher {
	factory := informers.NewSharedInformerFactoryWithOptions(
		client,
		0,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fmt.Sprintf(
				"spec.nodeName=%s,status.phase=Running",
				nodeName,
			)
		}),
	)

	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[queueKey](),
	)

	pods := factory.Core().V1().Pods()
	podInformer := pods.Informer()

	w := &podWatcher{
		factory:       factory,
		queue:         queue,
		informer:      podInformer,
		lister:        pods.Lister(),
		nodeName:      nodeName,
		eventHandlers: eventHandlers,
		deletedUIDs:   make(map[string]string),
		log:           ctrl.Log.WithName("podwatcher"),
	}

	// AddEventHandler only errors if the informer has already stopped, which
	// cannot happen here since it hasn't been started yet.
	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			w.enqueue(pod, events.EventTypeCreate)
		},
		UpdateFunc: func(_, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			w.enqueue(pod, events.EventTypeUpdate)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				// handle cache.DeletedFinalStateUnknown
				unknown, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				pod, ok = unknown.Obj.(*corev1.Pod)
				if !ok {
					return
				}
			}
			w.enqueue(pod, events.EventTypeDelete)
		},
	})

	return w
}

// enqueue converts an informer notification into a stable queueKey. Delete
// notifications additionally record the pod's UID, since the object is gone
// from the lister by the time the worker picks the key up and the UID is all
// the handlers need on delete.
func (w *podWatcher) enqueue(pod *corev1.Pod, evType string) {
	key, err := cache.MetaNamespaceKeyFunc(pod)
	if err != nil {
		w.log.Error(err, "cannot derive a queue key for pod", "pod", pod.Name, "namespace", pod.Namespace)
		return
	}
	if evType == events.EventTypeDelete {
		w.mu.Lock()
		w.deletedUIDs[key] = string(pod.UID)
		w.mu.Unlock()
	}
	w.queue.Add(queueKey{Type: evType, Key: key})
}

func (w *podWatcher) deletedUID(key string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.deletedUIDs[key]
}

// dropDeletedUID releases a recorded delete UID. It is only called once the
// item leaves the queue for good (handled or given up on), so requeued
// deletes can still find their UID.
func (w *podWatcher) dropDeletedUID(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.deletedUIDs, key)
}

func (w *podWatcher) runWorker() {
	for w.processNextWorkItem() {
	}
}

func (w *podWatcher) processNextWorkItem() bool {
	key, shutdown := w.queue.Get()
	if shutdown {
		return false
	}
	// without Done the item stays in the queue's processing set forever, which
	// means requeued events are never handed out again
	defer w.queue.Done(key)

	err := w.handle(key)
	if err != nil {
		requeues := w.queue.NumRequeues(key)
		// don't try the same logical item more than maxRequeues times. the key
		// is stable, so this cap holds even when the lister returns a
		// different object between attempts.
		if requeues >= maxRequeues {
			w.log.Error(err, "giving up on event after max requeues", "pod", key.Key, "type", key.Type, "requeues", requeues)
			w.forget(key)
			return true
		}
		w.queue.AddRateLimited(key)
		return true
	}

	w.forget(key)
	return true
}

// forget drops the item's rate limiter history and any delete UID it owned.
func (w *podWatcher) forget(key queueKey) {
	w.queue.Forget(key)
	if key.Type == events.EventTypeDelete {
		w.dropDeletedUID(key.Key)
	}
}

func (w *podWatcher) handle(key queueKey) error {
	if key.Type == events.EventTypeDelete {
		uid := w.deletedUID(key.Key)
		if uid == "" {
			// nothing to tell handlers about
			w.log.V(2).Info("no recorded UID for deleted pod, dropping event", "pod", key.Key)
			return nil
		}
		return w.handleDelete(uid)
	}

	namespace, name, err := cache.SplitMetaNamespaceKey(key.Key)
	if err != nil {
		w.log.Error(err, "malformed queue key, dropping event", "key", key.Key)
		return nil
	}

	// the object is always read from the lister at processing time so a retry
	// acts on the current state of the pod rather than on the revision that
	// happened to be queued
	pod, err := w.lister.Pods(namespace).Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// the pod is gone; its delete event carries the teardown
			w.log.V(2).Info("pod no longer in the lister, dropping event", "pod", key.Key, "type", key.Type)
			return nil
		}
		return fmt.Errorf("fetching pod %s from lister: %w", key.Key, err)
	}

	return w.handleCreateOrUpdate(pod, key.Type)
}

// handleCreateOrUpdate resolves the pod's cgroups and fans the event out.
//
// ResolveCgInfos returns partial results alongside an errors.Join of the
// containers it could not resolve, so the partial set is always handed to the
// handlers. A resolution failure is only retryable when nothing at all could
// be resolved (containers that are still being created); once anything
// resolved, an unattributable sibling container is logged at V(0) and left
// alone rather than driving the whole pod event through five retries.
func (w *podWatcher) handleCreateOrUpdate(pod *corev1.Pod, evType string) error {
	cgInfos, resolveErr := containers.ResolveCgInfos(pod)
	if resolveErr != nil {
		w.log.V(0).Info("some containers of the pod could not be attributed to a cgroup",
			"pod", fmt.Sprintf("%s/%s", pod.Namespace, pod.Name), "podUid", string(pod.UID),
			"resolved", len(cgInfos), "reason", resolveErr.Error())
	}

	fanOutErr := w.fanOut(pod, cgInfos, evType)

	if resolveRetryable(cgInfos, resolveErr) {
		return errors.Join(fanOutErr, resolveErr)
	}
	return fanOutErr
}

// resolveRetryable decides whether a containers.ResolveCgInfos failure should
// requeue the pod event. ResolveCgInfos reports partial success, so a failure
// alongside resolved containers is informational: the pod is attributed, one of
// its containers simply is not, and retrying the whole event five times will
// not change that. Only a total failure (nothing resolved at all) is worth a
// retry, since that is what a container mid-creation looks like.
func resolveRetryable(cgInfos []*containers.ContainerCgroupInfo, err error) bool {
	return err != nil && len(cgInfos) == 0
}

// handleDelete announces the deletion to every handler. Only the UID is
// delivered: every handler's teardown is keyed by pod UID, and a synthesized
// object would invite reads of fields that are empty only on this path.
func (w *podWatcher) handleDelete(uid string) error {
	return w.dispatch(
		func(handler events.PodEventHandler) string {
			return fmt.Sprintf("%T.PodDeleted(%s)", handler, uid)
		},
		func(handler events.PodEventHandler) error {
			return handler.PodDeleted(uid)
		})
}

// fanOut delivers a create or update to every handler.
func (w *podWatcher) fanOut(pod *corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, evType string) error {
	return w.dispatch(
		func(handler events.PodEventHandler) string {
			return fmt.Sprintf("%T.PodEvent(%s/%s, %s)", handler, pod.Namespace, pod.Name, evType)
		},
		func(handler events.PodEventHandler) error {
			return handler.PodEvent(*pod, cgInfos, evType)
		})
}

// dispatch runs call against every handler concurrently. Each call is wrapped
// in utils.Guard: a panicking handler becomes an error on this item instead of
// taking the informer worker down with it.
func (w *podWatcher) dispatch(describe func(events.PodEventHandler) string, call func(events.PodEventHandler) error) error {
	errChan := make(chan error, len(w.eventHandlers))
	var wg sync.WaitGroup
	wg.Add(len(w.eventHandlers))
	for _, e := range w.eventHandlers {
		go func(handler events.PodEventHandler) {
			defer wg.Done()
			if err := utils.Guard(describe(handler), func() error {
				return call(handler)
			}); err != nil {
				errChan <- err
			}
		}(e)
	}
	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
