package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
)

const maxRequeues = 5

type queueKey struct {
	Type string
	// Key is "<namespace>/<name>" for create and update, and the object UID for
	// delete.
	Key string
}

type podWatcher struct {
	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer
	lister   corev1listers.PodLister
	queue    workqueue.TypedRateLimitingInterface[queueKey]

	// namespaces are watched for their labels alone, so that a policy's
	// namespaceSelector is matched against a cache rather than by asking every
	// handler to hold its own. They need their own factory: the pod factory
	// carries a spec.nodeName field selector no namespace has.
	nsFactory  informers.SharedInformerFactory
	nsInformer cache.SharedIndexInformer
	nsLister   corev1listers.NamespaceLister

	nodeName      string
	eventHandlers []events.PodEventHandler
	nsHandlers    []events.NamespaceEventHandler
	log           logr.Logger
}

func (w *podWatcher) Start(ctx context.Context) error {
	defer w.queue.ShutDown()

	w.factory.Start(ctx.Done())
	w.nsFactory.Start(ctx.Done())

	timeOut, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	// the namespace cache is part of the same wait: a pod handled before it
	// syncs would be matched against an empty namespace label set, which reads
	// as "this policy does not select you".
	if !cache.WaitForCacheSync(timeOut.Done(), w.informer.HasSynced, w.nsInformer.HasSynced) {
		return fmt.Errorf("timed out waiting for cache sync")
	}

	go wait.Until(w.runWorker, time.Second, ctx.Done())

	<-ctx.Done()
	return nil
}

func NewPodWatcher(client kubernetes.Interface, nodeName string, eventHandlers []events.PodEventHandler, nsHandlers []events.NamespaceEventHandler) *podWatcher {
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

	nsFactory := informers.NewSharedInformerFactory(client, 0)
	namespaces := nsFactory.Core().V1().Namespaces()

	w := &podWatcher{
		factory:       factory,
		queue:         queue,
		informer:      podInformer,
		lister:        pods.Lister(),
		nsFactory:     nsFactory,
		nsInformer:    namespaces.Informer(),
		nsLister:      namespaces.Lister(),
		nodeName:      nodeName,
		eventHandlers: eventHandlers,
		nsHandlers:    nsHandlers,
		log:           ctrl.Log.WithName("podwatcher"),
	}

	// AddEventHandler only errors once the informer has stopped, which cannot
	// happen before Start.
	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(pod)
			if err != nil {
				w.log.Error(err, "cannot derive a queue key for pod", "pod", pod.Name, "namespace", pod.Namespace)
				return
			}
			w.queue.Add(queueKey{Type: events.EventTypeCreate, Key: key})
		},
		UpdateFunc: func(_, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(pod)
			if err != nil {
				w.log.Error(err, "cannot derive a queue key for pod", "pod", pod.Name, "namespace", pod.Namespace)
				return
			}
			w.queue.Add(queueKey{Type: events.EventTypeUpdate, Key: key})
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
			w.queue.Add(queueKey{Type: events.EventTypeDelete, Key: string(pod.UID)})
		},
	})

	// A relabelled namespace changes which policies select the pods inside it,
	// so those pods are replayed as ordinary updates rather than given their
	// own event type: the handlers already re-evaluate targets on an update.
	_, _ = w.nsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ns, ok := obj.(*corev1.Namespace)
			if !ok {
				return
			}
			w.fanOutNamespace(ns.Name, ns.Labels, events.EventTypeCreate)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNs, ok := oldObj.(*corev1.Namespace)
			if !ok {
				return
			}
			newNs, ok := newObj.(*corev1.Namespace)
			if !ok {
				return
			}
			if maps.Equal(oldNs.Labels, newNs.Labels) {
				return
			}
			w.fanOutNamespace(newNs.Name, newNs.Labels, events.EventTypeUpdate)
			w.requeueNamespace(newNs.Name)
		},
		DeleteFunc: func(obj interface{}) {
			ns, ok := obj.(*corev1.Namespace)
			if !ok {
				unknown, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				ns, ok = unknown.Obj.(*corev1.Namespace)
				if !ok {
					return
				}
			}
			w.fanOutNamespace(ns.Name, nil, events.EventTypeDelete)
		},
	})

	return w
}

// fanOutNamespace delivers namespace labels to the handlers that hold no pod
// state and so cannot read them off a pod event.
func (w *podWatcher) fanOutNamespace(name string, nsLabels map[string]string, evType string) {
	for _, h := range w.nsHandlers {
		if err := utils.Guard(fmt.Sprintf("%T.NamespaceEvent(%s, %s)", h, name, evType), func() error {
			h.NamespaceEvent(name, nsLabels, evType)
			return nil
		}); err != nil {
			w.log.Error(err, "namespace handler failed", "namespace", name, "type", evType)
		}
	}
}

// requeueNamespace replays every pod this node holds in the namespace. The pod
// lister is already filtered to this node, so the fan-out is bounded by the
// node's own pods rather than the cluster's.
func (w *podWatcher) requeueNamespace(namespace string) {
	pods, err := w.lister.Pods(namespace).List(labels.Everything())
	if err != nil {
		w.log.Error(err, "cannot list pods for a relabelled namespace", "namespace", namespace)
		return
	}
	w.log.V(2).Info("namespace labels changed, replaying its pods", "namespace", namespace, "pods", len(pods))
	for _, pod := range pods {
		key, err := cache.MetaNamespaceKeyFunc(pod)
		if err != nil {
			w.log.Error(err, "cannot derive a queue key for pod", "pod", pod.Name, "namespace", pod.Namespace)
			continue
		}
		w.queue.Add(queueKey{Type: events.EventTypeUpdate, Key: key})
	}
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
	// without Done the item stays in the queue's processing set and requeued
	// events are never handed out again
	defer w.queue.Done(key)

	var err error
	switch key.Type {
	case events.EventTypeCreate, events.EventTypeUpdate:
		namespace, name, keyErr := cache.SplitMetaNamespaceKey(key.Key)
		if keyErr != nil {
			w.log.Error(keyErr, "malformed queue key, dropping event", "key", key.Key)
			break
		}
		// the pod is read at processing time so a retry acts on its current
		// state rather than on the revision that was queued
		pod, getErr := w.lister.Pods(namespace).Get(name)
		if apierrors.IsNotFound(getErr) {
			w.log.V(2).Info("pod missing from the lister, dropping event", "pod", key.Key, "type", key.Type)
			break
		}
		if getErr != nil {
			err = fmt.Errorf("fetching pod %s from lister: %w", key.Key, getErr)
			break
		}
		err = w.handleCreateOrUpdate(pod, key.Type)
	case events.EventTypeDelete:
		err = w.handleDelete(key.Key)
	}

	if err != nil {
		requeues := w.queue.NumRequeues(key)
		if requeues >= maxRequeues {
			w.log.Error(err, "giving up on event after max requeues", "pod", key.Key, "type", key.Type, "requeues", requeues)
			w.queue.Forget(key)
			return true
		}
		w.queue.AddRateLimited(key)
		return true
	}

	w.queue.Forget(key)
	return true
}

// ResolveCgInfos reports partial success, so the resolved set is always handed
// to the handlers even when some containers could not be attributed.
func (w *podWatcher) handleCreateOrUpdate(pod *corev1.Pod, evType string) error {
	// A missing namespace is requeued rather than treated as an empty label
	// set: passing one on would silently unselect the pod from every policy
	// that carries a namespaceSelector.
	ns, err := w.nsLister.Get(pod.Namespace)
	if err != nil {
		return fmt.Errorf("fetching namespace %s for pod %s: %w", pod.Namespace, pod.Name, err)
	}

	cgInfos, resolveErr := containers.ResolveCgInfos(pod)
	if resolveErr != nil {
		w.log.V(2).Info("some containers of the pod could not be attributed to a cgroup",
			"pod", fmt.Sprintf("%s/%s", pod.Namespace, pod.Name), "podUid", string(pod.UID),
			"resolved", len(cgInfos), "reason", resolveErr.Error())
	}

	fanOutErr := w.fanOut(pod, ns.Labels, cgInfos, evType)

	if resolveRetryable(cgInfos, resolveErr) {
		return errors.Join(fanOutErr, resolveErr)
	}
	return fanOutErr
}

// only a total resolution failure is worth a retry, since that is what a
// container mid-creation looks like
func resolveRetryable(cgInfos []*containers.ContainerCgroupInfo, err error) bool {
	return err != nil && len(cgInfos) == 0
}

// every handler's teardown is keyed by pod UID, so the UID is all a delete
// carries
func (w *podWatcher) handleDelete(uid string) error {
	return w.dispatch(
		func(handler events.PodEventHandler) string {
			return fmt.Sprintf("%T.PodDeleted(%s)", handler, uid)
		},
		func(handler events.PodEventHandler) error {
			return handler.PodDeleted(uid)
		})
}

func (w *podWatcher) fanOut(pod *corev1.Pod, nsLabels map[string]string, cgInfos []*containers.ContainerCgroupInfo, evType string) error {
	return w.dispatch(
		func(handler events.PodEventHandler) string {
			return fmt.Sprintf("%T.PodEvent(%s/%s, %s)", handler, pod.Namespace, pod.Name, evType)
		},
		func(handler events.PodEventHandler) error {
			return handler.PodEvent(*pod, nsLabels, cgInfos, evType)
		})
}

// utils.Guard turns a panicking handler into an error on this item instead of
// taking the worker down
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
