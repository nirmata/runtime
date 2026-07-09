package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
)

type podWatcher struct {
	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer
	// we store pod cgroup infos here as well to avoid any case of pods being
	// deleted and we are unable to retrieve their cgroup infos
	podCgInfos map[string][]*containers.ContainerCgroupInfo
	queue      workqueue.TypedRateLimitingInterface[events.Event[*corev1.Pod]]

	nodeName      string
	eventHandlers []events.EventIface
	log           logr.Logger
}

func (w *podWatcher) Start(ctx context.Context) error {
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

func NewPodWatcher(client kubernetes.Interface, nodeName string, eventHandlers []events.EventIface) *podWatcher {
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
		workqueue.DefaultTypedControllerRateLimiter[events.Event[*corev1.Pod]](),
	)

	podInformer := factory.Core().V1().Pods().Informer()
	podCgInfos := make(map[string][]*containers.ContainerCgroupInfo)

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			queue.Add(events.Event[*corev1.Pod]{Obj: pod, Type: events.EventTypeCreate})
		},
		UpdateFunc: func(_, new interface{}) {
			pod, ok := new.(*corev1.Pod)
			if !ok {
				return
			}
			queue.Add(events.Event[*corev1.Pod]{Obj: pod, Type: events.EventTypeUpdate})
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				// handle cache.DeletedFinalStateUnknown
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				pod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					return
				}
			}
			queue.Add(events.Event[*corev1.Pod]{Obj: pod, Type: events.EventTypeDelete})
		},
	})

	w := &podWatcher{
		factory:       factory,
		queue:         queue,
		informer:      podInformer,
		nodeName:      nodeName,
		eventHandlers: eventHandlers,
		podCgInfos:    podCgInfos,
		log:           ctrl.Log.WithName("podwatcher"),
	}

	return w
}

func (w *podWatcher) runWorker() {
	for w.processNextWorkItem() {
	}
}

func (w *podWatcher) processNextWorkItem() bool {
	ev, shutdown := w.queue.Get()
	if shutdown {
		return false
	}

	var err error

	switch ev.Type {
	case events.EventTypeCreate:
		err = w.handleCreate(ev)
	case events.EventTypeUpdate:
		err = w.handleUpdate(ev)
	case events.EventTypeDelete:
		err = w.handleDelete(ev)
	}

	if err != nil {
		requeues := w.queue.NumRequeues(ev)
		// don't try the same event more than 5 times
		if requeues >= 5 {
			w.log.Error(err, "giving up on event after max requeues", "pod", fmt.Sprintf("%s/%s", ev.Obj.Namespace, ev.Obj.Name), "type", ev.Type, "requeues", requeues)
			w.queue.Forget(ev)
			return true
		}

		// we need to ensure that we are getting the latest pod during requeuing updates
		// because the pod object's status is what gets used to determine the container ids
		if ev.Type == events.EventTypeUpdate {
			current, fetchErr := w.factory.Core().V1().Pods().Lister().Pods(ev.Obj.Namespace).Get(ev.Obj.Name)
			if fetchErr != nil {
				w.log.Error(fetchErr, "failed to fetch latest pod from lister, giving up on update", "pod", fmt.Sprintf("%s/%s", ev.Obj.Namespace, ev.Obj.Name))
				w.queue.Forget(ev)
				return true
			}
			ev.Obj = current
			w.queue.AddRateLimited(ev)
			return true
		} else {
			w.queue.AddRateLimited(ev)
			return true
		}
	}

	w.queue.Forget(ev)
	return true
}

func (w *podWatcher) handleCreate(ev events.Event[*corev1.Pod]) error {
	pod := ev.Obj
	cgInfos, err := containers.ResolveCgInfos(pod)
	if err != nil {
		return err
	}

	if len(cgInfos) != 0 {
		w.podCgInfos[string(pod.UID)] = cgInfos
	}

	var wg sync.WaitGroup
	wg.Add(len(w.eventHandlers))
	for _, e := range w.eventHandlers {
		go func() { defer wg.Done(); e.PodEvent(*pod, cgInfos, events.EventTypeCreate) }()
	}
	wg.Wait()
	return nil
}

func (w *podWatcher) handleUpdate(ev events.Event[*corev1.Pod]) error {
	pod := ev.Obj
	cgInfos, err := containers.ResolveCgInfos(pod)
	if err != nil {
		return err
	}

	if len(cgInfos) != 0 {
		w.podCgInfos[string(pod.UID)] = cgInfos
	}

	var wg sync.WaitGroup
	wg.Add(len(w.eventHandlers))
	for _, e := range w.eventHandlers {
		go func() { defer wg.Done(); e.PodEvent(*pod, cgInfos, events.EventTypeUpdate) }()
	}

	wg.Wait()
	return nil
}

func (w *podWatcher) handleDelete(ev events.Event[*corev1.Pod]) error {
	pod := ev.Obj
	cgInfos := w.podCgInfos[string(pod.UID)]
	delete(w.podCgInfos, string(pod.UID))

	var wg sync.WaitGroup
	wg.Add(len(w.eventHandlers))
	for _, e := range w.eventHandlers {
		go func() { defer wg.Done(); e.PodEvent(*pod, cgInfos, events.EventTypeDelete) }()
	}
	wg.Wait()
	return nil
}
