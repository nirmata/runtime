package pods

import (
	"context"
	"fmt"
	"log"

	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type PodWatcher struct {
	factory    informers.SharedInformerFactory
	informer   cache.SharedIndexInformer
	podCgInfos map[string][]*containers.ContainerCgroupInfo // todo: we should be also delete dead pod entries

	nodeName     string
	eventHandler events.EventIface
}

func NewPodWatcher(client kubernetes.Interface, nodeName string, eventHandler events.EventIface) *PodWatcher {
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

	podInformer := factory.Core().V1().Pods().Informer()
	podCgInfos := make(map[string][]*containers.ContainerCgroupInfo)

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			cgInfos, err := containers.ResolveCgInfos(pod)
			if err != nil {
				// todo: handle this
				return
			}

			if len(cgInfos) != 0 {
				podCgInfos[string(pod.UID)] = cgInfos
			}
			eventHandler.PodEvent(*pod, cgInfos, "create")

		},
		UpdateFunc: func(_, new interface{}) {
			pod, ok := new.(*corev1.Pod)
			if !ok {
				return
			}
			cgInfos, err := containers.ResolveCgInfos(pod)
			if err != nil {
				// todo: handle this
				return
			}

			if len(cgInfos) != 0 {
				podCgInfos[string(pod.UID)] = cgInfos
			}

			eventHandler.PodEvent(*pod, cgInfos, "update")
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			cgInfos := podCgInfos[string(pod.UID)]
			delete(podCgInfos, string(pod.UID))
			eventHandler.PodEvent(*pod, cgInfos, "delete")
		},
	})

	w := &PodWatcher{
		factory:      factory,
		informer:     podInformer,
		nodeName:     nodeName,
		eventHandler: eventHandler,
		podCgInfos:   podCgInfos,
	}

	return w
}

func (w *PodWatcher) Start(ctx context.Context) {
	w.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), w.informer.HasSynced) {
		log.Printf("timed out waiting for cache sync")
		return
	}

	<-ctx.Done()
}
