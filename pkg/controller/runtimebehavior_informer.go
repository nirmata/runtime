package controller

import (
	"context"
	"log"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	v1alpha1client "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned"
	v1alpha1informers "github.com/nirmata/kyverno-runtime/pkg/client/informers/externalversions"
	"github.com/nirmata/kyverno-runtime/pkg/egressmgr"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type RuntimeBehaviorMgr struct {
	eventHandler egressmgr.EventIface
	factory      v1alpha1informers.SharedInformerFactory
	rbInformer   cache.SharedIndexInformer
}

func NewRuntimeBehaviorMgr(cfg *rest.Config, eventHandler egressmgr.EventIface) (*RuntimeBehaviorMgr, error) {
	client, err := v1alpha1client.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	factory := v1alpha1informers.NewSharedInformerFactory(client, 0)
	rbInformer := factory.Runtime().V1alpha1().RuntimeBehaviors().Informer()
	rbInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			rb, ok := obj.(*v1alpha1.RuntimeBehavior)
			if !ok {
				return
			}
			eventHandler.RuntimeBehaviorEvent(*rb, "create")
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			rb, ok := newObj.(*v1alpha1.RuntimeBehavior)
			if !ok {
				return
			}
			eventHandler.RuntimeBehaviorEvent(*rb, "update")
		},
		DeleteFunc: func(obj interface{}) {
			rb, ok := obj.(*v1alpha1.RuntimeBehavior)
			if !ok {
				return
			}
			eventHandler.RuntimeBehaviorEvent(*rb, "delete")
		},
	})

	m := &RuntimeBehaviorMgr{
		factory:      factory,
		eventHandler: eventHandler,
		rbInformer:   rbInformer,
	}

	return m, nil
}

func (m *RuntimeBehaviorMgr) Start(ctx context.Context) {
	m.factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), m.rbInformer.HasSynced) {
		log.Printf("timed out waiting for cache sync")
		return
	}

	<-ctx.Done()
}
