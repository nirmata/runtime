package controller

import (
	"context"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
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

func NewRuntimeBehaviorMgr(cfg *rest.Config, eventHandler egressmgr.EventIface, factory v1alpha1informers.SharedInformerFactory) (*RuntimeBehaviorMgr, error) {
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
	<-ctx.Done()
}
