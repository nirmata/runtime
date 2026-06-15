package controller

import (
	"context"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	v1alpha1informers "github.com/nirmata/kyverno-runtime/pkg/client/informers/externalversions"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type rbWatch struct {
	compiled *compiler.CompiledRuntimeBehavior
	cancel   context.CancelFunc
}

type RuntimeBehaviorMgr struct {
	eventHandlers []events.EventIface // both the reevaluator and the individual bpf program handlers
	factory       v1alpha1informers.SharedInformerFactory
	rbInformer    cache.SharedIndexInformer // todo: a queue
	compiler      compiler.Compiler
	rbThreadMap   map[string]*rbWatch
}

func NewRuntimeBehaviorMgr(cfg *rest.Config,
	eventHandlers []events.EventIface,
	factory v1alpha1informers.SharedInformerFactory,
	rbCompiler compiler.Compiler) (*RuntimeBehaviorMgr, error) {
	rbInformer := factory.Runtime().V1alpha1().RuntimeBehaviors().Informer()

	m := &RuntimeBehaviorMgr{
		factory:       factory,
		eventHandlers: eventHandlers,
		rbInformer:    rbInformer,
	}

	rbInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			rb, ok := obj.(*v1alpha1.RuntimeBehavior)
			if !ok {
				return
			}

			compiledRb, err := rbCompiler.Compile(*rb)
			if err != nil {
				// todo: log the errors
				return
			}

			if rb.Spec.ReevaluationInterval != nil {
				ctx, cancel := context.WithCancel(context.Background())
				go m.evaluateForInterval(ctx, *rb.Spec.ReevaluationInterval, string(rb.UID))
				m.rbThreadMap[string(rb.UID)] = &rbWatch{
					compiled: compiledRb,
					cancel:   cancel,
				}
			}

			evalRes, err := compiledRb.Evaluate()
			if err != nil {
				return
			}

			for _, handler := range eventHandlers {
				// todo: events should be handled in grs instead of serialy
				handler.RuntimeBehaviorEvent(evalRes, events.EventTypeCreate)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			rb, ok := newObj.(*v1alpha1.RuntimeBehavior)
			if !ok {
				return
			}
			compiledRb, err := rbCompiler.Compile(*rb)
			if err != nil {
				// todo: log the errors
				return
			}

			if currentRb, ok := m.rbThreadMap[string(rb.UID)]; ok {
				// if no re-eval interval previously existed or not equal to the one in the incoming runtime behavior
				if currentRb.compiled.ReevalInterval != rb.Spec.ReevaluationInterval {
					// there was a previously existing cancel function (different interval). cancel the re-evalutation
					// thread that runs on that interval
					if currentRb.cancel != nil {
						currentRb.cancel()
					}
					ctx, cancel := context.WithCancel(context.Background())
					go m.evaluateForInterval(ctx, *rb.Spec.ReevaluationInterval, string(rb.UID))
					m.rbThreadMap[string(rb.UID)] = &rbWatch{
						compiled: compiledRb,
						cancel:   cancel,
					}
				}
			}

			evalRes, err := compiledRb.Evaluate()
			if err != nil {
				return
			}

			for _, handler := range eventHandlers {
				handler.RuntimeBehaviorEvent(evalRes, events.EventTypeUpdate)
			}
		},
		DeleteFunc: func(obj interface{}) {
			rb, ok := obj.(*v1alpha1.RuntimeBehavior)
			if !ok {
				return
			}
			// if there was a re-eval thread running, stop it
			if rbwatch, ok := m.rbThreadMap[string(rb.UID)]; ok {
				delete(m.rbThreadMap, string(rb.UID))
				rbwatch.cancel()
			}

			// deletion events should not depend on runtime behavior data. given the UID, mark it for removal from any
			// internal data structures
			for _, handler := range eventHandlers {
				handler.RuntimeBehaviorEvent(&compiler.EvaluationResult{UID: string(rb.UID)}, events.EventTypeDelete)
			}
		},
	})

	return m, nil
}

func (m *RuntimeBehaviorMgr) Start(ctx context.Context) {
	m.factory.Start(ctx.Done())
	<-ctx.Done()
}

// if there was an object variable, this function would need to be pod aware
func (r *RuntimeBehaviorMgr) evaluateForInterval(ctx context.Context, interval time.Duration, rbUid string) {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rb, ok := r.rbThreadMap[rbUid]
			if !ok {
				return
			}

			evalRes, err := rb.compiled.Evaluate()
			if err != nil {
				continue
			}

			// and the event handlers would need to be able to receive an event for the combined evaluation result of a pod and a policy
			for _, handler := range r.eventHandlers {
				handler.RuntimeBehaviorEvent(evalRes, "update")
			}
		}
	}
}
