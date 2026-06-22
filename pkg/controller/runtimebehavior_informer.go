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

type rpWatch struct {
	compiled *compiler.CompiledRuntimePolicy
	cancel   context.CancelFunc
}

type RuntimePolicyMgr struct {
	eventHandlers []events.EventIface // both the reevaluator and the individual bpf program handlers
	factory       v1alpha1informers.SharedInformerFactory
	rpInformer    cache.SharedIndexInformer // todo: a queue
	compiler      compiler.Compiler
	rpThreadMap   map[string]*rpWatch
}

func NewRuntimePolicyMgr(cfg *rest.Config,
	eventHandlers []events.EventIface,
	factory v1alpha1informers.SharedInformerFactory,
	rpCompiler compiler.Compiler) (*RuntimePolicyMgr, error) {
	rpInformer := factory.Runtime().V1alpha1().RuntimePolicies().Informer()

	m := &RuntimePolicyMgr{
		factory:       factory,
		eventHandlers: eventHandlers,
		rpInformer:    rpInformer,
	}

	rpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			rp, ok := obj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}

			compiledRb, err := rpCompiler.Compile(*rp)
			if err != nil {
				// todo: log the errors
				return
			}

			if rp.Spec.EvaluationInterval != nil {
				ctx, cancel := context.WithCancel(context.Background())
				go m.evaluateForInterval(ctx, rp.Spec.EvaluationInterval.Duration, string(rp.UID))
				m.rpThreadMap[string(rp.UID)] = &rpWatch{
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
				handler.RuntimePolicyEvent(evalRes, events.EventTypeCreate)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			rp, ok := newObj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}
			compiledRb, err := rpCompiler.Compile(*rp)
			if err != nil {
				// todo: log the errors
				return
			}

			if currentRb, ok := m.rpThreadMap[string(rp.UID)]; ok {
				// if no re-eval interval previously existed or not equal to the one in the incoming runtime behavior
				if *currentRb.compiled.ReevalInterval != rp.Spec.EvaluationInterval.Duration {
					// there was a previously existing cancel function (different interval). cancel the re-evalutation
					// thread that runs on that interval
					if currentRb.cancel != nil {
						currentRb.cancel()
					}
					ctx, cancel := context.WithCancel(context.Background())
					go m.evaluateForInterval(ctx, rp.Spec.EvaluationInterval.Duration, string(rp.UID))
					m.rpThreadMap[string(rp.UID)] = &rpWatch{
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
				handler.RuntimePolicyEvent(evalRes, events.EventTypeUpdate)
			}
		},
		DeleteFunc: func(obj interface{}) {
			rp, ok := obj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}
			// if there was a re-eval thread running, stop it
			if rpwatch, ok := m.rpThreadMap[string(rp.UID)]; ok {
				delete(m.rpThreadMap, string(rp.UID))
				rpwatch.cancel()
			}

			// deletion events should not depend on runtime behavior data. given the UID, mark it for removal from any
			// internal data structures
			for _, handler := range eventHandlers {
				handler.RuntimePolicyEvent(&compiler.EvaluationResult{UID: string(rp.UID)}, events.EventTypeDelete)
			}
		},
	})

	return m, nil
}

func (m *RuntimePolicyMgr) Start(ctx context.Context) {
	m.factory.Start(ctx.Done())
	<-ctx.Done()
}

// if there was an object variable, this function would need to be pod aware
func (r *RuntimePolicyMgr) evaluateForInterval(ctx context.Context, interval time.Duration, rpUid string) {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rp, ok := r.rpThreadMap[rpUid]
			if !ok {
				return
			}

			evalRes, err := rp.compiled.Evaluate()
			if err != nil {
				continue
			}

			// and the event handlers would need to be able to receive an event for the combined evaluation result of a pod and a policy
			for _, handler := range r.eventHandlers {
				handler.RuntimePolicyEvent(evalRes, "update")
			}
		}
	}
}
