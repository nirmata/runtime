package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	v1alpha1informers "github.com/nirmata/kyverno-runtime/pkg/client/informers/externalversions"

	v1alpha1client "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const workers = 5

type rpWatch struct {
	compiled *compiler.CompiledRuntimePolicy
	cancel   context.CancelFunc
}

type RuntimePolicyMgr struct {
	eventHandlers []events.EventIface
	queue         workqueue.TypedRateLimitingInterface[events.Event[*v1alpha1.RuntimePolicy]]
	factory       v1alpha1informers.SharedInformerFactory
	rpInformer    cache.SharedIndexInformer
	compiler      compiler.Compiler
	rpThreadMap   map[string]*rpWatch
}

func (m *RuntimePolicyMgr) Start(ctx context.Context) {
	defer m.queue.ShutDown()

	if !cache.WaitForCacheSync(ctx.Done(), m.rpInformer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for cache sync"))
		return
	}

	m.factory.Start(ctx.Done())

	for range workers {
		go wait.UntilWithContext(ctx, m.runWorker, time.Second)
	}

	<-ctx.Done()
}

// expose HasSynced so we can wait till sync is complete from main before
// starting the pod sync
func (m *RuntimePolicyMgr) HasSynced() bool {
	return m.rpInformer.HasSynced()
}

func NewRuntimePolicyMgr(cfg *rest.Config,
	eventHandlers []events.EventIface,
	client v1alpha1client.Interface,
	rpCompiler compiler.Compiler) (*RuntimePolicyMgr, error) {
	factory := v1alpha1informers.NewSharedInformerFactory(client, 0)
	rpInformer := factory.Runtime().V1alpha1().RuntimePolicies().Informer()

	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[events.Event[*v1alpha1.RuntimePolicy]](),
	)

	m := &RuntimePolicyMgr{
		factory:       factory,
		eventHandlers: eventHandlers,
		rpInformer:    rpInformer,
		queue:         queue,
	}

	rpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			rp, ok := obj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}
			queue.Add(events.Event[*v1alpha1.RuntimePolicy]{Obj: rp, Type: events.EventTypeCreate})

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			rp, ok := newObj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}
			queue.Add(events.Event[*v1alpha1.RuntimePolicy]{Obj: rp, Type: events.EventTypeUpdate})
		},
		DeleteFunc: func(obj interface{}) {
			rp, ok := obj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}
			queue.Add(events.Event[*v1alpha1.RuntimePolicy]{Obj: rp, Type: events.EventTypeDelete})
		},
	})

	return m, nil
}

func (m *RuntimePolicyMgr) runWorker(ctx context.Context) {
	for m.processNextWorkItem(ctx) {
	}
}

func (m *RuntimePolicyMgr) processNextWorkItem(ctx context.Context) bool {
	ev, quit := m.queue.Get()
	if quit {
		return false
	}
	defer m.queue.Done(ev)

	var err error
	switch ev.Type {
	case events.EventTypeCreate:
		err = m.handleCreate(ctx, ev)
	case events.EventTypeUpdate:
		err = m.handleUpdate(ctx, ev)
	case events.EventTypeDelete:
		err = m.handleDelete(ev)
	}

	if err != nil {
	}

	m.queue.Forget(ev)
	return true
}

func (r *RuntimePolicyMgr) handleCreate(ctx context.Context, ev events.Event[*v1alpha1.RuntimePolicy]) error {
	rp := ev.Obj

	compiledRb, err := r.compiler.Compile(*rp)
	if err != nil {
		return err
	}

	if rp.Spec.EvaluationInterval != nil {
		ctx, cancel := context.WithCancel(context.Background())
		go r.evaluateForInterval(ctx, rp.Spec.EvaluationInterval.Duration, string(rp.UID))
		r.rpThreadMap[string(rp.UID)] = &rpWatch{
			compiled: compiledRb,
			cancel:   cancel,
		}
	}

	evalRes, err := compiledRb.Evaluate(ctx)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(len(r.eventHandlers))

	for _, handler := range r.eventHandlers {
		go func() { defer wg.Done(); handler.RuntimePolicyEvent(evalRes, events.EventTypeCreate) }()
	}

	wg.Wait()
	return nil
}

func (r *RuntimePolicyMgr) handleUpdate(ctx context.Context, ev events.Event[*v1alpha1.RuntimePolicy]) error {
	rp := ev.Obj
	compiledRb, err := r.compiler.Compile(*rp)
	if err != nil {
		return err
	}

	if currentRb, ok := r.rpThreadMap[string(rp.UID)]; ok {
		// if no re-eval interval previously existed or not equal to the one in the incoming runtime behavior
		if *currentRb.compiled.ReevalInterval != rp.Spec.EvaluationInterval.Duration {
			// there was a previously existing cancel function (different interval). cancel the re-evalutation
			// thread that runs on that interval
			if currentRb.cancel != nil {
				currentRb.cancel()
			}
			ctx, cancel := context.WithCancel(ctx)
			go r.evaluateForInterval(ctx, rp.Spec.EvaluationInterval.Duration, string(rp.UID))
			r.rpThreadMap[string(rp.UID)] = &rpWatch{
				compiled: compiledRb,
				cancel:   cancel,
			}
		}
	}

	evalRes, err := compiledRb.Evaluate(ctx)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(len(r.eventHandlers))

	for _, handler := range r.eventHandlers {
		go func() { defer wg.Done(); handler.RuntimePolicyEvent(evalRes, events.EventTypeUpdate) }()
	}

	wg.Wait()
	return nil
}

func (r *RuntimePolicyMgr) handleDelete(ev events.Event[*v1alpha1.RuntimePolicy]) error {
	rp := ev.Obj
	// if there was a re-eval thread running, stop it
	if rpwatch, ok := r.rpThreadMap[string(rp.UID)]; ok {
		delete(r.rpThreadMap, string(rp.UID))
		rpwatch.cancel()
	}

	var wg sync.WaitGroup
	wg.Add(len(r.eventHandlers))

	for _, handler := range r.eventHandlers {
		go func() {
			defer wg.Done()

			// deletion events should not depend on runtime behavior data. given the UID, mark it for removal from any
			// internal data structures
			handler.RuntimePolicyEvent(&compiler.EvaluationResult{UID: string(rp.UID)}, events.EventTypeDelete)
		}()
	}

	wg.Wait()
	return nil
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

			evalRes, err := rp.compiled.Evaluate(ctx)
			if err != nil {
				continue
			}

			var wg sync.WaitGroup
			wg.Add(len(r.eventHandlers))

			// and the event handlers would need to be able to receive an event for the combined evaluation result of a pod and a policy
			for _, handler := range r.eventHandlers {
				go func() { defer wg.Done(); handler.RuntimePolicyEvent(evalRes, events.EventTypeUpdate) }()
			}

			wg.Wait()
		}
	}
}
