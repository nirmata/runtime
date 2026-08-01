package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	v1alpha1client "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned"
	v1alpha1informers "github.com/nirmata/kyverno-runtime/pkg/client/informers/externalversions"
	v1alpha1listers "github.com/nirmata/kyverno-runtime/pkg/client/listers/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
)

// ServiceChangeNotifier reports that the addresses behind a Service reference
// may have changed. It is satisfied by *services.Resolver.
type ServiceChangeNotifier interface {
	AddChangeHandler(h func(ref v1alpha1.ServiceReference))
}

type rpWatch struct {
	compiled *compiler.CompiledRuntimePolicy
	cancel   context.CancelFunc
}

type RuntimePolicyMgr struct {
	eventHandlers []events.RuntimePolicyEventHandler
	queue         workqueue.TypedRateLimitingInterface[queueKey]
	factory       v1alpha1informers.SharedInformerFactory
	rpInformer    cache.SharedIndexInformer
	compiler      compiler.Compiler

	// threadMu guards rpThreadMap, read by every evaluateForInterval goroutine.
	threadMu    sync.Mutex
	rpThreadMap map[string]*rpWatch

	lister v1alpha1listers.RuntimePolicyLister
	log    logr.Logger
}

func (m *RuntimePolicyMgr) Start(ctx context.Context) error {
	defer m.queue.ShutDown()

	m.factory.Start(ctx.Done())
	// wait for 30 seconds tops for cache sync
	timeOut, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	if !cache.WaitForCacheSync(timeOut.Done(), m.rpInformer.HasSynced) {
		return fmt.Errorf("timed out waiting for cache sync")
	}

	go wait.UntilWithContext(ctx, m.runWorker, time.Second)

	<-ctx.Done()
	return nil
}

// expose HasSynced so we can wait till sync is complete from main before
// starting the pod sync
func (m *RuntimePolicyMgr) HasSynced() bool {
	return m.rpInformer.HasSynced()
}

func NewRuntimePolicyMgr(cfg *rest.Config,
	eventHandlers []events.RuntimePolicyEventHandler,
	client v1alpha1client.Interface,
	rpCompiler compiler.Compiler,
	resolver ServiceChangeNotifier) (*RuntimePolicyMgr, error) {
	factory := v1alpha1informers.NewSharedInformerFactory(client, 0)
	rpInformer := factory.Runtime().V1alpha1().RuntimePolicies().Informer()

	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[queueKey](),
	)

	m := &RuntimePolicyMgr{
		rpThreadMap:   make(map[string]*rpWatch),
		factory:       factory,
		eventHandlers: eventHandlers,
		compiler:      rpCompiler,
		rpInformer:    rpInformer,
		queue:         queue,
		lister:        factory.Runtime().V1alpha1().RuntimePolicies().Lister(),
		log:           ctrl.Log.WithName("runtimepolicy"),
	}

	// AddEventHandler only errors once the informer has stopped, which cannot
	// happen before Start.
	_, _ = rpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			rp, ok := obj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}
			m.queue.Add(queueKey{Type: events.EventTypeCreate, Key: rp.Name})
		},
		UpdateFunc: func(_, newObj interface{}) {
			rp, ok := newObj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}
			m.queue.Add(queueKey{Type: events.EventTypeUpdate, Key: rp.Name})
		},
		DeleteFunc: func(obj interface{}) {
			rp, ok := obj.(*v1alpha1.RuntimePolicy)
			if !ok {
				// handle cache.DeletedFinalStateUnknown
				unknown, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				rp, ok = unknown.Obj.(*v1alpha1.RuntimePolicy)
				if !ok {
					return
				}
			}
			m.queue.Add(queueKey{Type: events.EventTypeDelete, Key: string(rp.UID)})
		},
	})

	resolver.AddChangeHandler(m.serviceRefChanged)

	return m, nil
}

// serviceRefChanged runs on the resolver's informer goroutine, so it only queues:
// the worker recompiles and re-evaluates the policy, and the handlers diff the
// result against what they programmed.
func (m *RuntimePolicyMgr) serviceRefChanged(ref v1alpha1.ServiceReference) {
	policies, err := m.lister.List(labels.Everything())
	if err != nil {
		m.log.Error(err, "listing policies for a changed service", "service", ref.Namespace+"/"+ref.Name)
		return
	}
	for _, rp := range policies {
		if !referencesService(rp, ref) {
			continue
		}
		m.log.V(2).Info("service changed, requeueing the policies that reference it",
			"service", ref.Namespace+"/"+ref.Name, "policy", rp.Name)
		m.queue.Add(queueKey{Type: events.EventTypeUpdate, Key: rp.Name})
	}
}

func referencesService(rp *v1alpha1.RuntimePolicy, ref v1alpha1.ServiceReference) bool {
	for _, behavior := range rp.Spec.Behaviors {
		if behavior.Network == nil {
			continue
		}
		for _, rule := range []*v1alpha1.BehaviorRule{behavior.Network.Allow, behavior.Network.Deny} {
			if rule == nil {
				continue
			}
			if slices.Contains(rule.ServiceRefs, ref) {
				return true
			}
		}
	}
	return false
}

func (m *RuntimePolicyMgr) runWorker(ctx context.Context) {
	for m.processNextWorkItem(ctx) {
	}
}

func (m *RuntimePolicyMgr) processNextWorkItem(ctx context.Context) bool {
	key, quit := m.queue.Get()
	if quit {
		return false
	}
	defer m.queue.Done(key)

	var err error
	switch key.Type {
	case events.EventTypeCreate, events.EventTypeUpdate:
		// the policy is read at processing time so a retry programs the current
		// spec rather than the revision that was queued
		rp, getErr := m.lister.Get(key.Key)
		if apierrors.IsNotFound(getErr) {
			m.log.V(2).Info("policy missing from the lister, dropping event", "policy", key.Key, "type", key.Type)
			break
		}
		if getErr != nil {
			err = fmt.Errorf("fetching RuntimePolicy %s from lister: %w", key.Key, getErr)
			break
		}
		if key.Type == events.EventTypeCreate {
			err = m.handleCreate(ctx, rp)
		} else {
			err = m.handleUpdate(ctx, rp)
		}
	case events.EventTypeDelete:
		err = m.handleDelete(key.Key)
	}

	if err != nil {
		requeues := m.queue.NumRequeues(key)
		if requeues >= maxRequeues {
			m.log.Error(err, "giving up on event after max requeues", "policy", key.Key, "type", key.Type, "requeues", requeues)
			m.queue.Forget(key)
			return true
		}
		m.queue.AddRateLimited(key)
		return true
	}

	m.queue.Forget(key)
	return true
}

func (r *RuntimePolicyMgr) handleCreate(ctx context.Context, rp *v1alpha1.RuntimePolicy) error {
	compiledRb, err := r.compiler.Compile(*rp)
	if err != nil {
		return err
	}

	r.syncIntervalThread(ctx, rp, compiledRb)

	evalRes, err := compiledRb.Evaluate(ctx)
	if err != nil {
		return err
	}

	return r.fanOut(evalRes, events.EventTypeCreate)
}

// syncIntervalThread reconciles the periodic re-evaluation goroutine with the
// interval the policy asks for. A missing interval on either side counts as zero.
func (r *RuntimePolicyMgr) syncIntervalThread(ctx context.Context, rp *v1alpha1.RuntimePolicy, compiledRb *compiler.CompiledRuntimePolicy) {
	uid := string(rp.UID)

	var newInterval time.Duration
	if rp.Spec.EvaluationInterval != nil {
		newInterval = rp.Spec.EvaluationInterval.Duration
	}

	r.threadMu.Lock()
	defer r.threadMu.Unlock()

	current, tracked := r.rpThreadMap[uid]

	var currentInterval time.Duration
	if tracked && current.compiled != nil && current.compiled.ReevalInterval != nil {
		currentInterval = *current.compiled.ReevalInterval
	}

	// nothing tracked and nothing asked for
	if !tracked && newInterval <= 0 {
		return
	}

	// the goroutine stays, but evaluateForInterval reads compiled on every tick
	// so it has to be handed the freshly compiled policy
	if tracked && currentInterval == newInterval {
		current.compiled = compiledRb
		return
	}

	if tracked && current.cancel != nil {
		current.cancel()
	}

	// no periodic re-evaluation is asked for
	if newInterval <= 0 {
		delete(r.rpThreadMap, uid)
		return
	}

	// the goroutine outlives the work item's context, and is torn down by its
	// own cancel func or on delete
	threadCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	go r.evaluateForInterval(threadCtx, newInterval, uid)
	r.rpThreadMap[uid] = &rpWatch{
		compiled: compiledRb,
		cancel:   cancel,
	}
}

func (r *RuntimePolicyMgr) handleUpdate(ctx context.Context, rp *v1alpha1.RuntimePolicy) error {
	compiledRb, err := r.compiler.Compile(*rp)
	if err != nil {
		return err
	}

	r.syncIntervalThread(ctx, rp, compiledRb)

	evalRes, err := compiledRb.Evaluate(ctx)
	if err != nil {
		return err
	}

	return r.fanOut(evalRes, events.EventTypeUpdate)
}

func (r *RuntimePolicyMgr) handleDelete(uid string) error {
	// if there was a re-eval thread running, stop it
	r.threadMu.Lock()
	if rpwatch, ok := r.rpThreadMap[uid]; ok {
		delete(r.rpThreadMap, uid)
		if rpwatch.cancel != nil {
			rpwatch.cancel()
		}
	}
	r.threadMu.Unlock()

	// the UID is the whole identity a handler needs to drop its state
	return r.fanOut(&compiler.EvaluationResult{UID: uid}, events.EventTypeDelete)
}

// utils.Guard turns a panicking handler into an error on this item instead of
// taking the worker down
func (r *RuntimePolicyMgr) fanOut(evalRes *compiler.EvaluationResult, evType string) error {
	errChan := make(chan error, len(r.eventHandlers))
	var wg sync.WaitGroup
	wg.Add(len(r.eventHandlers))

	for _, handler := range r.eventHandlers {
		go func(handler events.RuntimePolicyEventHandler) {
			defer wg.Done()
			op := fmt.Sprintf("%T.RuntimePolicyEvent(%s, %s)", handler, policyRef(evalRes), evType)
			if err := utils.Guard(op, func() error {
				return handler.RuntimePolicyEvent(evalRes, evType)
			}); err != nil {
				errChan <- err
			}
		}(handler)
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func policyRef(res *compiler.EvaluationResult) string {
	if res == nil {
		return "<nil>"
	}
	if res.Name != "" {
		return res.Name
	}
	return res.UID
}

// if there was an object variable, this function would need to be pod aware
func (r *RuntimePolicyMgr) evaluateForInterval(ctx context.Context, interval time.Duration, rpUid string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.threadMu.Lock()
			watch, ok := r.rpThreadMap[rpUid]
			var compiled *compiler.CompiledRuntimePolicy
			if ok {
				compiled = watch.compiled
			}
			r.threadMu.Unlock()
			if !ok || compiled == nil {
				return
			}

			evalRes, err := compiled.Evaluate(ctx)
			if err != nil {
				r.log.Error(err, "evaluation failed in interval loop", "policy", rpUid)
				continue
			}

			// and the event handlers would need to be able to receive an event
			// for the combined evaluation result of a pod and a policy
			if err := r.fanOut(evalRes, events.EventTypeUpdate); err != nil {
				r.log.Error(err, "interval re-evaluation handler failed", "policy", rpUid)
			}
		}
	}
}
