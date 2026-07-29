package controller

import (
	"context"
	"errors"
	"fmt"
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
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
)

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

	// threadMu guards rpThreadMap, which is written by the informer worker and
	// read by every evaluateForInterval goroutine.
	threadMu    sync.Mutex
	rpThreadMap map[string]*rpWatch

	// mu guards deletedUIDs, which is written by the informer's handler
	// goroutine and read by the worker.
	mu sync.Mutex
	// deletedUIDs maps the name of a queued delete to the policy's UID. The
	// delete fan-out needs only the identity (UID and name), and the lister no
	// longer holds the object by the time the worker picks the key up.
	deletedUIDs map[string]string

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
	rpCompiler compiler.Compiler) (*RuntimePolicyMgr, error) {
	factory := v1alpha1informers.NewSharedInformerFactory(client, 0)
	rpInformer := factory.Runtime().V1alpha1().RuntimePolicies().Informer()

	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[queueKey](),
	)

	m := &RuntimePolicyMgr{
		rpThreadMap:   make(map[string]*rpWatch),
		deletedUIDs:   make(map[string]string),
		factory:       factory,
		eventHandlers: eventHandlers,
		compiler:      rpCompiler,
		rpInformer:    rpInformer,
		queue:         queue,
		lister:        factory.Runtime().V1alpha1().RuntimePolicies().Lister(),
		log:           ctrl.Log.WithName("runtimepolicy"),
	}

	// AddEventHandler only errors if the informer has already stopped, which
	// cannot happen here since it hasn't been started yet.
	_, _ = rpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			rp, ok := obj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}
			m.enqueue(rp, events.EventTypeCreate)
		},
		UpdateFunc: func(_, newObj interface{}) {
			rp, ok := newObj.(*v1alpha1.RuntimePolicy)
			if !ok {
				return
			}
			m.enqueue(rp, events.EventTypeUpdate)
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
			m.enqueue(rp, events.EventTypeDelete)
		},
	})

	return m, nil
}

// enqueue converts an informer notification into a stable queueKey.
// RuntimePolicies are cluster-scoped so the key is just the name. Delete
// notifications additionally record the policy's UID: the delete fan-out
// needs only the identity, and the lister no longer has the object by the
// time the worker picks the key up.
func (m *RuntimePolicyMgr) enqueue(rp *v1alpha1.RuntimePolicy, evType string) {
	if rp.Name == "" {
		m.log.V(0).Info("ignoring a RuntimePolicy notification with no name", "type", evType)
		return
	}
	if evType == events.EventTypeDelete {
		m.mu.Lock()
		m.deletedUIDs[rp.Name] = string(rp.UID)
		m.mu.Unlock()
	}
	m.queue.Add(queueKey{Type: evType, Key: rp.Name})
}

func (m *RuntimePolicyMgr) deletedUID(name string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deletedUIDs[name]
}

// dropDeletedUID releases a recorded delete UID once the item leaves the
// queue for good, so requeued deletes can still find their UID.
func (m *RuntimePolicyMgr) dropDeletedUID(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.deletedUIDs, name)
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

	err := m.handle(ctx, key)
	if err != nil {
		requeues := m.queue.NumRequeues(key)
		// the key is stable, so this cap counts retries of the logical policy
		// event and no longer resets when the lister's object changes
		if requeues >= maxRequeues {
			m.log.Error(err, "giving up on event after max requeues", "policy", key.Key, "type", key.Type, "requeues", requeues)
			m.forget(key)
			return true
		}
		m.queue.AddRateLimited(key)
		return true
	}

	m.forget(key)
	return true
}

func (m *RuntimePolicyMgr) forget(key queueKey) {
	m.queue.Forget(key)
	if key.Type == events.EventTypeDelete {
		m.dropDeletedUID(key.Key)
	}
}

func (m *RuntimePolicyMgr) handle(ctx context.Context, key queueKey) error {
	if key.Type == events.EventTypeDelete {
		uid := m.deletedUID(key.Key)
		if uid == "" {
			m.log.V(2).Info("no recorded UID for deleted policy, dropping event", "policy", key.Key)
			return nil
		}
		return m.handleDelete(uid, key.Key)
	}

	// always read the policy from the lister at processing time so a retry
	// programs the current spec rather than the revision that was queued
	rp, err := m.lister.Get(key.Key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			m.log.V(2).Info("policy no longer in the lister, dropping event", "policy", key.Key, "type", key.Type)
			return nil
		}
		return fmt.Errorf("fetching RuntimePolicy %s from lister: %w", key.Key, err)
	}

	switch key.Type {
	case events.EventTypeCreate:
		return m.handleCreate(ctx, rp)
	case events.EventTypeUpdate:
		return m.handleUpdate(ctx, rp)
	}
	return nil
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

// syncIntervalThread reconciles the periodic re-evaluation goroutine for a
// policy with the interval that policy now asks for. Either side of the
// comparison can be absent: a tracked policy may have had no interval, and the
// incoming policy may have dropped its evaluationInterval, so a missing
// interval is treated as zero (dereferencing either side unconditionally used
// to panic the worker).
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

	// the interval is unchanged, so the existing goroutine stays. it must still
	// be handed the freshly compiled policy: evaluateForInterval reads compiled
	// from this entry on every tick, so leaving the old pointer here would keep
	// re-evaluating a stale policy until the interval next changed.
	if tracked && currentInterval == newInterval {
		current.compiled = compiledRb
		return
	}

	// the interval changed, or a policy that was not tracked has gained one.
	// stop the goroutine running on the old interval, if there was one.
	if tracked && current.cancel != nil {
		current.cancel()
	}

	if newInterval <= 0 {
		// the policy no longer asks for periodic re-evaluation
		delete(r.rpThreadMap, uid)
		return
	}

	// context.WithoutCancel: the re-evaluation goroutine outlives the work
	// item's context, and is torn down by its own cancel func or on delete.
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

func (r *RuntimePolicyMgr) handleDelete(uid, name string) error {
	// if there was a re-eval thread running, stop it
	r.threadMu.Lock()
	if rpwatch, ok := r.rpThreadMap[uid]; ok {
		delete(r.rpThreadMap, uid)
		if rpwatch.cancel != nil {
			rpwatch.cancel()
		}
	}
	r.threadMu.Unlock()

	// deletion events should not depend on runtime behavior data. given the
	// UID, mark it for removal from any internal data structures.
	return r.fanOut(&compiler.EvaluationResult{UID: uid, Name: name}, events.EventTypeDelete)
}

// fanOut delivers the evaluation result to every handler concurrently. Each
// call is wrapped in utils.Guard so a panicking handler becomes an error on
// this item instead of killing the informer worker.
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
