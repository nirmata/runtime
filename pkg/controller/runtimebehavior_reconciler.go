package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/go-logr/logr"
	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

const cleanupFinalizer = "runtime.kyverno.io/cleanup"

type RuntimeBehaviorReconciler struct {
	Client client.Client
	RbMap  map[string]*Rb // a map of rb name to its matching labels and ips so when an event happens
	// todo: this needs to also have a dependency on the egress manager and other bpf handlers
	// in the future

	labelCallback func()
}

type Rb struct {
	Labels map[string]string
	Ips    []string
}

// NewRuntimeBehaviorReconciler creates a new RuntimeBehaviorReconciler.
func NewRuntimeBehaviorReconciler(c client.Client, l *logr.Logger) (*RuntimeBehaviorReconciler, error) {
	return &RuntimeBehaviorReconciler{
		RbMap:  make(map[string]*Rb),
		Client: c,
	}, nil
}

func (r *RuntimeBehaviorReconciler) SetCallback(f func()) {
	r.labelCallback = f
}

// Reconcile is called whenever a RuntimeBehavior is created, updated, or deleted.
func (r *RuntimeBehaviorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rb := &v1alpha1.RuntimeBehavior{}
	if err := r.Client.Get(ctx, req.NamespacedName, rb); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !rb.DeletionTimestamp.IsZero() {
		delete(r.RbMap, req.Name)
		// inform the containerd connector to reevaluate ips
		r.labelCallback()

		if rb.Finalizers != nil {
			if controllerutil.ContainsFinalizer(rb, cleanupFinalizer) {
				controllerutil.RemoveFinalizer(rb, cleanupFinalizer)
				if err := r.Client.Update(ctx, rb); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{}, nil
			}
		}
		return ctrl.Result{}, nil
	}

	if rb.Spec.Allow == nil || rb.Spec.Allow.Deny == nil {
		return ctrl.Result{}, nil
	}

	r.RbMap[req.Name] = &Rb{
		Ips:    rb.Spec.Allow.Deny.Network,
		Labels: rb.Spec.WorkloadSelector.MatchLabels,
	}

	// handle banned ips

	// todo: dont do this if the mode is not enforce

	// add finalizer if not present
	if !controllerutil.ContainsFinalizer(rb, cleanupFinalizer) {
		controllerutil.AddFinalizer(rb, cleanupFinalizer)
		if err := r.Client.Update(ctx, rb); err != nil {
			return ctrl.Result{}, err
		}
	}
	// should be the re-evaluate function on the connector
	r.labelCallback()

	return ctrl.Result{}, nil
}
