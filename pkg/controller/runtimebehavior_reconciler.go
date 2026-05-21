package controller

import (
	"context"
	"maps"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/go-logr/logr"
	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/probe"
)

const cleanupFinalizer = "runtime.kyverno.io/cleanup"

type RuntimeBehaviorReconciler struct {
	AllLabels map[string]string // all labels we saw from all runtime behaviors
	Client    client.Client

	bannedIps     map[string][]string
	probe         *probe.Probe
	labelCallback func()
}

// NewRuntimeBehaviorReconciler creates a new RuntimeBehaviorReconciler.
func NewRuntimeBehaviorReconciler(c client.Client, l *logr.Logger, probe *probe.Probe) (*RuntimeBehaviorReconciler, error) {
	return &RuntimeBehaviorReconciler{
		Client:    c,
		AllLabels: make(map[string]string),
		bannedIps: make(map[string][]string),
		probe:     probe,
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
		delete(r.bannedIps, req.Name)
		ipsToBan := []string{}
		for _, ips := range r.bannedIps {
			for _, ip := range ips {
				ipsToBan = append(ipsToBan, ip)
			}
		}
		r.probe.UpdateMap(ipsToBan)
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

	// add any new labels
	if rb.Spec.WorkloadSelector.MatchLabels != nil {
		// todo: handle overlapping labels
		maps.Copy(r.AllLabels, rb.Spec.WorkloadSelector.MatchLabels)
	}

	// handle banned ips
	r.bannedIps[req.Name] = rb.Spec.Allow.Deny.Network
	ipsToBan := []string{}
	for _, ips := range r.bannedIps {
		for _, ip := range ips {
			ipsToBan = append(ipsToBan, ip)
		}
	}

	// todo: dont do this if the mode is not enforce
	r.probe.UpdateMap(ipsToBan)

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
