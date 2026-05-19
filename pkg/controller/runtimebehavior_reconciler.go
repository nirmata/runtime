package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/probe"
)

type RuntimeBehaviorReconciler struct {
	client    client.Client
	bannedIps map[string][]string
	probe     *probe.Probe
}

// NewRuntimeBehaviorReconciler creates a new RuntimeBehaviorReconciler.
func NewRuntimeBehaviorReconciler(c client.Client) (*RuntimeBehaviorReconciler, error) {
	probe, err := probe.New()
	if err != nil {
		return nil, err
	}

	return &RuntimeBehaviorReconciler{
		client:    c,
		bannedIps: make(map[string][]string),
		probe:     probe,
	}, nil
}

// Reconcile is called whenever a RuntimeBehavior is created, updated, or deleted.
func (r *RuntimeBehaviorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rb := &v1alpha1.RuntimeBehavior{}
	if err := r.client.Get(ctx, req.NamespacedName, rb); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if rb.DeletionTimestamp != nil {
		delete(r.bannedIps, req.Name)
		ipsToBan := []string{}
		for _, ips := range r.bannedIps {
			for _, ip := range ips {
				ipsToBan = append(ipsToBan, ip)
			}
		}
		r.probe.UpdateMap(ipsToBan)
		return ctrl.Result{}, nil
	}

	if rb.Spec.Allow == nil {
		return ctrl.Result{}, nil
	}

	if rb.Spec.Allow.Deny == nil {
		return ctrl.Result{}, nil
	}

	r.bannedIps[req.Name] = rb.Spec.Allow.Deny.Network

	switch rb.Spec.Mode {
	case v1alpha1.ModeLearning:
		// todo
	case v1alpha1.ModeMonitor:
		// todo
	case v1alpha1.ModeEnforce:
		// load the bpf program with the new ips found
		ipsToBan := []string{}
		for _, ips := range r.bannedIps {
			for _, ip := range ips {
				ipsToBan = append(ipsToBan, ip)
			}
		}

		r.probe.UpdateMap(ipsToBan)
	}

	return ctrl.Result{}, nil
}
