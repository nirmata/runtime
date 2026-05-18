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
	bannedIps map[string]struct{}
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
		bannedIps: make(map[string]struct{}),
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
		return ctrl.Result{}, nil
	}

	for _, ip := range rb.Spec.Allow.Deny.Network {
		// register this ip so that its banned
		r.bannedIps[ip] = struct{}{}
	}

	switch rb.Spec.Mode {
	case v1alpha1.ModeLearning:
		// todo
	case v1alpha1.ModeMonitor:
		// todo
	case v1alpha1.ModeEnforce:
		// load the bpf program with the new ips found

	}

	return ctrl.Result{}, nil
}
