package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/pipeline"
)

// DaemonSetReconciler watches Pods and keeps streaming eBPF watches in sync
// with the set of matching RuntimePolicies. Actual event collection, evaluation,
// and reporting happen inside the WatchManager — not on the reconcile path.
type DaemonSetReconciler struct {
	client       client.Client
	matcher      pipeline.Matcher
	watchManager *pipeline.WatchManager
}

// NewDaemonSetReconciler creates a new DaemonSetReconciler.
func NewDaemonSetReconciler(
	c client.Client,
	matcher pipeline.Matcher,
	watchManager *pipeline.WatchManager,
) *DaemonSetReconciler {
	return &DaemonSetReconciler{
		client:       c,
		matcher:      matcher,
		watchManager: watchManager,
	}
}

// Reconcile syncs the streaming watch state for a Pod. It is called whenever
// a Pod or RuntimePolicy changes. It does not collect events directly.
func (r *DaemonSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Get the pod.
	pod := &corev1.Pod{}
	if err := r.client.Get(ctx, req.NamespacedName, pod); err != nil {
		if apierrors.IsNotFound(err) {
			// Pod gone — WatchManager cleans up via context cancellation when
			// the controller-runtime context is cancelled or next sync.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Only watch Running pods; skip pods that are terminating or not yet scheduled.
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		r.watchManager.StopPod(pod)
		return ctrl.Result{}, nil
	}

	// Get the namespace to access labels for policy matching.
	ns := &corev1.Namespace{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: pod.Namespace}, ns); err != nil {
		return ctrl.Result{}, err
	}

	// List all RuntimePolicies and find those matching this pod.
	policies := &v1alpha1.RuntimePolicyList{}
	if err := r.client.List(ctx, policies); err != nil {
		return ctrl.Result{}, err
	}

	matched := make([]*v1alpha1.RuntimePolicy, 0)
	for i := range policies.Items {
		p := &policies.Items[i]
		ok, err := r.matcher.Matches(p, pod, ns.Labels)
		if err != nil {
			return ctrl.Result{}, err
		}
		if ok {
			matched = append(matched, p)
		}
	}

	// Sync streaming watches — start for matched policies, stop if none match.
	r.watchManager.Sync(ctx, pod, matched)
	return ctrl.Result{}, nil
}
