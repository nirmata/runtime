package workloadprofile

import (
	"context"
	"fmt"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	finalizerName = "runtime.kyverno.io/finalizer"
)

type WorkloadProfileReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=runtime.kyverno.io,resources=workloadprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=runtime.kyverno.io,resources=workloadprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=runtime.kyverno.io,resources=workloadprofiles/finalizers,verbs=update

func (r *WorkloadProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj v1alpha1.WorkloadProfile
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get resource: %w", err)
	}

	// Handle deletion / finalizer logic
	if !obj.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&obj, finalizerName) {
			controllerutil.RemoveFinalizer(&obj, finalizerName)
			if err := r.Update(ctx, &obj); err != nil {
				return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure finalizer present before doing real work
	if !controllerutil.ContainsFinalizer(&obj, finalizerName) {
		controllerutil.AddFinalizer(&obj, finalizerName)
		if err := r.Update(ctx, &obj); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// add reconcile logic here

	// Update status subresource
	if err := r.Status().Update(ctx, &obj); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *WorkloadProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.WorkloadProfile{}).
		Complete(r)
}
