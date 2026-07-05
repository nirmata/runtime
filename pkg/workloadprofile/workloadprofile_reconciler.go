package workloadprofile

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"

	protolearning "github.com/nirmata/kyverno-runtime/pkg/proto/learning"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	finalizerName = "runtime.kyverno.io/finalizer"
)

type workloadProfileReconciler struct {
	client.Client

	daemonSetEndpoints []string
	daemonsetSvcName   string
	daemonsetSvcNs     string

	observedWorkloadProfileUids map[string]struct{}
}

func NewWorkloadProfileController(c client.Client, daemonsetSvcNs string, daemonsetSvcName string) *workloadProfileReconciler {
	return &workloadProfileReconciler{
		Client:                      c,
		daemonsetSvcName:            daemonsetSvcName,
		daemonsetSvcNs:              daemonsetSvcNs,
		observedWorkloadProfileUids: make(map[string]struct{}),
	}
}

// +kubebuilder:rbac:groups=runtime.kyverno.io,resources=workloadprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=runtime.kyverno.io,resources=workloadprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=runtime.kyverno.io,resources=workloadprofiles/finalizers,verbs=update

func (r *workloadProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var obj v1alpha1.WorkloadProfile
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get resource: %w", err)
	}

	// Handle deletion / finalizer logic
	if !obj.DeletionTimestamp.IsZero() {
		err := r.handleDeleteWorkloadProfile(ctx, string(obj.UID))
		if err != nil {
			// single client errors don't matter. in any case clients flush out
			// workload profiles after the learning duration expires
			logger.Error(err, "failed to stop learning for workload profile")
		}

		if controllerutil.ContainsFinalizer(&obj, finalizerName) {
			controllerutil.RemoveFinalizer(&obj, finalizerName)
			if err := r.Update(ctx, &obj); err != nil {
				return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	_, ok := r.observedWorkloadProfileUids[string(obj.UID)]
	// new workload profile
	if !ok {
		return r.handleNewWorkloadProfile(ctx, &obj)
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
	// new workload profile ? call start on the endpoints
	// the workload profile was deleted ? call stop
	// the time duration ended ?

	// Update status subresource
	if err := r.Status().Update(ctx, &obj); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *workloadProfileReconciler) handleDeleteWorkloadProfile(ctx context.Context, profileUid string) error {
	errChan := make(chan error, len(r.daemonSetEndpoints))

	var wg sync.WaitGroup
	wg.Add(len(r.daemonSetEndpoints))

	for _, dsEndpoint := range r.daemonSetEndpoints {
		go func() {
			defer wg.Done()
			conn, err := grpc.NewClient(dsEndpoint)
			if err != nil {
				errChan <- err
			}

			learningClient := protolearning.NewLearningServiceClient(conn)
			r := &protolearning.StopRequest{
				Uid: profileUid,
			}
			// a single client's start request should exit in less than 3 seconds
			ctx, cancel := context.WithTimeout(ctx, time.Second*3)
			defer cancel()
			_, err = learningClient.Stop(ctx, r)
			if err != nil {
				errChan <- err
			}
		}()
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (r *workloadProfileReconciler) handleNewWorkloadProfile(ctx context.Context, wp *v1alpha1.WorkloadProfile) (ctrl.Result, error) {
	r.observedWorkloadProfileUids[string(wp.UID)] = struct{}{}

	// use a buffered channel so that all goroutines can send their errors
	// without waiting on the caller to consume those errors
	errChan := make(chan error, len(r.daemonSetEndpoints))

	var wg sync.WaitGroup
	wg.Add(len(r.daemonSetEndpoints))

	for _, dsEndpoint := range r.daemonSetEndpoints {
		go func() {
			defer wg.Done()
			conn, err := grpc.NewClient(dsEndpoint)
			if err != nil {
				errChan <- err
			}

			learningClient := protolearning.NewLearningServiceClient(conn)
			r := &protolearning.StartRequest{
				Uid:      string(wp.UID),
				Labels:   make(map[string]string), // todo
				Duration: durationpb.New(wp.Spec.Duration.Duration),
			}
			// a single client's start request should exit in less than 3 seconds
			ctx, cancel := context.WithTimeout(ctx, time.Second*3)
			defer cancel()
			_, err = learningClient.Start(ctx, r)
			if err != nil {
				errChan <- err
			}
		}()
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return ctrl.Result{}, errors.Join(errs...)
	}

	return ctrl.Result{}, nil
}

func (r *workloadProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.WorkloadProfile{}).
		Complete(r)

	informer, err := mgr.GetCache().GetInformer(context.Background(), &discoveryv1.EndpointSlice{})
	if err != nil {
		return err
	}
	logger := log.FromContext(context.Background())

	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			es := obj.(*discoveryv1.EndpointSlice)
			r.handleEndpointSliceEvent(es)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			es := newObj.(*discoveryv1.EndpointSlice)
			r.handleEndpointSliceEvent(es)
		},
		DeleteFunc: func(obj interface{}) {
			es, ok := obj.(*discoveryv1.EndpointSlice)
			if !ok {
				// handle cache.DeletedFinalStateUnknown
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				es = tombstone.Obj.(*discoveryv1.EndpointSlice)
			}

			if es.Labels["kubernetes.io/service-name"] != r.daemonsetSvcName || es.Namespace != r.daemonsetSvcNs {
				return
			}

			logger.Info("deleting the endpoint slice of the daemon ds will cause degredation in learning mode findings. please recreate it")
		},
	})
	return err
}

func (r *workloadProfileReconciler) handleEndpointSliceEvent(es *discoveryv1.EndpointSlice) {
	if es.Labels["kubernetes.io/service-name"] != r.daemonsetSvcName || es.Namespace != r.daemonsetSvcNs {
		// not the daemon ds endpoint slice. do nothing
		return
	}
	currentEndpoints := make([]string, len(es.Endpoints))
	for _, e := range es.Endpoints {
		if e.Conditions.Ready != nil && *e.Conditions.Ready {
			currentEndpoints = append(currentEndpoints, e.Addresses...)
		}
	}
	r.daemonSetEndpoints = currentEndpoints
}
