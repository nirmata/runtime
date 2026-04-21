package main

import (
	"context"
	"flag"
	"os"
	"time"

	policyreportv1alpha2 "github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/config"
	"github.com/nirmata/kyverno-runtime/pkg/controller"
	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/pipeline"
	"github.com/nirmata/kyverno-runtime/pkg/policy"
)

func main() {
	var metricsAddr string
	var probeAddr string
	var enableLeaderElection bool
	var igExecTimeout time.Duration
	var reportBufferInterval time.Duration
	var reportBufferMaxCount int
	var enableBaselineEngine bool
	var enableSignatureEngine bool
	var enableAlertSinks bool
	var enableAlertAggregation bool

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	flag.DurationVar(&igExecTimeout, "inspektor-gadget-timeout", 8*time.Second, "Timeout for inspektor gadget runtime initialization.")
	flag.DurationVar(&reportBufferInterval, "report-buffer-interval", 10*time.Second, "Interval to flush buffered PolicyReport updates.")
	flag.IntVar(&reportBufferMaxCount, "report-buffer-max-count", 1000, "Maximum buffered findings before forcing a flush.")
	flag.BoolVar(&enableBaselineEngine, "feature-baseline-engine", false, "Enable baseline lifecycle and learning engine.")
	flag.BoolVar(&enableSignatureEngine, "feature-signature-engine", false, "Enable signature-based rule detection engine.")
	flag.BoolVar(&enableAlertSinks, "feature-alert-sinks", false, "Enable external alert sinks and routing.")
	flag.BoolVar(&enableAlertAggregation, "feature-alert-aggregation", false, "Enable cross-rule aggregation and suppression controls.")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	// Create feature gates configuration from flags
	features := config.FeatureGates{
		BaselineEngine:   enableBaselineEngine,
		SignatureEngine:  enableSignatureEngine,
		AlertSinks:       enableAlertSinks,
		AlertAggregation: enableAlertAggregation,
	}
	logger.Info("feature gates", "baselineEngine", features.BaselineEngine, "signatureEngine", features.SignatureEngine, "alertSinks", features.AlertSinks, "alertAggregation", features.AlertAggregation)

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(policyreportv1alpha2.Install(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	cfg := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "runtime.kyverno.io",
	})
	if err != nil {
		logger.Error(err, "failed to create manager")
		os.Exit(1)
	}

	// igExecTimeout is reused as the IG initialisation/context timeout;
	// streaming runs until the pod watch context is cancelled.
	igSource := datasource.NewInspektorGadgetSource(igExecTimeout, 0)

	evaluator := policy.NewEvaluator()
	matcher := pipeline.NewPolicyMatcher(evaluator)
	policyEvaluator := pipeline.NewPolicyEvaluator(evaluator)
	reporter := pipeline.NewK8sReporterWithOptions(mgr.GetClient(), pipeline.ReporterOptions{
		BufferInterval:   reportBufferInterval,
		MaxBufferedCount: reportBufferMaxCount,
	})

	watchManager := pipeline.NewWatchManager(igSource, policyEvaluator, reporter)

	// Create the DaemonSet-based reconciler
	reconciler := controller.NewDaemonSetReconciler(
		mgr.GetClient(),
		matcher,
		watchManager,
	)

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Watches(&v1alpha1.RuntimePolicy{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
			pods := &corev1.PodList{}
			if err := mgr.GetClient().List(ctx, pods); err != nil {
				return nil
			}
			requests := make([]reconcile.Request, 0, len(pods.Items))
			for i := range pods.Items {
				pod := &pods.Items[i]
				if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
					continue
				}
				requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}})
			}
			return requests
		})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
			ns, ok := obj.(*corev1.Namespace)
			if !ok {
				return nil
			}
			pods := &corev1.PodList{}
			if err := mgr.GetClient().List(ctx, pods, client.InNamespace(ns.Name)); err != nil {
				return nil
			}
			requests := make([]reconcile.Request, 0, len(pods.Items))
			for i := range pods.Items {
				pod := &pods.Items[i]
				if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
					continue
				}
				requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}})
			}
			return requests
		})).
		Complete(reconciler); err != nil {
		logger.Error(err, "failed to set up reconciler")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "failed to add health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "failed to add readiness check")
		os.Exit(1)
	}

	logger.Info("starting kyverno-runtime DaemonSet controller")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "manager exited non-zero")
		os.Exit(1)
	}
}
