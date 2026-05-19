package main

import (
	"flag"
	"os"
	"strings"
	"time"

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/config"
	"github.com/nirmata/kyverno-runtime/pkg/controller"
	"github.com/nirmata/kyverno-runtime/pkg/preflight"
)

func main() {
	var metricsAddr string
	var probeAddr string
	var enableLeaderElection bool
	var igExecTimeout time.Duration
	var reportBufferInterval time.Duration
	var reportBufferMaxCount int
	var reportSuppressionCooldown time.Duration
	var reportSuppressionBurst int
	var reportEventCooldown time.Duration
	var reportEventBurst int
	var enableBaselineEngine bool
	var enableSignatureEngine bool
	var enableAlertSinks bool
	var enableAlertAggregation bool
	var runtimeBehaviorAutoCreate bool
	var runtimeBehaviorIncludeControllers string
	var runtimeBehaviorIncludeBarePods bool
	var runtimeBehaviorIncludeNamespaces string
	var runtimeBehaviorExcludeNamespaces string
	var runtimeBehaviorInitialMode string
	var runtimeBehaviorOptOutLabel string
	var sharedDefaultsNamespace string

	defaults := config.DefaultFeatures()

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	flag.DurationVar(&igExecTimeout, "inspektor-gadget-timeout", 8*time.Second, "Timeout for inspektor gadget runtime initialization.")
	flag.DurationVar(&reportBufferInterval, "report-buffer-interval", 10*time.Second, "Interval to flush buffered PolicyReport updates.")
	flag.IntVar(&reportBufferMaxCount, "report-buffer-max-count", 1000, "Maximum buffered findings before forcing a flush.")
	flag.DurationVar(&reportSuppressionCooldown, "report-suppression-cooldown", 30*time.Second, "Rolling cooldown window for duplicate finding suppression.")
	flag.IntVar(&reportSuppressionBurst, "report-suppression-burst", 20, "Maximum duplicate finding updates per fingerprint in one cooldown window.")
	flag.DurationVar(&reportEventCooldown, "report-event-cooldown", 30*time.Second, "Rolling cooldown window for Kubernetes Event emission dedup/rate-limit.")
	flag.IntVar(&reportEventBurst, "report-event-burst", 10, "Maximum Kubernetes Events emitted per fingerprint in one cooldown window.")
	flag.BoolVar(&enableBaselineEngine, "feature-baseline-engine", defaults.BaselineEngine, "Enable baseline lifecycle and learning engine.")
	flag.BoolVar(&enableSignatureEngine, "feature-signature-engine", defaults.SignatureEngine, "Enable signature-based rule detection engine.")
	flag.BoolVar(&enableAlertSinks, "feature-alert-sinks", false, "Enable external alert sinks and routing.")
	flag.BoolVar(&enableAlertAggregation, "feature-alert-aggregation", defaults.AlertAggregation, "Enable cross-rule aggregation and suppression controls.")
	flag.BoolVar(&runtimeBehaviorAutoCreate, "runtimebehavior-auto-create", true, "Enable automatic RuntimeBehavior creation for enrolled workloads.")
	flag.StringVar(&runtimeBehaviorIncludeControllers, "runtimebehavior-include-controllers", "Deployment,StatefulSet,DaemonSet,Job,CronJob,ReplicaSet", "Comma-separated controller kinds for RuntimeBehavior auto-enrollment.")
	flag.BoolVar(&runtimeBehaviorIncludeBarePods, "runtimebehavior-include-bare-pods", false, "Whether bare pods are eligible for RuntimeBehavior auto-enrollment.")
	flag.StringVar(&runtimeBehaviorIncludeNamespaces, "runtimebehavior-include-namespaces", "", "Optional comma-separated namespace allow-list for RuntimeBehavior auto-enrollment.")
	flag.StringVar(&runtimeBehaviorExcludeNamespaces, "runtimebehavior-exclude-namespaces", "kube-system,kyverno-runtime", "Comma-separated namespace deny-list for RuntimeBehavior auto-enrollment.")
	flag.StringVar(&runtimeBehaviorInitialMode, "runtimebehavior-initial-mode", "learning", "Initial mode for auto-created RuntimeBehavior resources: learning|monitor.")
	flag.StringVar(&runtimeBehaviorOptOutLabel, "runtimebehavior-optout-label", "", "Optional label key to allow auditable RuntimeBehavior opt-out.")
	flag.StringVar(&sharedDefaultsNamespace, "shared-defaults-namespace", "kyverno-runtime", "Namespace to discover shared RuntimeBehavior defaults.")

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
	utilruntime.Must(openreportsv1alpha1.Install(scheme))
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
	// igSource := datasource.NewInspektorGadgetSource(igExecTimeout, 0)

	runtimeBehaviorReconciler, err := controller.NewRuntimeBehaviorReconciler(mgr.GetClient())
	if err != nil {
		logger.Error(err, "failed to set up RuntimeBehavior reconciler")
		os.Exit(1)
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.RuntimeBehavior{}).
		Complete(runtimeBehaviorReconciler); err != nil {
		logger.Error(err, "failed to set up RuntimeBehavior reconciler")
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
	if err := mgr.AddReadyzCheck("ebpf-preflight", preflight.EBPFCapabilityCheck); err != nil {
		logger.Error(err, "failed to add eBPF preflight readiness check")
		os.Exit(1)
	}
	// if err := mgr.AddReadyzCheck("ebpf-operators", func(req *http.Request) error {
	// 	select {
	// 	case <-operatorsReady:
	// 		return nil
	// 	default:
	// 		return fmt.Errorf("eBPF gadget operators are still initializing")
	// 	}
	// }); err != nil {
	// 	logger.Error(err, "failed to add eBPF operators readiness check")
	// 	os.Exit(1)
	// }

	logger.Info("starting kyverno-runtime DaemonSet controller")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "manager exited non-zero")
		os.Exit(1)
	}
}

func parseCSVSet(value string) map[string]bool {
	out := map[string]bool{}
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		out[token] = true
	}
	return out
}
