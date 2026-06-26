package main

import (
	"flag"
	"log"
	"os"
	"time"

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"

	v1alpha1client "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned"
	v1alpha1informers "github.com/nirmata/kyverno-runtime/pkg/client/informers/externalversions"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/lsmmgr"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/config"
	"github.com/nirmata/kyverno-runtime/pkg/controller"
	"github.com/nirmata/kyverno-runtime/pkg/egressmgr"
	"github.com/nirmata/kyverno-runtime/pkg/pods"
	"github.com/nirmata/kyverno-runtime/pkg/preflight"
)

func main() {
	var metricsAddr string
	var probeAddr string
	var enableLeaderElection bool
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

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.DurationVar(&reportBufferInterval, "report-buffer-interval", 10*time.Second, "Interval to flush buffered PolicyReport updates.")
	flag.IntVar(&reportBufferMaxCount, "report-buffer-max-count", 1000, "Maximum buffered findings before forcing a flush.")
	flag.DurationVar(&reportSuppressionCooldown, "report-suppression-cooldown", 30*time.Second, "Rolling cooldown window for duplicate finding suppression.")
	flag.IntVar(&reportSuppressionBurst, "report-suppression-burst", 20, "Maximum duplicate finding updates per fingerprint in one cooldown window.")
	flag.DurationVar(&reportEventCooldown, "report-event-cooldown", 30*time.Second, "Rolling cooldown window for Kubernetes Event emission dedup/rate-limit.")
	flag.IntVar(&reportEventBurst, "report-event-burst", 10, "Maximum Kubernetes Events emitted per fingerprint in one cooldown window.")

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

	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		os.Exit(1)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		logger.Info("NODE_NAME must be provided")
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

	eventHandlers := []events.EventIface{egressmgr.NewEgressManager(), lsmmgr.NewLsmManager()}
	c, err := v1alpha1client.NewForConfig(cfg)
	if err != nil {
		os.Exit(1)
	}

	factory := v1alpha1informers.NewSharedInformerFactory(c, 0)
	rpCompiler, err := compiler.NewCompiler()
	if err != nil {
		os.Exit(1)
	}

	rbInformer, err := controller.NewRuntimePolicyMgr(cfg, eventHandlers, factory, rpCompiler)
	if err != nil {
		os.Exit(1)
	}

	sigCtx := ctrl.SetupSignalHandler()

	go func() {
		rbInformer.Start(sigCtx)
	}()

	// sync the runtime behaviors before syncing pods
	if !cache.WaitForCacheSync(sigCtx.Done(), factory.Runtime().V1alpha1().RuntimePolicies().Informer().HasSynced) {
		log.Printf("timed out waiting for cache sync")
		os.Exit(1)
	}

	// todo: how to make it durable with restarts ? again.. refer to the policy reporter
	pw := pods.NewPodWatcher(k8sClient, nodeName, eventHandlers)
	pw.Start(sigCtx)
}
