package main

import (
	"os"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/controller"
	"github.com/nirmata/kyverno-runtime/pkg/workloadprofile"

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var ctrlCmd = &cobra.Command{
	Use:   "ctrl",
	Short: "Run the workload profile controller",
	RunE:  runCtrl,
}

var (
	daemonsetSvcName     string
	daemonsetSvcNs       string
	metricsAddr          string
	probeAddr            string
	enableLeaderElection bool
)

func init() {
	ctrlCmd.Flags().StringVar(&daemonsetSvcName, "daemonset-svc-name", "runtime-ds", "The name of the kyverno runtime daemon daemonset")
	ctrlCmd.Flags().StringVar(&daemonsetSvcNs, "daemonset-svc-ns", "kyverno-runtime", "The namespace of the kyverno runtime daemon daemonset")
	ctrlCmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	ctrlCmd.Flags().StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	ctrlCmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for the workload profile controller.")
}

func runCtrl(cmd *cobra.Command, args []string) error {
	// we should configure a proper logger here
	opts := zap.Options{
		Development: true,
		EncoderConfigOptions: []zap.EncoderConfigOption{
			func(c *zapcore.EncoderConfig) { c.EncodeLevel = verbosityLevelEncoder },
		},
	}

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

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

	dsr, err := controller.NewDsEndpointResolver(mgr, daemonsetSvcNs, daemonsetSvcName)
	if err != nil {
		logger.Error(err, "failed to create daemonset endpoint resolver")
		os.Exit(1)
	}

	wpController := workloadprofile.NewWorkloadProfileController(mgr.GetClient(), dsr.GetEndpoints)
	err = wpController.SetupWithManager(mgr)
	if err != nil {
		logger.Error(err, "error registering the workload profile controller with the manager")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	if err := mgr.Start(ctx); err != nil {
		os.Exit(1)
	}
	// and a http server that receives a request from the cli client

	return nil
}
