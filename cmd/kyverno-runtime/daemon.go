package main

import (
	"net"
	"os"
	"time"

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	v1alpha1client "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/lsmmgr"
	pb "github.com/nirmata/kyverno-runtime/pkg/proto/learning"
	"github.com/nirmata/kyverno-runtime/pkg/srv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/controller"
	"github.com/nirmata/kyverno-runtime/pkg/egressmgr"
)

var (
	metricsAddr               string
	probeAddr                 string
	httpAddr                  string
	grpcAddr                  string
	enableLeaderElection      bool
	reportBufferInterval      time.Duration
	reportBufferMaxCount      int
	reportSuppressionCooldown time.Duration
	reportSuppressionBurst    int
	reportEventCooldown       time.Duration
	reportEventBurst          int
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run the kyverno-runtime daemon",
	RunE:  runDaemon,
}

func init() {
	daemonCmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	daemonCmd.Flags().StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	daemonCmd.Flags().StringVar(&httpAddr, "http-bind-address", ":8090", "The address the HTTP server binds to.")
	daemonCmd.Flags().StringVar(&grpcAddr, "grpc-bind-address", ":9090", "The address the gRPC server binds to.")
	daemonCmd.Flags().DurationVar(&reportBufferInterval, "report-buffer-interval", 10*time.Second, "Interval to flush buffered PolicyReport updates.")
	daemonCmd.Flags().IntVar(&reportBufferMaxCount, "report-buffer-max-count", 1000, "Maximum buffered findings before forcing a flush.")
	daemonCmd.Flags().DurationVar(&reportSuppressionCooldown, "report-suppression-cooldown", 30*time.Second, "Rolling cooldown window for duplicate finding suppression.")
	daemonCmd.Flags().IntVar(&reportSuppressionBurst, "report-suppression-burst", 20, "Maximum duplicate finding updates per fingerprint in one cooldown window.")
	daemonCmd.Flags().DurationVar(&reportEventCooldown, "report-event-cooldown", 30*time.Second, "Rolling cooldown window for Kubernetes Event emission dedup/rate-limit.")
	daemonCmd.Flags().IntVar(&reportEventBurst, "report-event-burst", 10, "Maximum Kubernetes Events emitted per fingerprint in one cooldown window.")
}

func runDaemon(cmd *cobra.Command, args []string) error {
	opts := zap.Options{Development: true}

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(openreportsv1alpha1.Install(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	cfg := ctrl.GetConfigOrDie()

	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		os.Exit(1)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		logger.Info("NODE_NAME must be provided")
		os.Exit(1)
	}
	// initialize the bpf program wrappers
	em := egressmgr.NewEgressManager()
	lsmm := lsmmgr.NewLsmManager()

	eventHandlers := []events.EventIface{em, lsmm}
	c, err := v1alpha1client.NewForConfig(cfg)
	if err != nil {
		os.Exit(1)
	}

	rpCompiler, err := compiler.NewCompiler()
	if err != nil {
		os.Exit(1)
	}

	sigCtx := ctrl.SetupSignalHandler()
	g, ctx := errgroup.WithContext(sigCtx)

	// runtime policy informer
	rpInformer, err := controller.NewRuntimePolicyMgr(cfg, eventHandlers, c, rpCompiler)
	if err != nil {
		os.Exit(1)
	}
	g.Go(func() error {
		for {
			if err := rpInformer.Start(ctx); err != nil {
				logger.Error(err, "runtime policy informer error")
				continue
			}
		}
	})

	// wait for runtime policy cache sync so that when we start the pod informer we have
	// synced the policies
	if !cache.WaitForCacheSync(ctx.Done(), rpInformer.HasSynced) {
		os.Exit(1)
	}

	// pod informer
	pw := controller.NewPodWatcher(k8sClient, nodeName, eventHandlers)
	g.Go(func() error {
		for {
			if err := pw.Start(ctx); err != nil {
				logger.Error(err, "pod watcher error")
				continue
			}
		}
	})

	// grpc server
	grpcServer := grpc.NewServer()
	pb.RegisterLearningServiceServer(grpcServer, srv.NewLeaningModeSrv(lsmm, em))
	g.Go(func() error {
		lis, err := net.Listen("tcp", grpcAddr)
		if err != nil {
			logger.Error(err, "failed to listen for gRPC server")
			return err
		}

		logger.Info("starting gRPC server", "address", grpcAddr)
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error(err, "gRPC server error")
			os.Exit(1)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		logger.Error(err, "failed to wait for informer threads")
		os.Exit(1)
	}

	return nil
}
