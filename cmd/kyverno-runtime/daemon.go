package main

import (
	"os"
	"time"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/attribution"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/exectrace"
	v1alpha1client "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned"
	"github.com/nirmata/kyverno-runtime/pkg/collector"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/controller"
	"github.com/nirmata/kyverno-runtime/pkg/egressmgr"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/lsmmgr"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/monitor"
	"github.com/nirmata/kyverno-runtime/pkg/reporter"

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// Defaults for the daemon's tunables.
const (
	defaultObserveInterval      = 10 * time.Second
	defaultEventBufferSize      = collector.DefaultBufferSize
	defaultSourceRestartBackoff = collector.DefaultRestartBackoff
)

var (
	logLevel             int
	metricsAddr          string
	observeInterval      time.Duration
	eventBufferSize      int
	sourceRestartBackoff time.Duration
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run the kyverno-runtime daemon",
	RunE:  runDaemon,
}

func init() {
	daemonCmd.Flags().IntVar(&logLevel, "log-level", 0, "Verbosity level for debug logs (higher is more verbose).")
	daemonCmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":9090",
		"Address the Prometheus /metrics endpoint binds to. Set to an empty string to disable it.")
	daemonCmd.Flags().DurationVar(&observeInterval, "observe-interval", defaultObserveInterval,
		"How often the BPF observation maps are drained. Bounds monitor-mode detection latency.")
	daemonCmd.Flags().IntVar(&eventBufferSize, "event-buffer-size", defaultEventBufferSize,
		"Depth of the collector's fan-in buffer. Events arriving when it is full are dropped and counted.")
	daemonCmd.Flags().DurationVar(&sourceRestartBackoff, "source-restart-backoff", defaultSourceRestartBackoff,
		"How long a failed event source waits before it is restarted.")
}

func runDaemon(cmd *cobra.Command, args []string) error {
	opts := zap.Options{
		Development: true,
		Level:       zapcore.Level(-logLevel),
		EncoderConfigOptions: []zap.EncoderConfigOption{
			func(c *zapcore.EncoderConfig) { c.EncodeLevel = verbosityLevelEncoder },
		},
	}

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	logger.Info("starting kyverno-runtime daemon")

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(openreportsv1alpha1.Install(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	cfg := ctrl.GetConfigOrDie()

	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "failed to create kubernetes client")
		os.Exit(1)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		logger.Info("NODE_NAME must be provided")
		os.Exit(1)
	}

	c, err := v1alpha1client.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "failed to create v1alpha1 client")
		os.Exit(1)
	}

	// orClient writes OpenReports Reports; the scheme above already has the
	// openreports types installed.
	orClient, err := crclient.New(cfg, crclient.Options{Scheme: scheme})
	if err != nil {
		logger.Error(err, "failed to create controller-runtime client")
		os.Exit(1)
	}

	dclient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "failed to create dynamic client")
		os.Exit(1)
	}

	rpCompiler, err := compiler.NewCompiler(dclient)
	if err != nil {
		logger.Error(err, "failed to create runtime policy compiler")
		os.Exit(1)
	}

	sigCtx := ctrl.SetupSignalHandler()
	g, ctx := errgroup.WithContext(sigCtx)

	// a private registry so repeated wiring never panics on duplicate
	// registration
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	if metricsAddr != "" {
		g.Go(func() error {
			return metrics.Serve(ctx, metricsAddr, reg, logger.WithName("metrics"))
		})
	} else {
		logger.Info("metrics endpoint disabled (--metrics-addr is empty)")
	}

	// attribution is both a pod-event handler (it builds the cgroup -> pod map)
	// and a collector stage (it annotates events and drops unattributed ones).
	attrIdx := attribution.NewIndex(logger.WithName("attribution"), attribution.WithMetrics(m))

	rep := reporter.New(orClient, logger.WithName("reporter"), m, reporter.Options{NodeName: nodeName})

	// sw owns this node's shard of every RuntimePolicy status.
	sw := controller.NewStatusWriter(c, nodeName, controller.DefaultStatusFlushInterval, logger.WithName("statuswriter"))

	em := egressmgr.NewEgressManager(logger, sw)

	// The exec tracer is optional: a kernel without the ring buffer or the
	// sched_process_exec raw tracepoint still runs everything else. A nil
	// source is skipped by AddSource and mirrors no cgroups.
	var execSinks []lsmmgr.CgroupSink
	execSrc, err := exectrace.New(logger.WithName("exectrace"), observeInterval)
	if err != nil {
		logger.Error(err, "exec tracing unavailable; argv will not be observed")
		execSrc = nil
	} else {
		defer func() { _ = execSrc.Close() }()
		execSinks = append(execSinks, execSrc)
	}

	lsmm := lsmmgr.NewLsmManager(logger, sw, execSinks...)

	// mon evaluates observed events against monitor-mode policies and turns
	// matches into findings.
	mon := monitor.New(logger.WithName("monitor"), rep, m)

	// Handlers are dispatched concurrently, so ordering between them is not
	// guaranteed. An event observed before attribution has indexed its pod is
	// dropped by the attribution stage and counted, never misattributed.
	podHandlers := []events.PodEventHandler{em, lsmm, attrIdx}
	policyHandlers := []events.RuntimePolicyEventHandler{em, lsmm, sw, mon}

	// Poll the managers' observation maps, attribute, then hand to the monitor.
	col := collector.New(logger.WithName("collector"), eventBufferSize, sourceRestartBackoff, m)
	col.AddSource(collector.NewPollSource("egress-observe", observeInterval, em.CollectObservations))
	col.AddSource(collector.NewPollSource("lsm-observe", observeInterval, lsmm.CollectObservations))
	// A typed nil in the Source interface is not nil, so the check is here
	// rather than left to AddSource.
	if execSrc != nil {
		col.AddSource(execSrc)
	}
	col.AddStage(attrIdx)
	col.AddSink(mon)

	// runtime policy informer
	rpInformer, err := controller.NewRuntimePolicyMgr(cfg, policyHandlers, c, rpCompiler)
	if err != nil {
		logger.Error(err, "failed to create runtime policy informer")
		os.Exit(1)
	}
	g.Go(func() error {
		for {
			if err := rpInformer.Start(ctx); err != nil {
				logger.Error(err, "runtime policy informer error, sleeping 10 seconds and trying again")
				time.Sleep(time.Second * 10)
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
	pw := controller.NewPodWatcher(k8sClient, nodeName, podHandlers)
	g.Go(func() error {
		for {
			if err := pw.Start(ctx); err != nil {
				logger.Error(err, "pod watcher error, sleeping 10 seconds then trying again")
				time.Sleep(time.Second * 10)
				continue
			}
		}
	})

	g.Go(func() error { return col.Run(ctx) })
	g.Go(func() error { return sw.Run(ctx) })
	g.Go(func() error { return rep.Run(ctx) })

	if err := g.Wait(); err != nil {
		logger.Error(err, "failed to wait for informer threads")
		os.Exit(1)
	}

	return nil
}
