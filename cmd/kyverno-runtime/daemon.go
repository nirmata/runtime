package main

import (
	"errors"
	"os"
	"time"

	v1alpha1 "github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/attribution"
	"github.com/nirmata/runtime/pkg/bpf/dnsquery"
	"github.com/nirmata/runtime/pkg/bpf/exectrace"
	v1alpha1client "github.com/nirmata/runtime/pkg/client/clientset/versioned"
	"github.com/nirmata/runtime/pkg/collector"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/controller"
	"github.com/nirmata/runtime/pkg/dnsmgr"
	"github.com/nirmata/runtime/pkg/egressmgr"
	"github.com/nirmata/runtime/pkg/events"
	"github.com/nirmata/runtime/pkg/lsmmgr"
	"github.com/nirmata/runtime/pkg/metrics"
	"github.com/nirmata/runtime/pkg/monitor"
	"github.com/nirmata/runtime/pkg/pushsink"
	"github.com/nirmata/runtime/pkg/reporter"
	"github.com/nirmata/runtime/pkg/services"

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
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

// healthMaxHeartbeatAge is how long the collector's dispatch loop can go
// without ticking before /healthz reports it stalled.
const healthMaxHeartbeatAge = 30 * time.Second

// The names the managers' poll sources are registered under, and the source
// label of every metric attributed to them.
const (
	egressObserveSource = "egress-observe"
	lsmObserveSource    = "lsm-observe"
)

var (
	logLevel             int
	metricsAddr          string
	clusterDomain        string
	observeInterval      time.Duration
	eventBufferSize      int
	sourceRestartBackoff time.Duration
	pushTarget           string
	pushTLSCA            string
	pushTLSCert          string
	pushTLSKey           string
	reportsEnabled       bool
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
	daemonCmd.Flags().StringVar(&clusterDomain, "cluster-domain", "cluster.local",
		"The cluster's DNS domain. A network target under it names an in-cluster Service; any other name is an external one.")
	daemonCmd.Flags().DurationVar(&observeInterval, "observe-interval", defaultObserveInterval,
		"How often the BPF observation maps are drained. Bounds monitor-mode detection latency.")
	daemonCmd.Flags().IntVar(&eventBufferSize, "event-buffer-size", defaultEventBufferSize,
		"Depth of the collector's fan-in buffer. Events arriving when it is full are dropped and counted.")
	daemonCmd.Flags().DurationVar(&sourceRestartBackoff, "source-restart-backoff", defaultSourceRestartBackoff,
		"How long a failed event source waits before it is restarted.")
	daemonCmd.Flags().StringVar(&pushTarget, "push-target", "",
		"Address of a collector to stream findings to. Empty disables the push sink and opens no connection.")
	daemonCmd.Flags().StringVar(&pushTLSCA, "push-tls-ca", "",
		"PEM bundle verifying the collector named by --push-target. Required with it.")
	daemonCmd.Flags().StringVar(&pushTLSCert, "push-tls-cert", "",
		"PEM client certificate this daemon presents to the collector. Required with --push-target.")
	daemonCmd.Flags().StringVar(&pushTLSKey, "push-tls-key", "",
		"PEM private key for --push-tls-cert. Required with --push-target.")
	daemonCmd.Flags().BoolVar(&reportsEnabled, "reports-enabled", true,
		"Write findings to namespaced OpenReports Report resources. Set to false for deployments that consume findings only through --push-target.")
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

	logger.Info("starting kyverno-runtime daemon", "clusterDomain", clusterDomain)

	// the domain decides whether a network target is a Service or an external
	// name, so it has to be in place before the first policy is compiled.
	compiler.ClusterDomain = clusterDomain

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
	// openreports types installed. It is only constructed when the reporter
	// is, so a disabled reporter opens no OpenReports connection.
	var orClient crclient.Client
	if reportsEnabled {
		orClient, err = crclient.New(cfg, crclient.Options{Scheme: scheme})
		if err != nil {
			logger.Error(err, "failed to create controller-runtime client")
			os.Exit(1)
		}
	}

	dclient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "failed to create dynamic client")
		os.Exit(1)
	}

	resolver := services.NewResolver(k8sClient, logger.WithName("services"))

	rpCompiler, err := compiler.NewCompiler(dclient, resolver)
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

	// attribution is both a pod-event handler (it builds the cgroup -> pod map)
	// and a collector stage (it annotates events and drops unattributed ones).
	attrIdx := attribution.NewIndex(logger.WithName("attribution"), attribution.WithMetrics(m))

	var rep *reporter.Reporter
	if reportsEnabled {
		rep = reporter.New(orClient, logger.WithName("reporter"), m, reporter.Options{NodeName: nodeName})
	} else {
		logger.Info("openreports writes disabled (--reports-enabled=false)")
	}

	// nodeFactory backs shard pruning: the status writer drops another node's
	// entry from status.nodes only when this watch says the node is gone. The
	// transform keeps just the name, which is all the existence check reads.
	nodeFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	nodeInformer := nodeFactory.Core().V1().Nodes().Informer()
	_ = nodeInformer.SetTransform(func(obj any) (any, error) {
		if n, ok := obj.(*corev1.Node); ok {
			return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n.Name}}, nil
		}
		return obj, nil
	})
	nodeFactory.Start(ctx.Done())
	nodeGone := func(name string) bool {
		// before the first sync the watch cannot distinguish a deleted node
		// from one it has not listed yet
		if !nodeInformer.HasSynced() {
			return false
		}
		_, exists, err := nodeInformer.GetStore().GetByKey(name)
		return err == nil && !exists
	}

	// sw owns this node's shard of every RuntimePolicy status.
	sw := controller.NewStatusWriter(c, nodeName, controller.DefaultStatusFlushInterval, logger.WithName("statuswriter"), nodeGone)

	em := egressmgr.NewEgressManager(logger, sw, func(reason string, delta uint64) {
		m.EventsDropped.WithLabelValues(egressObserveSource, reason).Add(float64(delta))
	})

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

	var push *pushsink.GRPCSink
	if pushTarget != "" {
		push, err = pushsink.New(logger.WithName(pushsink.SourceName), pushsink.Options{
			Target:   pushTarget,
			CAFile:   pushTLSCA,
			CertFile: pushTLSCert,
			KeyFile:  pushTLSKey,
			LossFunc: func(reason string, delta uint64) {
				m.EventsDropped.WithLabelValues(pushsink.SourceName, reason).Add(float64(delta))
			},
		})
		if err != nil {
			logger.Error(err, "failed to create push sink")
			os.Exit(1)
		}
	}

	// Findings fan out to whichever sinks are configured: the reporter when
	// reports are enabled, and the push sink when a collector target is set.
	sinks := findingSinks(rep, push)

	// mon evaluates observed events against monitor-mode policies and turns
	// matches into findings.
	mon := monitor.New(logger.WithName("monitor"), sinks, m)

	// monitor holds no pod state, so its namespaceSelector input arrives here
	// rather than on the pod events the other handlers read it from.
	nsHandlers := []events.NamespaceEventHandler{mon}

	// Handlers are dispatched concurrently, so ordering between them is not
	// guaranteed. An event observed before attribution has indexed its pod is
	// dropped by the attribution stage and counted, never misattributed.
	podHandlers := []events.PodEventHandler{em, attrIdx}
	policyHandlers := []events.RuntimePolicyEventHandler{em, sw, mon}

	// Poll the managers' observation maps, attribute, then hand to the monitor.
	col := collector.New(logger.WithName("collector"), eventBufferSize, sourceRestartBackoff, m)
	col.AddSource(collector.NewPollSource(egressObserveSource, observeInterval, em.CollectObservations))

	// LSM manager init may fail, and in that case only the other enforcers will work.
	// Try to initialize it and add it to the event sources
	lsmm, err := lsmmgr.NewLsmManager(logger, sw, func(reason string, delta uint64) {
		m.EventsDropped.WithLabelValues(lsmObserveSource, reason).Add(float64(delta))
	}, execSinks...)
	if err != nil {
		logger.Error(err, "failed to create lsm manager, exec and open enforcement won't work")
	} else {
		podHandlers = append(podHandlers, lsmm)
		policyHandlers = append(policyHandlers, lsmm)
		col.AddSource(collector.NewPollSource(lsmObserveSource, observeInterval, lsmm.CollectObservations))
	}

	// A typed nil in the Source interface is not nil, so the check is here
	// rather than left to AddSource.
	if execSrc != nil {
		col.AddSource(execSrc)
	}
	col.AddStage(attrIdx)
	col.AddSink(mon)

	// DNS observation is best effort: a kernel that will not load the
	// cgroup_skb program leaves every other behavior working.
	if dnsObs, err := dnsquery.New(); err != nil {
		logger.Error(err, "dns question observation disabled")
	} else {
		defer func() { _ = dnsObs.Close() }()
		dm := dnsmgr.New(logger.WithName("dnsmgr"), dnsObs)
		podHandlers = append(podHandlers, dm)
		policyHandlers = append(policyHandlers, dm)
		col.AddSource(dnsquery.NewSource(logger.WithName(dnsquery.SourceName), dnsObs,
			dnsquery.WithStatsInterval(observeInterval),
			dnsquery.WithLossFunc(func(reason string, delta uint64) {
				m.EventsDropped.WithLabelValues(dnsquery.SourceName, reason).Add(float64(delta))
			})))
	}

	// runtime policy informer. Constructing it registers its service change
	// handler on the resolver, which has to happen before the resolver starts.
	rpInformer, err := controller.NewRuntimePolicyMgr(cfg, policyHandlers, c, rpCompiler, resolver, sw)
	if err != nil {
		logger.Error(err, "failed to create runtime policy informer")
		os.Exit(1)
	}

	if metricsAddr != "" {
		health := func() error {
			if !rpInformer.HasSynced() {
				return errors.New("runtime policy cache not synced")
			}
			if !col.Healthy(healthMaxHeartbeatAge) {
				return errors.New("collector loop stalled")
			}
			return nil
		}
		g.Go(func() error {
			return metrics.Serve(ctx, metricsAddr, reg, health, logger.WithName("metrics"))
		})
	} else {
		logger.Info("metrics endpoint disabled (--metrics-addr is empty)")
	}

	// a policy compiled from an unsynced service cache resolves its references to
	// nothing, so a default deny would black-hole the egress of every pod it
	// matches: the resolver syncs before the policy informer programs anything.
	g.Go(func() error { return resolver.Start(ctx) })
	if !cache.WaitForCacheSync(ctx.Done(), resolver.HasSynced) {
		logger.Info("service resolver caches did not sync")
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
	pw := controller.NewPodWatcher(k8sClient, nodeName, podHandlers, nsHandlers)
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
	if rep != nil {
		g.Go(func() error { return rep.Run(ctx) })
	}
	if push != nil {
		g.Go(func() error { return push.Run(ctx) })
	}

	if err := g.Wait(); err != nil {
		logger.Error(err, "failed to wait for informer threads")
		os.Exit(1)
	}

	return nil
}

// findingSinks assembles the monitor's fan-out. Absent sinks are skipped here
// rather than appended: a typed nil in the interface slice would pass every
// nil check downstream and panic on the first finding.
func findingSinks(rep *reporter.Reporter, push *pushsink.GRPCSink) []monitor.FindingSink {
	var sinks []monitor.FindingSink
	if rep != nil {
		sinks = append(sinks, rep)
	}
	if push != nil {
		sinks = append(sinks, push)
	}
	return sinks
}
