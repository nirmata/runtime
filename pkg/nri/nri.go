package nri

import (
	"context"
	"fmt"
	"maps"

	"github.com/nirmata/runtime/pkg/containers"
	"github.com/nirmata/runtime/pkg/openexecmgr"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const pluginName = "kyverno-runtime"

type Nri struct {
	stub     stub.Stub
	log      logr.Logger
	openExec *openexecmgr.OpenExecManager
	// nsLabels returns a namespace's labels: nri carries none.
	nsLabels func(namespace string) (map[string]string, error)
	// written in Configure, which the stub's Start waits on before Run can
	// return, so the daemon reads it without a race
	registered bool
}

func New(socketPath string, log logr.Logger, openExec *openexecmgr.OpenExecManager, nsLabels func(string) (map[string]string, error)) (*Nri, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("invalid NRI configuration: empty socket path")
	}
	n := &Nri{log: log, openExec: openExec, nsLabels: nsLabels}
	s, err := stub.New(n,
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx("10"),
		stub.WithSocketPath(socketPath),
		stub.WithLogger(nriLogger{log}),
	)
	if err != nil {
		return nil, fmt.Errorf("creating nri plugin: %w", err)
	}
	n.stub = s
	return n, nil
}

func (n *Nri) Run(ctx context.Context) error {
	return n.stub.Run(ctx)
}

// Registered reports whether the runtime has ever accepted this plugin.
func (n *Nri) Registered() bool {
	return n.registered
}

func (n *Nri) Configure(_ context.Context, _, runtime, version string) (api.EventMask, error) {
	n.registered = true
	n.log.Info("registered with container runtime over nri", "runtime", runtime, "version", version)
	return api.ParseEventMask("StartContainer")
}

// StartContainer runs once the container's cgroup and init process exist but
// before the entrypoint is executed, and the runtime waits for it to return.
func (n *Nri) StartContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	if ctr.GetPid() == 0 {
		n.log.Error(nil, "container has no pid at start, not registered", "podUid", pod.GetUid(), "container", ctr.GetName())
		return nil
	}
	cgInfo, err := containers.ResolveCgroupByPID("/proc", ctr.GetPid())
	if err != nil {
		n.log.Error(err, "failed to resolve container cgroup, not registered", "podUid", pod.GetUid(), "container", ctr.GetName())
		return nil
	}

	// an empty label set would unselect the pod from every namespaceSelector
	// policy, so the pod informer is left to register it instead
	nsLabels, err := n.nsLabels(pod.GetNamespace())
	if err != nil {
		n.log.Error(err, "namespace not cached, not registered", "podUid", pod.GetUid(), "container", ctr.GetName())
		return nil
	}

	k8sPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID:    types.UID(pod.GetUid()),
			Labels: podLabels(pod),
		},
	}
	if err := n.openExec.ContainerStarted(k8sPod, nsLabels, cgInfo.ID); err != nil {
		n.log.Error(err, "failed to register started container", "podUid", k8sPod.UID, "container", ctr.GetName())
	}
	return nil
}

// the sandbox labels are the pod's labels plus the identity keys the kubelet
// adds, which the informer's view of the pod does not carry
func podLabels(pod *api.PodSandbox) map[string]string {
	labels := maps.Clone(pod.GetLabels())
	delete(labels, "io.kubernetes.pod.name")
	delete(labels, "io.kubernetes.pod.namespace")
	delete(labels, "io.kubernetes.pod.uid")
	return labels
}

type nriLogger struct {
	log logr.Logger
}

func (l nriLogger) Debugf(_ context.Context, format string, args ...any) {
	l.log.V(2).Info(fmt.Sprintf(format, args...))
}

func (l nriLogger) Infof(_ context.Context, format string, args ...any) {
	l.log.Info(fmt.Sprintf(format, args...))
}

func (l nriLogger) Warnf(_ context.Context, format string, args ...any) {
	l.log.Info(fmt.Sprintf(format, args...))
}

func (l nriLogger) Errorf(_ context.Context, format string, args ...any) {
	l.log.Error(nil, fmt.Sprintf(format, args...))
}
