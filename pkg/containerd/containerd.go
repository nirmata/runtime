package containerd

import (
	"context"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/typeurl/v2"
	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/probe"
	"github.com/nirmata/kyverno-runtime/pkg/controller"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type podK8sSpec struct {
	pod      corev1.Pod
	attached bool
	pid      uint32 // todo: how to keep pid up to date ?
	// todo: do we need any more information here ?
}

type ContainerdConnector struct {
	// the connector should have a way for me to tell it hey bro, reevaluate the pods
	// you have against this new set of selectors. we should avoid a circular dependency
	// between the connector and the behavior reconciler
	// can we have a god listener and everything channel sends to it whenever it gets an update?
	// what am i solving ? the need to tell the connector to reevaluate against the pods it has
	// so what if it stores all pods it saw. and there is a function on it ?
	// but again.. to call it.. we will have a circular dependency
	client            *containerd.Client
	runtimeReconciler *controller.RuntimeBehaviorReconciler
	probe             *probe.Probe
	pods              map[string]*podK8sSpec
	logger            *logr.Logger
}

func InitContainerdConnector(socketPath string,
	probe *probe.Probe,
	r *controller.RuntimeBehaviorReconciler,
	logger *logr.Logger) (*ContainerdConnector, error) {
	client, err := containerd.New(socketPath)
	if err != nil {
		return nil, err
	}

	c := &ContainerdConnector{
		probe:             probe,
		client:            client,
		runtimeReconciler: r,
		pods:              map[string]*podK8sSpec{},
		logger:            logger,
	}

	return c, nil
}

func (c *ContainerdConnector) EvaluatePodsAgaintLabels() {
	// check if every pod you have still matches those labels, remove the ones that don't
	// attach to the ones that do
	for _, podSpec := range c.pods {
		stillMatchesLabels := false
		for labelKey, labelVal := range c.runtimeReconciler.AllLabels {
			if podLabelVal, exists := podSpec.pod.Labels[labelKey]; exists {
				if podLabelVal == labelVal {
					if !podSpec.attached {
						c.probe.Attach(podSpec.pid)
					}
					stillMatchesLabels = true
					break
				}
			}
		}

		if !stillMatchesLabels {
			// this pod no longer matches the labels
			// todo: create a probe detach function
			podSpec.attached = false
		}
	}
}

func (c *ContainerdConnector) Run(ctx context.Context) error {
	ctx = namespaces.WithNamespace(ctx, "k8s.io")
	evCh, errCh := c.client.Subscribe(ctx, `topic=="/tasks/start"`)

	// start the thread that will make sure deleted containers get removed from the map
	// todo: maybe check if there's a way to subscribe to container deletions?
	go c.cleanup(ctx)

	for {
		select {
		case ev := <-evCh:
			var taskStart events.TaskStart
			if err := typeurl.UnmarshalTo(ev.Event, &taskStart); err != nil {
				c.logger.Error(err, "failed to unmarshal task start event")
				continue
			}
			c.logger.Info("new pod container", "containerID", taskStart.ContainerID, "pid", taskStart.Pid)

			cont, err := c.client.LoadContainer(ctx, taskStart.ContainerID)
			if err != nil {
				c.logger.Error(err, "failed to load container", "containerID", taskStart.ContainerID)
				continue
			}

			labels, err := cont.Labels(ctx)
			if err != nil {
				c.logger.Error(err, "failed to get container labels", "containerID", taskStart.ContainerID)
				continue
			}

			podName, ok := labels["io.kubernetes.pod.name"]
			if !ok {
				c.logger.Info("container missing pod name label, skipping", "containerID", cont.ID())
				continue
			}

			ns, ok := labels["io.kubernetes.pod.namespace"]
			if !ok {
				c.logger.Info("container missing pod namespace label, skipping", "containerID", cont.ID())
				continue
			}

			pod := &corev1.Pod{}
			err = c.runtimeReconciler.Client.Get(context.Background(), client.ObjectKey{
				Name:      podName,
				Namespace: ns,
			}, pod)
			if err != nil {
				c.logger.Error(err, "failed to get pod from API server", "pod", podName, "namespace", ns)
				continue
			}

			task, err := cont.Task(ctx, nil)
			if err != nil {
				c.logger.Error(err, "failed to get container task", "containerID", taskStart.ContainerID)
				continue
			}

			podK8s := &podK8sSpec{
				pod:      *pod,
				pid:      task.Pid(),
				attached: false,
			}

			for labelKey, labelVal := range c.runtimeReconciler.AllLabels {
				if podLabelVal, exists := pod.Labels[labelKey]; exists {
					if podLabelVal == labelVal {
						// a pod matches the labels.. we should attach to it
						c.probe.Attach(task.Pid())
						podK8s.attached = true
					}
				}
			}

			c.pods[ns+"/"+podName] = podK8s

		case err := <-errCh:
			c.logger.Error(err, "containerd event stream error")
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

func (c *ContainerdConnector) cleanup(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			newPodMap := make(map[string]*podK8sSpec)
			containers, err := c.client.Containers(ctx)
			if err != nil {
				c.logger.Error(err, "failed to list containers during cleanup")
				continue
			}
			for _, cont := range containers {
				labels, err := cont.Labels(ctx)
				if err != nil {
					c.logger.Error(err, "failed to get container labels during cleanup", "containerID", cont.ID())
					continue
				}
				podName, ok := labels["io.kubernetes.pod.name"]
				if !ok {
					// something
					continue
				}
				ns, ok := labels["io.kubernetes.pod.namespace"]
				if !ok {
					// something
					continue
				}
				key := ns + "/" + podName
				if k8sSpec, exists := c.pods[key]; exists {
					newPodMap[key] = k8sSpec
				}
			}

			// replace the pod map with the currrent running set of pods
			c.pods = newPodMap
		case <-ctx.Done():
			return
		}
	}
}
