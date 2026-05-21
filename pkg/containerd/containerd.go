package containerd

import (
	"context"
	"fmt"
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

type podInfo struct {
	k8sPod   corev1.Pod
	attached bool
	probe    *probe.Probe
	pid      uint32 // todo: how to keep pid up to date ?
}

type ContainerdConnector struct {
	client            *containerd.Client
	runtimeReconciler *controller.RuntimeBehaviorReconciler
	pods              map[string]*podInfo
	logger            *logr.Logger
}

func InitContainerdConnector(socketPath string,
	r *controller.RuntimeBehaviorReconciler,
	logger *logr.Logger) (*ContainerdConnector, error) {
	client, err := containerd.New(socketPath)
	if err != nil {
		return nil, err
	}

	c := &ContainerdConnector{
		client:            client,
		runtimeReconciler: r,
		pods:              map[string]*podInfo{},
		logger:            logger,
	}

	return c, nil
}

func (c *ContainerdConnector) EvaluatePodsAgaintLabels() {
	// check if every pod you have still matches those labels, remove the ones that don't
	// attach to the ones that do. (maybe make it map to avoid duplicates?)
	for _, podInfo := range c.pods {
		ipsToBan := c.getIpsToBanForPod(podInfo.k8sPod)
		if len(ipsToBan) == 0 {
			continue
		}
		if podInfo.probe == nil {
			probe, err := probe.New(c.logger)
			if err != nil {
				c.logger.Error(err, "failed to create probe")
				continue
			}

			err = probe.Attach(podInfo.pid)
			if err != nil {
				c.logger.Error(err, "failed to create probe")
				continue
			}
		}

		podInfo.probe.UpdateMap(ipsToBan)
	}
}

func (c *ContainerdConnector) getIpsToBanForPod(pod corev1.Pod) []string {
	ipsToBan := []string{}
	for _, rb := range c.runtimeReconciler.RbMap {
		rbMatched := false
		for labelKey, labelVal := range rb.Labels {
			podLabelVal, exists := pod.Labels[labelKey]
			// pod doesn't have that label, continue
			if !exists {
				continue
			}

			// the pod has the label, but a different value that the one this rb matches on
			if podLabelVal != labelVal {
				continue
			}

			rbMatched = true
		}

		// this rb didn't match this pod, skip it
		if !rbMatched {
			continue
		}

		// the rb matched the pod, get its ips and add them to the ips to ban
		ipsToBan = append(ipsToBan, rb.Ips...)
	}

	return ipsToBan
}

func (c *ContainerdConnector) Run(ctx context.Context) error {
	ctx = namespaces.WithNamespace(ctx, "k8s.io")

	// initial listing of all containers
	err := c.listAndMatch(ctx)
	if err != nil {
		return err
	}

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

			podInfo, err := c.buildPodInfo(ctx, cont)
			if err != nil {
				c.logger.Error(err, "failed to build k8s spec for container", "containerID", cont.ID())
				continue
			}
			// get the ips to ban for that pod
			ipsToBan := c.getIpsToBanForPod(podInfo.k8sPod)

			c.pods[podInfo.k8sPod.Namespace+"/"+podInfo.k8sPod.Name] = podInfo

			// no ips to ban for that pod.. do nothing
			if len(ipsToBan) == 0 {
				continue
			}

			probe, err := probe.New(c.logger)
			if err != nil {
				c.logger.Error(err, "failed to create probe")
				continue
			}

			err = probe.Attach(podInfo.pid)
			if err != nil {
				c.logger.Error(err, "failed to create probe")
				continue
			}

			// put it in the pod's program
			podInfo.probe = probe
			podInfo.probe.UpdateMap(ipsToBan)

		case err := <-errCh:
			c.logger.Error(err, "containerd event stream error")
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

func (c *ContainerdConnector) listAndMatch(ctx context.Context) error {
	containers, err := c.client.Containers(ctx)
	if err != nil {
		c.logger.Error(err, "failed to list containers")
		return err
	}

	for _, cont := range containers {
		podInfo, err := c.buildPodInfo(ctx, cont)
		if err != nil {
			c.logger.Error(err, fmt.Sprintf("failed to build spec for container %s", cont.ID()))
			continue
		}
		ipsToBan := c.getIpsToBanForPod(podInfo.k8sPod)
		if len(ipsToBan) == 0 {
			continue
		}

		if podInfo.probe == nil {
			probe, err := probe.New(c.logger)
			if err != nil {
				c.logger.Error(err, "failed to create probe")
				continue
			}

			err = probe.Attach(podInfo.pid)
			if err != nil {
				c.logger.Error(err, "failed to create probe")
				continue
			}
		}

		podInfo.probe.UpdateMap(ipsToBan)
		c.pods[podInfo.k8sPod.Namespace+"/"+podInfo.k8sPod.Name] = podInfo
	}
	return nil
}

func (c *ContainerdConnector) buildPodInfo(ctx context.Context, cont containerd.Container) (*podInfo, error) {
	labels, err := cont.Labels(ctx)
	if err != nil {
		c.logger.Error(err, "failed to get container labels", "containerID", cont.ID())
		return nil, err
	}

	podName, ok := labels["io.kubernetes.pod.name"]
	if !ok {
		c.logger.Info("container missing pod name label, skipping", "containerID", cont.ID())
		return nil, err
	}

	ns, ok := labels["io.kubernetes.pod.namespace"]
	if !ok {
		c.logger.Info("container missing pod namespace label, skipping", "containerID", cont.ID())
		return nil, err
	}

	pod := &corev1.Pod{}
	err = c.runtimeReconciler.Client.Get(context.Background(), client.ObjectKey{
		Name:      podName,
		Namespace: ns,
	}, pod)
	if err != nil {
		c.logger.Error(err, "failed to get pod from API server", "pod", podName, "namespace", ns)
		return nil, err
	}

	task, err := cont.Task(ctx, nil)
	if err != nil {
		c.logger.Error(err, "failed to get container task", "containerID", cont.ID())
		return nil, err
	}
	return &podInfo{
		k8sPod: *pod,
		pid:    task.Pid(),
	}, nil
}

func (c *ContainerdConnector) cleanup(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			newPodMap := make(map[string]*podInfo)
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
