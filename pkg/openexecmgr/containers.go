package openexecmgr

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
)

// ContainerStarted adds one container's cgroup to its pod, creating the pod if
// this is its first container.
func (l *OpenExecManager) ContainerStarted(pod corev1.Pod, nsLabels map[string]string, cgid uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	// we need to check if this pod uid previously existed in the pod map because
	// a container restart would appear as a pod update in the informer, but would
	// still trigger ContainerStarted event
	pr, ok := l.pods[string(pod.UID)]
	if !ok {
		l.podCreated(pod, nsLabels, []uint64{cgid})
		return nil
	}
	if slices.Contains(pr.cgids, cgid) {
		return nil
	}
	return l.podUpdated(pod, nsLabels, append(slices.Clone(pr.cgids), cgid))
}
