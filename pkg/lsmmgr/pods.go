package lsmmgr

import (
	"fmt"
	"maps"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/containers"
	"github.com/nirmata/runtime/pkg/utils"

	corev1 "k8s.io/api/core/v1"
)

func (l *LsmManager) podCreated(pod corev1.Pod, nsLabels map[string]string, cgInfos []*containers.ContainerCgroupInfo) {
	l.logger.V(2).Info("pod created", "podUid", pod.UID)
	pr := &podRepresentation{
		labels:       pod.Labels,
		nsLabels:     nsLabels,
		cgids:        containers.ExtractCgids(cgInfos),
		attachedLsms: make(map[string]*lsmAttachment),
	}
	for rpUid, la := range l.lsmAttachments {
		if la.target.Matches(nsLabels, pod.Labels) {
			l.logger.V(2).Info("new pod matches existing runtime policy", "podUid", pod.UID, "rpUid", rpUid, "cgids", pr.cgids)
			for progType, prog := range la.progs {
				l.addPodCgids(rpUid, progType, prog, pr.cgids, la.observe)
			}

			attach(rpUid, la, string(pod.UID), pr)
			l.recordCondition(rpUid, v1alpha1.PodsMatchedCondition(len(la.attachedPods), l.clock()))
		}
	}
	l.pods[string(pod.UID)] = pr
}

// podUpdated reconciles both halves of a pod update: a cgroup-id change is
// applied to every attachment the pod is already attached to (containers
// restarting inside a live pod), and a change to either the pod's own labels or
// its namespace's refreshes the cached sets and re-evaluates every attachment's
// target.
func (l *LsmManager) podUpdated(pod corev1.Pod, nsLabels map[string]string, cgInfos []*containers.ContainerCgroupInfo) error {
	l.logger.V(2).Info("pod updated", "podUid", pod.UID)
	pr, ok := l.pods[string(pod.UID)]
	if !ok {
		return fmt.Errorf("got a pod event for a pod that doesn't exist")
	}

	cgids := containers.ExtractCgids(cgInfos)
	toAdd := utils.DiffSlice(pr.cgids, cgids)
	toRemove := utils.DiffSlice(cgids, pr.cgids)
	labelsChanged := !maps.Equal(pr.labels, pod.Labels) || !maps.Equal(pr.nsLabels, nsLabels)

	if len(toAdd) == 0 && len(toRemove) == 0 && !labelsChanged {
		l.logger.V(2).Info("pod update had no cgid or label changes, skipping", "podUid", pod.UID)
		return nil
	}

	if len(toAdd) != 0 || len(toRemove) != 0 {
		l.logger.V(2).Info("pod cgids changed", "podUid", pod.UID, "toAdd", toAdd, "toRemove", toRemove)
	}

	// the labels have to land before syncPodAttachment below, which matches
	// against them
	pr.cgids = cgids
	pr.labels = pod.Labels
	pr.nsLabels = nsLabels

	// the cgid diff runs before the selector re-evaluation, so a pod on either
	// side of an attachment change is handled with its new cgid set
	for rpUid, la := range l.lsmAttachments {
		if _, ok := la.attachedPods[string(pod.UID)]; !ok {
			continue
		}
		for progType, prog := range la.progs {
			l.addPodCgids(rpUid, progType, prog, toAdd, la.observe)
			l.removePodCgids(rpUid, progType, prog, toRemove)
		}
	}

	if labelsChanged {
		l.logger.V(2).Info("pod or namespace labels changed, re-evaluating policy targets", "podUid", pod.UID)
		for rpUid, la := range l.lsmAttachments {
			l.syncPodAttachment(rpUid, la)
			l.recordCondition(rpUid, v1alpha1.PodsMatchedCondition(len(la.attachedPods), l.clock()))
		}
	}
	return nil
}

func (l *LsmManager) podDeleted(podUid string) {
	l.logger.V(2).Info("pod deleted", "podUid", podUid)
	delete(l.pods, podUid)
	for rpUid, la := range l.lsmAttachments {
		podAttachment, ok := la.attachedPods[podUid]
		if !ok {
			continue
		}
		for progType, prog := range la.progs {
			l.removePodCgids(rpUid, progType, prog, podAttachment.cgids)
		}
		delete(la.attachedPods, podUid)
		l.recordCondition(rpUid, v1alpha1.PodsMatchedCondition(len(la.attachedPods), l.clock()))
	}
}
