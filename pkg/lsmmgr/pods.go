package lsmmgr

import (
	"fmt"
	"maps"

	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (l *LsmManager) podCreated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) {
	l.logger.V(2).Info("pod created", "podUid", pod.UID)
	pr := &podRepresentation{
		labels:       pod.Labels,
		cgids:        containers.ExtractCgids(cgInfos),
		attachedLsms: make(map[string]*lsmAttachment),
	}
	for rpUid, la := range l.lsmAttachments {
		if la.selector.Matches(labels.Set(pod.Labels)) {
			l.logger.V(2).Info("new pod matches existing runtime policy", "podUid", pod.UID, "rpUid", rpUid, "cgids", pr.cgids)
			for progType, prog := range la.progs {
				l.addPodCgids(rpUid, progType, prog, pr.cgids)
			}

			attach(rpUid, la, string(pod.UID), pr)
		}
	}
	l.pods[string(pod.UID)] = pr
}

// podUpdated reconciles both halves of a pod update:
//
//   - a cgroup-id change is applied to every attachment the pod is already
//     attached to (containers restarting inside a live pod);
//   - a label change refreshes the cached label set and re-evaluates every
//     attachment's selector. Without this, enforcement outlived its
//     selector: a relabelled pod kept the deny maps of a policy that no longer
//     selects it, and was invisible to policies that now do.
func (l *LsmManager) podUpdated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	l.logger.V(2).Info("pod updated", "podUid", pod.UID)
	pr, ok := l.pods[string(pod.UID)]
	if !ok {
		return fmt.Errorf("got a pod event for a pod that doesn't exist")
	}

	cgids := containers.ExtractCgids(cgInfos)
	toAdd := utils.DiffSlice(pr.cgids, cgids)
	toRemove := utils.DiffSlice(cgids, pr.cgids)
	labelsChanged := !maps.Equal(pr.labels, pod.Labels)

	// nothing we track changed, do nothing
	if len(toAdd) == 0 && len(toRemove) == 0 && !labelsChanged {
		l.logger.V(2).Info("pod update had no cgid or label changes, skipping", "podUid", pod.UID)
		return nil
	}

	if len(toAdd) != 0 || len(toRemove) != 0 {
		l.logger.V(2).Info("pod cgids changed", "podUid", pod.UID, "toAdd", toAdd, "toRemove", toRemove)
	}

	// update the cgids and labels in the pod representation pointer. the labels
	// have to land before syncPodAttachment below, which matches against them.
	pr.cgids = cgids
	pr.labels = pod.Labels

	// apply the cgid diff to the attachments this pod is currently attached to.
	// this runs before the selector re-evaluation so that a pod that is about to
	// be detached is detached with its new cgid set, and a pod that is about to be
	// attached is attached with it too.
	for rpUid, la := range l.lsmAttachments {
		// that policy wasn't attached to that pod. move on
		if _, ok := la.attachedPods[string(pod.UID)]; !ok {
			continue
		}
		for progType, prog := range la.progs {
			l.addPodCgids(rpUid, progType, prog, toAdd)
			l.removePodCgids(rpUid, progType, prog, toRemove)
		}
	}

	if labelsChanged {
		l.logger.V(2).Info("pod labels changed, re-evaluating policy selectors", "podUid", pod.UID)
		for rpUid, la := range l.lsmAttachments {
			l.syncPodAttachment(rpUid, la)
		}
	}
	return nil
}

func (l *LsmManager) podDeleted(podUid string) {
	l.logger.V(2).Info("pod deleted", "podUid", podUid)
	// delete those cgids
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
	}
}
