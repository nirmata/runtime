package lsmmgr

import (
	"fmt"

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
			for _, prog := range la.progs {
				if err := prog.enf.AddCgids(pr.cgids); err != nil {
					l.logger.Error(err, "failed to add cgids to enforcer", "podUid", pod.UID, "rpUid", rpUid)
				}
			}

			attach(rpUid, la, string(pod.UID), pr)
		}
	}
	l.pods[string(pod.UID)] = pr
}

func (l *LsmManager) podUpdated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	l.logger.V(2).Info("pod updated", "podUid", pod.UID)
	// the only important update is a cgid change. if one such update happens
	// delete the old cgids and add the new ones from la.enf
	pr, ok := l.pods[string(pod.UID)]
	if !ok {
		return fmt.Errorf("got a pod event for a pod that doesn't exist")
	}

	cgids := containers.ExtractCgids(cgInfos)
	toAdd := utils.DiffSlice(pr.cgids, cgids)
	toRemove := utils.DiffSlice(cgids, pr.cgids)

	// cgids didn't change, do nothing
	if len(toAdd) == 0 && len(toRemove) == 0 {
		l.logger.V(2).Info("pod update had no cgid changes, skipping", "podUid", pod.UID)
		return nil
	}

	l.logger.V(2).Info("pod cgids changed", "podUid", pod.UID, "toAdd", toAdd, "toRemove", toRemove)

	// update the cgids in the pod representation pointer
	pr.cgids = cgids

	for _, la := range l.lsmAttachments {
		// that policy wasn't attached to that pod. move on
		if _, ok := la.attachedPods[string(pod.UID)]; !ok {
			continue
		}
		for _, prog := range la.progs {
			if err := prog.enf.AddCgids(toAdd); err != nil {
				l.logger.Error(err, "failed to add cgids to enforcer", "podUid", pod.UID)
			}
			if err := prog.enf.DeleteCgids(toRemove); err != nil {
				l.logger.Error(err, "failed to remove cgids from enforcer", "podUid", pod.UID)
			}
		}
	}
	return nil

}

func (l *LsmManager) podDeleted(podUid string) {
	l.logger.V(2).Info("pod deleted", "podUid", podUid)
	// delete those cgids
	delete(l.pods, podUid)
	for _, la := range l.lsmAttachments {
		podAttachment, ok := la.attachedPods[podUid]
		if !ok {
			continue
		}
		for _, prog := range la.progs {
			if err := prog.enf.DeleteCgids(podAttachment.cgids); err != nil {
				l.logger.Error(err, "failed to remove cgids from enforcer", "podUid", podUid)
			}
		}
		delete(la.attachedPods, podUid)
	}
}
