package lsmmgr

import (
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (l *LsmManager) podCreated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	// new pod, does it match any of the existing rps ?
	// yes ? add its cgids to the map.
	pr := &podRepresentation{
		labels:       pod.Labels,
		cgids:        containers.ExtractCgids(cgInfos),
		attachedLsms: make(map[string]*lsmAttachment),
	}
	for rpUid, la := range l.lsmAttachments {
		if la.selector.Matches(labels.Set(pod.Labels)) {
			err := la.enf.AddCgids(pr.cgids)
			if err != nil {
				return err
			}
			pr.attachedLsms[rpUid] = la
		}
	}
	l.pods[string(pod.UID)] = pr
	return nil
}

func (l *LsmManager) podUpdated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
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
		return nil
	}

	// update the cgids in the pod representation pointer
	pr.cgids = cgids

	for _, la := range l.lsmAttachments {
		// that policy wasn't attached to that pod. move on
		if _, ok := la.attachedPods[string(pod.UID)]; !ok {
			continue
		}
		if err := la.enf.AddCgids(toAdd); err != nil {
			return err
		}
		if err := la.enf.DeleteCgids(toRemove); err != nil {
			return err
		}
	}
	return nil

}

func (l *LsmManager) podDeleted(podUid string) error {
	// delete those cgids
	delete(l.pods, podUid)
	for _, la := range l.lsmAttachments {
		podAttachment, ok := la.attachedPods[podUid]
		if !ok {
			continue
		}
		err := la.enf.DeleteCgids(podAttachment.cgids)
		if err != nil {
			return err
		}
		delete(la.attachedPods, podUid)
	}
	return nil

}
