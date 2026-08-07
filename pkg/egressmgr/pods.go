package egressmgr

import (
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"

	"github.com/cilium/ebpf/link"
	corev1 "k8s.io/api/core/v1"
)

func (e *EgressManager) podCreated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	e.logger.V(2).Info("pod created", "podUid", pod.UID)
	filter, err := e.newFilter(&e.logger)
	if err != nil {
		return err
	}

	pa := &podAttachment{
		cgs:             make(map[containers.ContainerCgroupInfo][]link.Link),
		attachedFilters: make(map[string]*compiler.EvaluationResult),
		defaultDeny:     make(map[string]struct{}),
		labels:          pod.Labels,
		filter:          filter,
		allowOwners:     newSideOwners(),
		denyOwners:      newSideOwners(),
	}

	for _, cg := range cgInfos {
		links, err := filter.Attach(cg.Path)
		if err != nil {
			for _, attached := range pa.cgs {
				e.closeLinks(string(pod.UID), attached)
			}
			return err
		}
		pa.cgs[*cg] = links
	}

	for rpName, rp := range e.rps {
		if !selectorMatches(rp.Selector, pod.Labels) {
			continue
		}
		e.logger.V(2).Info("new pod matches existing runtime policy", "podUid", pod.UID, "rpUid", rpName)
		pa.attachedFilters[rpName] = rp

		// observe-mode policies program nothing
		if compiler.IsObserveMode(rp.Mode) {
			continue
		}

		// programmed per policy rather than as one aggregate pair so each
		// address records the policy that wants it
		if rp.IPs.HasEntries() {
			e.addIps(string(pod.UID), rp.UID, pa, rp.IPs)
		}

		if denyHasStar(rp.IPs) {
			pa.defaultDeny[rp.UID] = struct{}{}
		}
	}

	if len(pa.defaultDeny) > 0 {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
	}
	// every pod with an attached policy is observed, whatever mode it is in
	if len(pa.attachedFilters) > 0 {
		pa.filter.SetFlagIdx(egressfilter.OBSERVE, true)
	}

	e.pods[string(pod.UID)] = pa
	return nil
}

// podUpdated refreshes the cached labels and re-evaluates every tracked policy's
// selector against them before reconciling the cgroup links. Without the label
// refresh a relabelled pod keeps enforcement from a policy that stopped
// selecting it, and is never picked up by one that starts to.
func (e *EgressManager) podUpdated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	e.logger.V(2).Info("pod updated", "podUid", pod.UID)
	pa, ok := e.pods[string(pod.UID)]
	if !ok {
		return fmt.Errorf("got a pod event for a pod that doesn't exist")
	}

	e.refreshLabels(string(pod.UID), pa, pod.Labels)

	// check if there are new cgroup infos. if there is, create links for them.
	newCgs := make(map[containers.ContainerCgroupInfo][]link.Link)
	for _, cgInfo := range cgInfos {
		links, exists := pa.cgs[*cgInfo]
		if !exists {
			newLinks, err := pa.filter.Attach(cgInfo.Path)
			if err != nil {
				return err
			}
			links = newLinks
		}
		newCgs[*cgInfo] = links
	}
	for cg, links := range pa.cgs {
		if _, kept := newCgs[cg]; !kept {
			e.closeLinks(string(pod.UID), links)
		}
	}
	pa.cgs = newCgs
	return nil
}

func (e *EgressManager) closeLinks(podUid string, links []link.Link) {
	for _, l := range links {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil {
			e.logger.Error(err, "failed to close an egress cgroup link", "podUid", podUid)
		}
	}
}

// refreshLabels stores the new label set and attaches/detaches every tracked
// policy accordingly. Detaching decrements the default-deny refcount rather than
// clearing the flag, so overlapping policies survive.
func (e *EgressManager) refreshLabels(podUid string, pa *podAttachment, newLabels map[string]string) {
	pa.labels = newLabels

	for uid, rp := range e.rps {
		matches := selectorMatches(rp.Selector, newLabels)
		att, attached := pa.attachedFilters[uid]
		switch {
		case matches && !attached:
			e.logger.V(2).Info("relabelled pod newly matches runtime policy", "podUid", podUid, "uid", uid)
			e.attachPolicy(podUid, pa, rp)
		case !matches && attached:
			e.logger.V(2).Info("relabelled pod stopped matching runtime policy, detaching", "podUid", podUid, "uid", uid)
			e.detachPolicy(podUid, pa, uid, att.IPs)
		}
	}
}

func (e *EgressManager) podDeleted(podUid string) {
	e.logger.V(2).Info("pod deleted", "podUid", podUid)
	pa, ok := e.pods[podUid]
	if !ok {
		return
	}
	// the kernel detaches the programs with the cgroup, but the link fds are
	// ours and outlive it until they are closed
	for _, links := range pa.cgs {
		e.closeLinks(podUid, links)
	}
	delete(e.pods, podUid)
}
