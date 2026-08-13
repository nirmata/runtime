package egressmgr

import (
	"fmt"

	"github.com/nirmata/runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/runtime/pkg/bpf/protofilter"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/containers"

	"github.com/cilium/ebpf/link"
	corev1 "k8s.io/api/core/v1"
)

func (e *EgressManager) podCreated(pod corev1.Pod, nsLabels map[string]string, cgInfos []*containers.ContainerCgroupInfo) error {
	e.logger.V(2).Info("pod created", "podUid", pod.UID)
	filter, err := e.newFilter(&e.logger)
	if err != nil {
		return err
	}
	pf, err := e.newProtoFilter(&e.logger)
	if err != nil {
		return err
	}

	pa := &podAttachment{
		cgs:              make(map[containers.ContainerCgroupInfo][]link.Link),
		attachedFilters:  make(map[string]*compiler.EvaluationResult),
		defaultDeny:      make(map[string]struct{}),
		protoDefaultDeny: make(map[string]struct{}),
		labels:           pod.Labels,
		nsLabels:         nsLabels,
		filter:           filter,
		protoFilter:      pf,
		allowOwners:      newSideOwners(),
		denyOwners:       newSideOwners(),
		allowProtoOwners: newProtoOwners(),
		denyProtoOwners:  newProtoOwners(),
	}

	for _, cg := range cgInfos {
		links, err := attachBoth(filter, pf, cg.Path)
		if err != nil {
			for _, attached := range pa.cgs {
				e.closeLinks(string(pod.UID), attached)
			}
			e.closeLinks(string(pod.UID), links)
			return err
		}
		pa.cgs[*cg] = links
	}

	// registered before the matching loop below so recomputePodsMatchedCondition,
	// which counts over e.pods, sees this pod too
	e.pods[string(pod.UID)] = pa

	for rpName, rp := range e.rps {
		if !rp.AppliesTo.Matches(nsLabels, pod.Labels) {
			continue
		}
		e.logger.V(2).Info("new pod matches existing runtime policy", "podUid", pod.UID, "rpUid", rpName)
		pa.attachedFilters[rpName] = rp
		e.recomputePodsMatchedCondition(rpName)

		// observe-mode policies program nothing
		if compiler.IsObserveMode(rp.Mode) {
			continue
		}

		// programmed per policy rather than as one aggregate pair so each
		// address records the policy that wants it
		if rp.IPs.HasEntries() {
			e.addIps(string(pod.UID), rp.UID, pa, rp.IPs)
		}
		if rp.Protocols.HasEntries() {
			e.addProtos(string(pod.UID), rp.UID, pa, rp.Protocols)
		}

		if denyHasStar(rp.IPs) {
			pa.defaultDeny[rp.UID] = struct{}{}
		}
		if denyHasStar(rp.Protocols) {
			pa.protoDefaultDeny[rp.UID] = struct{}{}
		}
	}

	if len(pa.defaultDeny) > 0 {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
	}
	if len(pa.protoDefaultDeny) > 0 {
		pa.protoFilter.SetFlagIdx(protofilter.DEFAULT_DENY, true)
	}
	// every pod with an attached policy is observed, whatever mode it is in
	if len(pa.attachedFilters) > 0 {
		pa.filter.SetFlagIdx(egressfilter.OBSERVE, true)
		pa.protoFilter.SetFlagIdx(protofilter.OBSERVE, true)
	}
	return nil
}

// podUpdated refreshes the cached pod and namespace labels and re-evaluates
// every tracked policy's target against them before reconciling the cgroup
// links. Without the refresh a relabelled pod keeps enforcement from a policy
// that stopped selecting it, and is never picked up by one that starts to.
func (e *EgressManager) podUpdated(pod corev1.Pod, nsLabels map[string]string, cgInfos []*containers.ContainerCgroupInfo) error {
	e.logger.V(2).Info("pod updated", "podUid", pod.UID)
	pa, ok := e.pods[string(pod.UID)]
	if !ok {
		return fmt.Errorf("got a pod event for a pod that doesn't exist")
	}

	e.refreshLabels(string(pod.UID), pa, nsLabels, pod.Labels)

	// check if there are new cgroup infos. if there is, create links for them.
	newCgs := make(map[containers.ContainerCgroupInfo][]link.Link)
	for _, cgInfo := range cgInfos {
		links, exists := pa.cgs[*cgInfo]
		if !exists {
			newLinks, err := attachBoth(pa.filter, pa.protoFilter, cgInfo.Path)
			if err != nil {
				// only the links this call created: the rest stay live under
				// the untouched pa.cgs
				for cg, created := range newCgs {
					if _, reused := pa.cgs[cg]; !reused {
						e.closeLinks(string(pod.UID), created)
					}
				}
				e.closeLinks(string(pod.UID), newLinks)
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

// refreshLabels stores the new label sets and attaches/detaches every tracked
// policy accordingly. Detaching decrements the default-deny refcount rather than
// clearing the flag, so overlapping policies survive.
func (e *EgressManager) refreshLabels(podUid string, pa *podAttachment, newNsLabels, newLabels map[string]string) {
	pa.labels = newLabels
	pa.nsLabels = newNsLabels

	for uid, rp := range e.rps {
		matches := rp.AppliesTo.Matches(newNsLabels, newLabels)
		att, attached := pa.attachedFilters[uid]
		switch {
		case matches && !attached:
			e.logger.V(2).Info("relabelled pod newly matches runtime policy", "podUid", podUid, "uid", uid)
			e.attachPolicy(podUid, pa, rp)
			e.recomputePodsMatchedCondition(uid)
		case !matches && attached:
			e.logger.V(2).Info("relabelled pod stopped matching runtime policy, detaching", "podUid", podUid, "uid", uid)
			e.detachPolicy(podUid, pa, uid, att.IPs, att.Protocols)
			e.recomputePodsMatchedCondition(uid)
		}
	}
}

// recomputePodsMatchedCondition recounts how many pods on this node currently
// match a policy and reports it. Pod events change that count without a
// corresponding policy event, so a pod attaching to or detaching from a
// policy has to trigger this itself rather than wait for the policy's own
// create/update path to notice.
func (e *EgressManager) recomputePodsMatchedCondition(uid string) {
	rp, ok := e.rps[uid]
	if !ok {
		return
	}
	matched := 0
	for _, pod := range e.pods {
		if rp.AppliesTo.Matches(pod.nsLabels, pod.labels) {
			matched++
		}
	}
	e.recordPodsMatchedCondition(uid, matched)
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
	// recomputed after the delete, so a departing pod no longer counts toward
	// the policies it was attached to
	for uid := range pa.attachedFilters {
		e.recomputePodsMatchedCondition(uid)
	}
}

// attachBoth attaches the egress and protocol programs to one cgroup, returning
// every link created so a caller that fails partway can close them together.
// Both programs live on the same cgroup hook, so a pod is either covered by
// both or by neither.
func attachBoth(f egressFilter, pf protoFilter, cgPath string) ([]link.Link, error) {
	links, err := f.Attach(cgPath)
	if err != nil {
		return links, err
	}
	pl, err := pf.Attach(cgPath)
	if err != nil {
		return links, err
	}
	return append(links, pl), nil
}
