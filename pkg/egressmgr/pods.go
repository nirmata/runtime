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
		cgs:             make(map[containers.ContainerCgroupInfo]link.Link),
		attachedFilters: make(map[string]*compiler.EvaluationResult),
		defaultDeny:     make(map[string]struct{}),
		observe:         make(map[string]struct{}),
		labels:          pod.Labels,
		filter:          filter,
	}

	for _, cg := range cgInfos {
		l, err := filter.Attach(cg.Path)
		if err != nil {
			return err
		}
		pa.cgs[*cg] = l
	}

	ips := &compiler.AllowDenyPair{}
	for rpName, rp := range e.rps {
		if !selectorMatches(rp.Selector, pod.Labels) {
			continue
		}
		e.logger.V(2).Info("new pod matches existing runtime policy", "podUid", pod.UID, "rpUid", rpName)
		pa.attachedFilters[rpName] = rp

		// observe-mode policies program nothing: they only ask for observation
		if compiler.IsObserveMode(rp.Mode) {
			pa.observe[rp.UID] = struct{}{}
			continue
		}

		if rp.IPs != nil {
			ips.Allow = append(ips.Allow, rp.IPs.Allow...)
			ips.Deny = append(ips.Deny, rp.IPs.Deny...)
		}

		// the filter's IP contain a default deny. add it to the group of filters
		// that specify a default deny
		if denyHasStar(rp.IPs) {
			pa.defaultDeny[rp.UID] = struct{}{}
		}
	}

	if len(pa.defaultDeny) > 0 {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
	}
	if len(pa.observe) > 0 {
		pa.filter.SetFlagIdx(egressfilter.OBSERVE, true)
	}

	// ban ips in case there was a rp that matched
	if ips.HasEntries() {
		e.addIps(string(pod.UID), "", pa.filter, ips)
	}

	e.pods[string(pod.UID)] = pa
	return nil
}

// podUpdated refreshes the cached labels and re-evaluates every tracked policy's
// selector against them before reconciling the cgroup links. Without the
// label refresh a relabelled pod keeps enforcement from a policy that no longer
// selects it, and is never picked up by one that now does.
func (e *EgressManager) podUpdated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	e.logger.V(2).Info("pod updated", "podUid", pod.UID)
	pa, ok := e.pods[string(pod.UID)]
	if !ok {
		return fmt.Errorf("got a pod event for a pod that doesn't exist")
	}

	e.refreshLabels(string(pod.UID), pa, pod.Labels)

	// check if there are new cgroup infos. if there is, create links for them.
	// for the ones that are gone the attachment would be already deleted by the kernel
	newCgs := make(map[containers.ContainerCgroupInfo]link.Link)
	for _, cgInfo := range cgInfos {
		l, exists := pa.cgs[*cgInfo]
		if !exists {
			// new cgroup, attach and get a link
			newLink, err := pa.filter.Attach(cgInfo.Path)
			if err != nil {
				return err
			}
			l = newLink
		}
		newCgs[*cgInfo] = l
	}
	pa.cgs = newCgs
	return nil
}

// refreshLabels stores the new label set and attaches/detaches every tracked
// policy accordingly. Detaching decrements the default-deny and OBSERVE
// refcounts rather than clearing the flags, so overlapping policies survive.
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
			e.logger.V(2).Info("relabelled pod no longer matches runtime policy, detaching", "podUid", podUid, "uid", uid)
			_, observed := pa.observe[uid]
			e.detachPolicy(podUid, pa, uid, observed, att.IPs)
		}
	}
}

func (e *EgressManager) podDeleted(podUid string) {
	e.logger.V(2).Info("pod deleted", "podUid", podUid)
	// a pod being deleted means that its cgroup id is deleted. so any attached links
	// will automatically die
	delete(e.pods, podUid)
}
