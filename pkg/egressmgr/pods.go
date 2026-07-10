package egressmgr

import (
	"fmt"
	"slices"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"

	"github.com/cilium/ebpf/link"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (e *EgressManager) podCreated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	e.logger.V(2).Info("pod created", "podUid", pod.UID)
	filter, err := egressfilter.New(&e.logger)
	if err != nil {
		return err
	}

	pa := &podAttachment{
		cgs:             make(map[containers.ContainerCgroupInfo]link.Link),
		attachedFilters: make(map[string]*compiler.EvaluationResult),
		defaultDeny:     make(map[string]struct{}),
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
	for rpName, filter := range e.rps {
		if !filter.Selector.Matches(labels.Set(pod.Labels)) {
			continue
		}
		e.logger.V(2).Info("new pod matches existing runtime policy", "podUid", pod.UID, "rpUid", rpName)
		ips.Allow = append(ips.Allow, filter.IPs.Allow...)
		ips.Deny = append(ips.Deny, filter.IPs.Deny...)

		// the filter's IP contain a default deny. add it to the group of filters
		// that specify a default deny
		if slices.Contains(filter.IPs.Deny, "*") {
			pa.defaultDeny[filter.UID] = struct{}{}
		}

		pa.attachedFilters[rpName] = filter
	}

	if len(pa.defaultDeny) > 0 {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
	}

	// ban ips in case there was a rp that matched
	if len(ips.Allow) > 0 || len(ips.Deny) > 0 {
		pa.filter.AddIps(ips)
	}

	e.pods[string(pod.UID)] = pa
	return nil
}

func (e *EgressManager) podUpdated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	e.logger.V(2).Info("pod updated", "podUid", pod.UID)
	pa, ok := e.pods[string(pod.UID)]
	if !ok {
		return fmt.Errorf("got a pod event for a pod that doesn't exist")
	}
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

func (e *EgressManager) podDeleted(podUid string) {
	e.logger.V(2).Info("pod deleted", "podUid", podUid)
	// a pod being deleted means that its cgroup id is deleted. so any attached links
	// will automatically die
	delete(e.pods, podUid)
}
