package egressmgr

import (
	"fmt"
	"slices"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (e *egressManager) podCreated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	// not sure if it makes sense that i am creating the filter once and attaching it
	// per container c group id. or idk maybe it does.. in the end of the day learning mode
	// collects events for a single pod. so yeah maybe all pod containers can share a program
	// this kinda simplifies things because this means we can have events on the workload profile
	// api. if it targets this pod. we enable collection for it. for a workload profile, we kinda
	// don't give a shit about policies. so we can just have another event source that links to pod
	// attachments
	filter, err := egressfilter.New(&logr.Logger{})
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

func (e *egressManager) podUpdated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
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

func (e *egressManager) podDeleted(podUid string) error {
	// a pod being deleted means that its cgroup id is deleted. so any attached links
	// will automatically die
	delete(e.pods, podUid)
	return nil
}
