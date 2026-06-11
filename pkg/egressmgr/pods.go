package egressmgr

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (e *egressManager) podCreated(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) error {
	filter, err := egressfilter.New(&logr.Logger{})
	if err != nil {
		return err
	}

	pa := &podAttachment{
		cgs:             make(map[containers.ContainerCgroupInfo]link.Link),
		labels:          pod.Labels,
		filter:          filter,
		attachedFilters: make(map[string]*compiler.EvaluationResult),
	}

	for _, cg := range cgInfos {
		l, err := filter.Attach(cg.Path)
		if err != nil {
			return err
		}
		pa.cgs[*cg] = l
	}

	ipsToBan := []string{}
	for rbName, filter := range e.rbs {
		if !filter.Selector.Matches(labels.Set(pod.Labels)) {
			continue
		}
		ipsToBan = append(ipsToBan, filter.IPs...)
		pa.attachedFilters[rbName] = filter
	}
	// ban ips in case there was a rb that matches
	if len(ipsToBan) > 0 {
		pa.filter.AddIps(ipsToBan)
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
