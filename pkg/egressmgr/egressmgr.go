package egressmgr

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/containers"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type egressManager struct {
	pods       map[string]*podAttachment
	rbs        map[string]*compiler.EvaluationResult
	policies   map[string]*compiler.EvaluationResult
	reevalChan chan (*compiler.EvaluationResult)
}

type podAttachment struct {
	labels          map[string]string                            // todo: centralize pod label storage in the podwatcher
	cgs             map[containers.ContainerCgroupInfo]link.Link // todo: can we store this more efficiently
	filter          *egressfilter.EgressFilter
	attachedFilters map[string]*compiler.EvaluationResult
}

func NewEgressManager() *egressManager {
	return &egressManager{
		pods:     make(map[string]*podAttachment),
		rbs:      make(map[string]*compiler.EvaluationResult),
		policies: make(map[string]*compiler.EvaluationResult),
	}
}

// what about handling compilation outside of this entitity ?
// on a new rb or policy.. we compile and call RuntimeBehaviorEvent. for periodic recompilation
// we launch a ticker that compiles per interval and calls RuntimeBehaviorEvent
func (e *egressManager) RuntimeBehaviorEvent(compiledRb *compiler.EvaluationResult, rbEventType string) error {
	switch rbEventType {
	case "create":
		e.rbs[compiledRb.UID] = compiledRb

		for _, pod := range e.pods {
			if !compiledRb.Selector.Matches(labels.Set(pod.labels)) {
				continue
			}
			pod.filter.AddIps(compiledRb.IPs)
			pod.attachedFilters[compiledRb.UID] = compiledRb
		}

	case "update":
		currentRb, ok := e.rbs[compiledRb.UID]
		if !ok {
			return fmt.Errorf("got an update for a non existing runtime behavior uid")
		}
		oldIps := make([]string, len(currentRb.IPs))

		// store the old ips becuase we may need to delete them from a pod's attachment if the runtime behavior no longer matches
		copy(oldIps, currentRb.IPs)

		toAdd := diffSlice(currentRb.IPs, compiledRb.IPs)
		toRemove := diffSlice(compiledRb.IPs, currentRb.IPs)
		// update the current runtime behavior's information to point to the new compiled behavior data
		currentRb.IPs = compiledRb.IPs
		currentRb.Selector = compiledRb.Selector

		e.rbs[string(compiledRb.UID)] = compiledRb
		for _, pod := range e.pods {
			rbMatches := compiledRb.Selector.Matches(labels.Set(pod.labels))
			if ok {
				// there is no diff and rb still matches, do nothing
				if len(toRemove) == 0 && len(toAdd) == 0 && rbMatches {
					continue
				}

				if !rbMatches {
					// this rb doesn't match anymore. delete the old ips from this attachment's map
					pod.filter.DeleteIps(oldIps)
					delete(pod.attachedFilters, string(compiledRb.UID))
					continue
				}

				// rb matches and there is a diff. add the new ips, delete the old
				// and update our tracking data structures
				pod.filter.DeleteIps(toRemove)
				pod.filter.AddIps(toAdd)
				continue
			}

			// this rb wasn't previously attached to that pod. add its ips if it matches
			if rbMatches {
				pod.filter.AddIps(compiledRb.IPs)
				pod.attachedFilters[string(compiledRb.UID)] = currentRb // add that runtime behavior's pointer to the atatchedFilters map of that pod
			}
		}
	case "delete":
		delete(e.rbs, string(compiledRb.UID))
		for _, pod := range e.pods {
			if att, ok := pod.attachedFilters[string(compiledRb.UID)]; ok {
				pod.filter.DeleteIps(att.IPs)
				delete(pod.attachedFilters, string(compiledRb.UID))
			}
		}
	default:
		return fmt.Errorf("invalid runtime behavior event type")
	}

	return nil
}

func (e *egressManager) PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error {
	switch podEventType {
	case "create":
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
	case "update":
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

	case "delete":
		// nothing to do
	}

	return nil
}

// return the entries in array b and not a
func diffSlice(a, b []string) []string {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	var out []string
	for _, v := range b {
		if _, ok := set[v]; !ok {
			out = append(out, v)
		}
	}
	return out
}
