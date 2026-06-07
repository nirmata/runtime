package egressmgr

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/google/cel-go/cel"
	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// todo: move this interface to a generic module once the api settled on
type EventIface interface {
	PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error
	RuntimeBehaviorEvent(rb v1alpha1.RuntimeBehavior, rbEventType string) error
}

type egressManager struct {
	pods     map[string]*podAttachment
	rbs      map[string]*compiledEgressFilter
	policies map[string]*compiledEgressFilter
}

type podAttachment struct {
	labels          map[string]string
	cgs             map[containers.ContainerCgroupInfo]link.Link // todo: can we store this more efficiently
	filter          *egressfilter.EgressFilter
	attachedFilters map[string]*compiledEgressFilter
}

type compiledEgressFilter struct {
	ips       []string // the evaluated list of IPs to ban
	variables []cel.Program
	prog      cel.Program
	selector  labels.Selector
}

func NewEgressManager() *egressManager {
	return &egressManager{
		pods:     make(map[string]*podAttachment),
		rbs:      make(map[string]*compiledEgressFilter),
		policies: make(map[string]*compiledEgressFilter),
	}
}

// what about handling compilation outside of this entitity ?
// on a new rb or policy.. we compile and call RuntimeBehaviorEvent. for periodic recompilation
// we launch a ticker that compiles per interval and calls RuntimeBehaviorEvent
func (e *egressManager) RuntimeBehaviorEvent(rb v1alpha1.RuntimeBehavior, rbEventType string) error {
	switch rbEventType {
	case "create":
		// nil guard
		if rb.Spec.Allow == nil || rb.Spec.Allow.Deny == nil {
			return nil
		}

		// compile the runtime behavior and store it in our map
		compiledRb, err := compileRb(&rb)
		if err != nil {
			return err
		}
		e.rbs[string(rb.UID)] = compiledRb

		for _, pod := range e.pods {
			if !compiledRb.selector.Matches(labels.Set(pod.labels)) {
				continue
			}
			pod.filter.AddIps(compiledRb.ips)
			pod.attachedFilters[string(rb.UID)] = compiledRb
		}

	case "update":
		currentRb, ok := e.rbs[string(rb.UID)]
		if !ok {
			return fmt.Errorf("got an update for a non existing runtime behavior uid")
		}
		oldIps := make([]string, len(currentRb.ips))

		// store the old ips becuase we may need to delete them from a pod's attachment if the runtime behavior no longer matches
		copy(oldIps, currentRb.ips)

		// compile the runtime behavior and store it in our map
		compiledRb, err := compileRb(&rb)
		if err != nil {
			return err
		}

		toAdd := diffSlice(currentRb.ips, compiledRb.ips)
		toRemove := diffSlice(compiledRb.ips, currentRb.ips)
		// update the current runtime behavior's information to point to the new compiled behavior data
		currentRb.ips = compiledRb.ips
		currentRb.selector = compiledRb.selector

		e.rbs[string(rb.UID)] = compiledRb
		for _, pod := range e.pods {
			rbMatches := compiledRb.selector.Matches(labels.Set(pod.labels))
			if ok {
				// there is no diff and rb still matches, do nothing
				if len(toRemove) == 0 && len(toAdd) == 0 && rbMatches {
					continue
				}

				if !rbMatches {
					// this rb doesn't match anymore. delete the old ips from this attachment's map
					pod.filter.DeleteIps(oldIps)
					delete(pod.attachedFilters, string(rb.UID))
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
				pod.filter.AddIps(compiledRb.ips)
				pod.attachedFilters[string(rb.UID)] = currentRb // add that runtime behavior's pointer to the atatchedFilters map of that pod
			}
		}
	case "delete":
		delete(e.rbs, string(rb.UID))
		for _, pod := range e.pods {
			if att, ok := pod.attachedFilters[string(rb.UID)]; ok {
				pod.filter.DeleteIps(att.ips)
				delete(pod.attachedFilters, string(rb.UID))
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
			attachedFilters: make(map[string]*compiledEgressFilter),
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
			if !filter.selector.Matches(labels.Set(pod.Labels)) {
				continue
			}
			ipsToBan = append(ipsToBan, filter.ips...)
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

func compileRb(rb *v1alpha1.RuntimeBehavior) (*compiledEgressFilter, error) {
	selector, err := metav1.LabelSelectorAsSelector(rb.Spec.WorkloadSelector)
	if err != nil {
		return nil, err
	}
	// todo
	return &compiledEgressFilter{
		ips:      rb.Spec.Allow.Deny.Network,
		selector: selector,
	}, nil
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
