package egressmgr

import (
	"fmt"

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
	cgPaths         []string
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
		selector, err := metav1.LabelSelectorAsSelector(rb.Spec.WorkloadSelector)
		if err != nil {
			return err
		}

		// compile the runtime behavior and store it in our map
		compiledRb, err := compileRb(&rb)
		if err != nil {
			return err
		}
		e.rbs[string(rb.UID)] = compiledRb

		for _, pod := range e.pods {
			if !selector.Matches(labels.Set(pod.labels)) {
				continue
			}
			pod.filter.AddIps(compiledRb.ips)
			pod.attachedFilters[string(rb.UID)] = compiledRb
		}

	case "update":
		selector, err := metav1.LabelSelectorAsSelector(rb.Spec.WorkloadSelector)
		if err != nil {
			return err
		}

		// compile the runtime behavior and store it in our map
		compiledRb, err := compileRb(&rb)
		if err != nil {
			return err
		}

		e.rbs[string(rb.UID)] = compiledRb
		for _, pod := range e.pods {
			rbMatches := selector.Matches(labels.Set(pod.labels))
			att, ok := pod.attachedFilters[string(rb.UID)]
			if ok {
				toRemove := diffSlice(att.ips, compiledRb.ips)
				toAdd := diffSlice(compiledRb.ips, att.ips)

				// there is no diff and rb still matches, do nothing
				if len(toRemove) == 0 && len(toAdd) == 0 && rbMatches {
					continue
				}

				if !rbMatches {
					// this rb doesn't match anymore. delete the old ips from this attachment's map
					pod.filter.DeleteIps(att.ips)
					delete(pod.attachedFilters, string(rb.UID))
					continue
				}

				// rb matches and there is a diff. add the new ips, delete the old
				// and update our tracking data structures
				pod.filter.DeleteIps(toRemove)
				pod.filter.AddIps(toAdd)
				pod.attachedFilters[string(rb.UID)] = compiledRb
				continue
			}

			// this rb wasn't previously attached to that pod. add its ips if it matches
			if rbMatches {
				pod.filter.AddIps(compiledRb.ips)
				pod.attachedFilters[string(rb.UID)] = compiledRb
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
		filter, err := egressfilter.New(nil)
		if err != nil {
			return err
		}
		cgPaths := containers.ExtractCgPaths(cgInfos)

		err = filter.Attach(cgPaths)
		if err != nil {
			return err
		}

		pa := &podAttachment{
			cgPaths:         cgPaths,
			labels:          pod.Labels,
			filter:          filter,
			attachedFilters: make(map[string]*compiledEgressFilter),
		}

		ipsToBan := []string{}
		for rbName, filter := range e.policies {
			if !filter.selector.Matches(labels.Set(pod.Labels)) {
				continue
			}
			ipsToBan = append(ipsToBan, filter.ips...)
			pa.attachedFilters[rbName] = filter
		}

		pa.filter.AddIps(ipsToBan)
		e.pods[string(pod.UID)] = pa
	case "update":
		cgPaths := containers.ExtractCgPaths(cgInfos)
		pa, ok := e.pods[string(pod.UID)]
		if !ok {
			return fmt.Errorf("got a pod event for a pod that doesn't exist")
		}

		// pod crashes or anything that may trigger a container cgid change
		newCgPaths := diffSlice(pa.cgPaths, cgPaths)
		err := pa.filter.Attach(newCgPaths)
		if err != nil {
			return err
		}

		pa.cgPaths = cgPaths
	case "delete":
		// nothing to do
	}

	return nil
}

func compileRb(rb *v1alpha1.RuntimeBehavior) (*compiledEgressFilter, error) {
	// todo
	return &compiledEgressFilter{
		ips: rb.Spec.Allow.Deny.Network,
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
