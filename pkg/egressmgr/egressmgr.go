package egressmgr

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	corev1 "k8s.io/api/core/v1"
)

type egressManager struct {
	pods map[string]*podAttachment
	rps  map[string]*compiler.EvaluationResult
}

type podAttachment struct {
	labels          map[string]string                            // todo: centralize pod label storage in the podwatcher
	cgs             map[containers.ContainerCgroupInfo]link.Link // todo: can we store this more efficiently
	filter          *egressfilter.EgressFilter
	attachedFilters map[string]*compiler.EvaluationResult
}

func NewEgressManager() *egressManager {
	return &egressManager{
		pods: make(map[string]*podAttachment),
		rps:  make(map[string]*compiler.EvaluationResult),
	}
}

// what about handling compilation outside of this entitity ?
// on a new rp or policy.. we compile and call RuntimePolicyEvent. for periodic recompilation
// we launch a ticker that compiles per interval and calls RuntimePolicyEvent
func (e *egressManager) RuntimePolicyEvent(compiledRb *compiler.EvaluationResult, rpEventType string) error {
	switch rpEventType {
	case events.EventTypeCreate:
		return e.rpCreated(compiledRb)
	case events.EventTypeUpdate:
		return e.rpUpdated(compiledRb)
	case events.EventTypeDelete:
		return e.rpDeleted(compiledRb)
	default:
		return fmt.Errorf("invalid runtime behavior event type")
	}
}

func (e *egressManager) PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error {
	switch podEventType {
	case events.EventTypeCreate:
		return e.podCreated(pod, cgInfos)
	case events.EventTypeUpdate:
		return e.podUpdated(pod, cgInfos)
	case events.EventTypeDelete:
		return e.podDeleted(string(pod.UID))
	default:
		return fmt.Errorf("invalid pod event type")
	}
}
