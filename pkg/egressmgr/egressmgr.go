package egressmgr

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	corev1 "k8s.io/api/core/v1"
)

type EgressManager struct {
	pods map[string]*podAttachment
	rps  map[string]*compiler.EvaluationResult
	wps  map[string]*workloadProfile
}

// no additional information need to exist on it apart from what pods
// currently are live,
type workloadProfile struct {
	cancel context.CancelFunc
	pods   map[string]*podAttachment
}

type podAttachment struct {
	defaultDeny     map[string]struct{} // the group of runtime policy uids that contained a default deny
	learningEnabled map[string]struct{} // the ids of the workload profiles that specify we should be learning this pod's behavior
	// at the end of the learning duration what happens ?

	labels          map[string]string                            // todo: centralize pod label storage in the podwatcher
	cgs             map[containers.ContainerCgroupInfo]link.Link // todo: can we store this more efficiently
	filter          *egressfilter.EgressFilter
	attachedFilters map[string]*compiler.EvaluationResult
}

func NewEgressManager() *EgressManager {
	return &EgressManager{
		pods: make(map[string]*podAttachment),
		rps:  make(map[string]*compiler.EvaluationResult),
		wps:  make(map[string]*workloadProfile),
	}
}

func (e *EgressManager) RuntimePolicyEvent(compiledRb *compiler.EvaluationResult, rpEventType string) error {
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

func (e *EgressManager) PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error {
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
