package egressmgr

import (
	"fmt"
	"sync"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
)

type EgressManager struct {
	logger logr.Logger

	// while each informer is serial, both the pod and the policy informers run in parallel.
	// we need to guard against them both modifying the internal state concurrently
	mu sync.Mutex

	pods map[string]*podAttachment
	rps  map[string]*compiler.EvaluationResult
}

type podAttachment struct {
	defaultDeny map[string]struct{} // the group of runtime policy uids that contained a default deny

	labels          map[string]string
	cgs             map[containers.ContainerCgroupInfo]link.Link
	filter          *egressfilter.EgressFilter
	attachedFilters map[string]*compiler.EvaluationResult
}

func NewEgressManager(logger logr.Logger) *EgressManager {
	return &EgressManager{
		logger: logger,
		pods:   make(map[string]*podAttachment),
		rps:    make(map[string]*compiler.EvaluationResult),
	}
}

func (e *EgressManager) RuntimePolicyEvent(compiledRb *compiler.EvaluationResult, rpEventType string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch rpEventType {
	case events.EventTypeCreate:
		e.rpCreated(compiledRb)
		return nil
	case events.EventTypeUpdate:
		e.rpUpdated(compiledRb)
		return nil
	case events.EventTypeDelete:
		e.rpDeleted(compiledRb)
		return nil
	default:
		return fmt.Errorf("invalid runtime behavior event type")
	}
}

func (e *EgressManager) PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch podEventType {
	case events.EventTypeCreate:
		return e.podCreated(pod, cgInfos)
	case events.EventTypeUpdate:
		return e.podUpdated(pod, cgInfos)
	case events.EventTypeDelete:
		e.podDeleted(string(pod.UID))
		return nil
	default:
		return fmt.Errorf("invalid pod event type")
	}
}
