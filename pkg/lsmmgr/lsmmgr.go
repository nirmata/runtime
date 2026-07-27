package lsmmgr

import (
	"sync"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// enforcer is the narrow surface of the bpf lsm enforcer that this package depends on.
// it is declared here (and satisfied structurally by *lsm.LsmEnforcer) so the manager's
// state machine can be exercised without loading bpf programs.
type enforcer interface {
	Attach() (link.Link, error)
	Close() error
	AddCgids(cgids []uint64) error
	DeleteCgids(cgids []uint64) error
	AddTargets(paths *compiler.AllowDenyPair) error
	DeleteTargets(paths *compiler.AllowDenyPair) error
	SetDefaultDeny(val bool) error
}

type LsmManager struct {
	logger logr.Logger

	// newEnforcer builds an enforcer for a given bpf lsm attach target. it is a field
	// so tests can inject a fake; production always uses lsm.NewForAttachTarget.
	newEnforcer func(logger *logr.Logger, target string) (enforcer, error)

	// while each informer is serial, both the pod and the policy informers run in parallel.
	// we need to guard against them both modifying the internal state concurrently
	mu sync.Mutex

	// we are fine with storing pod labels in multiple places which means more memory
	// usage. but the alternative is a centralized dependency that you have to consult
	// everytime you wanna read the labels. the code already contains enough entanglement
	// between data structures
	pods           map[string]*podRepresentation
	lsmAttachments map[string]*lsmAttachment
}

type podRepresentation struct {
	cgids        []uint64
	labels       map[string]string
	attachedLsms map[string]*lsmAttachment
}

type progState struct {
	enf   enforcer
	files *compiler.AllowDenyPair
}

type lsmAttachment struct {
	progs        map[string]*progState
	selector     labels.Selector
	attachedPods map[string]*podRepresentation
}

func NewLsmManager(logger logr.Logger) *LsmManager {
	return &LsmManager{
		logger: logger,
		newEnforcer: func(logger *logr.Logger, target string) (enforcer, error) {
			enf, err := lsm.NewForAttachTarget(logger, target)
			if err != nil {
				return nil, err
			}
			return enf, nil
		},
		pods:           make(map[string]*podRepresentation),
		lsmAttachments: make(map[string]*lsmAttachment),
	}
}

func (l *LsmManager) RuntimePolicyEvent(compiledRb *compiler.EvaluationResult, eventType string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch eventType {
	case events.EventTypeCreate:
		return l.rpCreated(compiledRb)
	case events.EventTypeUpdate:
		return l.rpUpdated(compiledRb)
	case events.EventTypeDelete:
		l.rpDeleted(compiledRb)
	}
	return nil
}

func (l *LsmManager) PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, eventType string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch eventType {
	case events.EventTypeCreate:
		l.podCreated(pod, cgInfos)
		return nil
	case events.EventTypeUpdate:
		return l.podUpdated(pod, cgInfos)
	case events.EventTypeDelete:
		l.podDeleted(string(pod.UID))
		return nil
	}
	return nil
}
