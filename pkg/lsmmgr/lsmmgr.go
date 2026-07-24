package lsmmgr

import (
	"context"
	"sync"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type LsmManager struct {
	logger logr.Logger

	// while each informer is serial, both the pod and the policy informers run in parallel.
	// we need to guard against them both modifying the internal state concurrently
	mu sync.Mutex

	// we are fine with storing pod labels in multiple places which means more memory
	// usage. but the alternative is a centralized dependency that you have to consult
	// everytime you wanna read the labels. the code already contains enough entanglement
	// between data structures
	pods           map[string]*podRepresentation
	lsmAttachments map[string]*lsmAttachment
	wps            map[string]*workloadProfile
}

type podRepresentation struct {
	cgids           []uint64
	labels          map[string]string
	attachedLsms    map[string]*lsmAttachment
	learningEnabled map[string]struct{}
}

type workloadProfile struct {
	cancel context.CancelFunc
	pods   map[string]*podRepresentation
}

type lsmAttachment struct {
	openEnforcer *lsm.LsmEnforcer
	execEnforcer *lsm.LsmEnforcer
	selector     labels.Selector
	attachedPods map[string]*podRepresentation
	openFiles    *compiler.AllowDenyPair
	execFiles    *compiler.AllowDenyPair
}

func (la *lsmAttachment) access(progType string) (enf **lsm.LsmEnforcer, files **compiler.AllowDenyPair) {
	switch progType {
	case lsm.PROG_TYPE_LSM_OPEN:
		return &la.openEnforcer, &la.openFiles
	case lsm.PROG_TYPE_LSM_EXEC:
		return &la.execEnforcer, &la.openFiles
	}
	panic("unknown program type")
}

func NewLsmManager(logger logr.Logger) *LsmManager {
	return &LsmManager{
		logger:         logger,
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
		return l.podCreated(pod, cgInfos)
	case events.EventTypeUpdate:
		return l.podUpdated(pod, cgInfos)
	case events.EventTypeDelete:
		return l.podDeleted(string(pod.UID))
	}
	return nil
}
