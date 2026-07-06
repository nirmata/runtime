package lsmmgr

import (
	"context"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// i will assume exec doesn't exist for now
type LsmManager struct {
	pods           map[string]*podRepresentation // pod label storage. todo: take this out of here
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
	enf          *lsm.LsmEnforcer
	selector     labels.Selector
	attachedPods map[string]*podRepresentation
	files        *compiler.AllowDenyPair
}

func NewLsmManager() *LsmManager {
	return &LsmManager{
		pods:           make(map[string]*podRepresentation),
		lsmAttachments: make(map[string]*lsmAttachment),
	}
}

func (l *LsmManager) RuntimePolicyEvent(compiledRb *compiler.EvaluationResult, eventType string) error {
	switch eventType {
	case events.EventTypeCreate:
		return l.rpCreated(compiledRb)
	case events.EventTypeUpdate:
		return l.rpUpdated(compiledRb)
	case events.EventTypeDelete:
		return l.rpDeleted(compiledRb)
	}
	return nil
}

func (l *LsmManager) PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, eventType string) error {
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
