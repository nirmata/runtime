package lsmmgr

import (
	"errors"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// enforcerFactory builds an enforcer for a bpf lsm attach target.
type enforcerFactory func(logger *logr.Logger, target string) (lsmEnforcer, error)

type LsmManager struct {
	logger logr.Logger

	// surfaces per-policy conditions so a policy that cannot be honored does not
	// look healthy. may be nil
	status runtimeevent.PolicyStatusRecorder

	newEnforcer enforcerFactory
	clock       func() time.Time

	// while each informer is serial, both the pod and the policy informers run in parallel.
	// we need to guard against them both modifying the internal state concurrently
	mu sync.Mutex

	// labels are stored in several places, costing memory, because the alternative is
	// one more centralized dependency to consult on every read
	pods           map[string]*podRepresentation
	lsmAttachments map[string]*lsmAttachment
}

type podRepresentation struct {
	cgids        []uint64
	labels       map[string]string
	attachedLsms map[string]*lsmAttachment
}

type progState struct {
	enf   lsmEnforcer
	files *compiler.AllowDenyPair
}

type lsmAttachment struct {
	progs        map[string]*progState
	selector     labels.Selector
	attachedPods map[string]*podRepresentation

	// monitor policies: the enforcers are attached with empty banned and allowed
	// maps and default-deny unset, so the program cannot return -EPERM. they only
	// count open and exec paths per cgroup
	observe bool
}

func NewLsmManager(logger logr.Logger, status runtimeevent.PolicyStatusRecorder) *LsmManager {
	return &LsmManager{
		logger: logger,
		status: status,
		newEnforcer: func(logger *logr.Logger, target string) (lsmEnforcer, error) {
			enf, err := lsm.NewForAttachTarget(logger, target)
			if err != nil {
				return nil, err
			}
			return enf, nil
		},
		clock:          time.Now,
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
	}
	return nil
}

// PodDeleted removes the pod's cgroups from every attached program and drops
// its bookkeeping.
func (l *LsmManager) PodDeleted(uid string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.podDeleted(uid)
	return nil
}

// addPodCgids adds cgids to one program's cgroup map and turns observation on
// for them. Observation is enabled in enforce mode too: the counted paths feed
// userspace deny delivery.
func (l *LsmManager) addPodCgids(rpUID, progType string, prog *progState, cgids []uint64) {
	if len(cgids) == 0 {
		return
	}
	if err := prog.enf.AddCgids(cgids); err != nil {
		l.logger.Error(err, "failed to add cgids to enforcer", "uid", rpUID, "progType", progType)
	}
	if err := prog.enf.EnableObservation(cgids); err != nil {
		l.observationUnavailable(rpUID, progType, "failed to enable observation", err)
	}
}

// removePodCgids is addPodCgids' inverse.
func (l *LsmManager) removePodCgids(rpUID, progType string, prog *progState, cgids []uint64) {
	if len(cgids) == 0 {
		return
	}
	if err := prog.enf.DeleteCgids(cgids); err != nil {
		l.logger.Error(err, "failed to remove cgids from enforcer", "uid", rpUID, "progType", progType)
	}
	if err := prog.enf.DisableObservation(cgids); err != nil {
		l.observationUnavailable(rpUID, progType, "failed to disable observation", err)
	}
}

// observationUnavailable records a policy condition for an observation failure:
// the policy produces no findings at all, so it should not read as healthy.
func (l *LsmManager) observationUnavailable(rpUID, progType, msg string, err error) {
	if errors.Is(err, lsm.ErrObservationUnavailable) {
		l.logger.V(2).Info(msg, "uid", rpUID, "progType", progType, "reason", err.Error())
	} else {
		l.logger.Error(err, msg, "uid", rpUID, "progType", progType)
	}
	l.recordCondition(rpUID, metav1.Condition{
		Type:    "ObservationAvailable",
		Status:  metav1.ConditionFalse,
		Reason:  "ObservationUnavailable",
		Message: msg + " for " + progType + ": " + err.Error(),
	})
}

func (l *LsmManager) recordCondition(rpUID string, cond metav1.Condition) {
	if l.status == nil || rpUID == "" {
		return
	}
	l.status.RecordCondition(rpUID, cond)
}
