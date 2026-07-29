// Package lsmmgr owns the lifecycle of the bpf LSM enforcers: it turns
// RuntimePolicy evaluation results and pod events into attached programs whose
// cgroup-id, allow and deny maps track the current state of the node.
//
// Two things are deliberately indirected so the state machine can be exercised
// without a kernel: the enforcer surface (the lsmEnforcer interface) and the
// factory that builds one (enforcerFactory, injectable through an option).
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

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// lsmEnforcer is the narrow surface of the bpf lsm enforcer that this package
// depends on. It is declared here (and satisfied structurally by
// *lsm.LsmEnforcer) so the manager's state machine can be exercised without
// loading bpf programs.
type lsmEnforcer interface {
	Attach() (link.Link, error)
	Close() error
	AddCgids(cgids []uint64) error
	DeleteCgids(cgids []uint64) error
	AddTargets(paths *compiler.AllowDenyPair) error
	DeleteTargets(paths *compiler.AllowDenyPair) error
	SetDefaultDeny(val bool) error
	EnableObservation(cgids []uint64) error
	DisableObservation(cgids []uint64) error
	ReadEvents(cgids []uint64) (map[uint64]map[lsm.PathEventKey]uint32, error)
}

// the production enforcer must keep satisfying the seam.
var _ lsmEnforcer = (*lsm.LsmEnforcer)(nil)

// enforcerFactory builds an enforcer for a bpf lsm attach target.
type enforcerFactory func(logger *logr.Logger, target string) (lsmEnforcer, error)

// Option customizes an LsmManager at construction time.
type Option func(*LsmManager)

// WithClock replaces the clock used to timestamp observed events.
func WithClock(clock func() time.Time) Option {
	return func(l *LsmManager) {
		if clock != nil {
			l.clock = clock
		}
	}
}

// withEnforcerFactory injects the enforcer constructor. Unexported: production
// always uses lsm.NewForAttachTarget, only tests substitute a fake.
func withEnforcerFactory(f enforcerFactory) Option {
	return func(l *LsmManager) {
		if f != nil {
			l.newEnforcer = f
		}
	}
}

type LsmManager struct {
	logger logr.Logger

	// status surfaces per-policy conditions (e.g. observation unavailable) so a
	// policy that cannot be honored is never silently degraded. May be nil.
	status runtimeevent.PolicyStatusRecorder

	// newEnforcer builds an enforcer for a given bpf lsm attach target.
	newEnforcer enforcerFactory

	clock func() time.Time

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
	enf   lsmEnforcer
	files *compiler.AllowDenyPair
}

type lsmAttachment struct {
	progs        map[string]*progState
	selector     labels.Selector
	attachedPods map[string]*podRepresentation

	// observe is true for monitor policies: their enforcers are
	// attached with EMPTY banned/allowed maps and default-deny unset, so the
	// kernel program can never return -EPERM for them. They exist purely to
	// count open/exec paths per cgroup.
	observe bool
}

func NewLsmManager(logger logr.Logger, status runtimeevent.PolicyStatusRecorder, opts ...Option) *LsmManager {
	l := &LsmManager{
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
	for _, opt := range opts {
		if opt != nil {
			opt(l)
		}
	}
	return l
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
// for them. Observation is enabled in enforce mode too: the counted paths are
// what feeds userspace deny delivery.
//
// Map failures are logged, never fatal — losing one cgid must not abort the
// manager's bookkeeping for the rest.
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

// observationUnavailable reports an observation failure loudly: V(0) for the
// operator plus a policy condition, because a policy whose observation could not
// be turned on produces no findings at all and must not look healthy.
func (l *LsmManager) observationUnavailable(rpUID, progType, msg string, err error) {
	if errors.Is(err, lsm.ErrObservationUnavailable) {
		l.logger.V(0).Info(msg, "uid", rpUID, "progType", progType, "reason", err.Error())
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
