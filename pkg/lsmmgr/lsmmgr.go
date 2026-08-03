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

	// cgroupSinks gate observation-only sources on the pods the exec policies
	// select. Set before the informers start and not mutated afterwards.
	cgroupSinks []CgroupSink

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

func NewLsmManager(logger logr.Logger, status runtimeevent.PolicyStatusRecorder, cgroupSinks ...CgroupSink) *LsmManager {
	return &LsmManager{
		logger:      logger,
		status:      status,
		cgroupSinks: cgroupSinks,
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
// for them. Attached implies observed, in enforce mode as well: the counted
// paths feed userspace deny delivery. Keep the two calls together.
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
	l.mirrorCgids(rpUID, progType, cgids, true)
}

// removePodCgids is addPodCgids' inverse, and pairs the same two calls.
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
	l.mirrorCgids(rpUID, progType, cgids, false)
}

// mirrorCgids forwards the exec program's cgroup set to the observation-only
// sources that gate on the same pods.
//
// Only the exec attach target is mirrored. A pod can be attached for
// file_open and for bprm_check_security independently, and the sinks hold one
// unqualified set: mirroring both targets would let a file_open detach remove
// a cgroup the exec target still wants.
//
// The same unqualified set means a detach must also survive other policies:
// two exec policies can select one pod, so a removal only reaches the sinks for
// the cgroups no other exec attachment still holds.
func (l *LsmManager) mirrorCgids(rpUID, progType string, cgids []uint64, add bool) {
	if progType != lsm.PROG_TYPE_LSM_EXEC {
		return
	}
	if !add {
		cgids = l.cgidsUnwantedByOtherExecPolicies(rpUID, cgids)
		if len(cgids) == 0 {
			return
		}
	}
	for _, sink := range l.cgroupSinks {
		var err error
		if add {
			err = sink.AddCgids(cgids)
		} else {
			err = sink.DeleteCgids(cgids)
		}
		if err != nil {
			l.logger.Error(err, "failed to mirror cgids to observation source", "uid", rpUID, "add", add)
		}
	}
}

// cgidsUnwantedByOtherExecPolicies filters cgids down to those no exec
// attachment other than excludeUID still selects.
//
// Callers run before their own bookkeeping is torn down — podDeleted and the
// selector sync both remove the pod from attachedPods after the cgid removal —
// so excluding the caller's own policy is what makes this answer the question
// "does anyone else still need this cgroup".
func (l *LsmManager) cgidsUnwantedByOtherExecPolicies(excludeUID string, cgids []uint64) []uint64 {
	wanted := make(map[uint64]struct{})
	for uid, la := range l.lsmAttachments {
		if uid == excludeUID {
			continue
		}
		if _, ok := la.progs[lsm.PROG_TYPE_LSM_EXEC]; !ok {
			continue
		}
		for _, pod := range la.attachedPods {
			for _, cgid := range pod.cgids {
				wanted[cgid] = struct{}{}
			}
		}
	}

	unwanted := make([]uint64, 0, len(cgids))
	for _, cgid := range cgids {
		if _, ok := wanted[cgid]; !ok {
			unwanted = append(unwanted, cgid)
		}
	}
	return unwanted
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
