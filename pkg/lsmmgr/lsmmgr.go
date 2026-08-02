package lsmmgr

import (
	"errors"
	"fmt"
	"strings"
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

// Condition types and reasons the manager writes onto a RuntimePolicy's status.
// Exec and open get a condition each because conditions are keyed by type and
// last-write-wins: one shared type would report whichever behavior was recorded
// last.
const (
	ConditionExecRulesValid  = "ExecRulesValid"
	ConditionOpenRulesValid  = "OpenRulesValid"
	ReasonUnsupportedPaths   = "UnsupportedPaths"
	ReasonAllPathsSupported  = "AllPathsSupported"
	ReasonNoPaths            = "NoPaths"
	maxReportedRejectedPaths = 10
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

// recordPathRulesCondition reports, once per policy event, whether every path
// value of one behavior can be programmed. It parses the policy's own values
// with the parser the enforcer uses, so the answer holds in observe mode too,
// where nothing reaches a kernel map at all.
func (l *LsmManager) recordPathRulesCondition(rpUID, condType string, pair *compiler.AllowDenyPair) {
	if !pair.HasEntries() {
		l.recordCondition(rpUID, metav1.Condition{
			Type:               condType,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonNoPaths,
			Message:            "the policy declares no paths for this behavior",
			LastTransitionTime: metav1.NewTime(l.clock()),
		})
		return
	}

	_, _, rejected := lsm.ParsePaths(pair.Deny)
	_, _, allowRejected := lsm.ParsePaths(pair.Allow)
	rejected = append(rejected, allowRejected...)
	if len(rejected) == 0 {
		l.recordCondition(rpUID, metav1.Condition{
			Type:               condType,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonAllPathsSupported,
			Message:            fmt.Sprintf("all %d paths are supported", len(pair.Allow)+len(pair.Deny)),
			LastTransitionTime: metav1.NewTime(l.clock()),
		})
		return
	}
	for _, r := range rejected {
		l.logger.V(0).Info("path cannot be enforced", "policy", rpUID, "condition", condType,
			"path", r.Value, "reason", r.Reason)
	}
	l.recordCondition(rpUID, metav1.Condition{
		Type:               condType,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonUnsupportedPaths,
		Message:            rejectionMessage(rejected),
		LastTransitionTime: metav1.NewTime(l.clock()),
	})
}

// logRejected reports what one enforcer refused to key. recordPathRulesCondition
// already carries the same values onto the policy status, so this stays at V(2)
// and only adds the program type.
func (l *LsmManager) logRejected(rpUID, progType string, rejected []lsm.RejectedTarget) {
	for _, r := range rejected {
		l.logger.V(2).Info("path was not programmed", "uid", rpUID, "progType", progType,
			"path", r.Value, "reason", r.Reason)
	}
}

func rejectionMessage(rejected []lsm.RejectedTarget) string {
	parts := make([]string, 0, len(rejected))
	for i, r := range rejected {
		if i == maxReportedRejectedPaths {
			parts = append(parts, fmt.Sprintf("and %d more", len(rejected)-maxReportedRejectedPaths))
			break
		}
		parts = append(parts, r.String())
	}
	return fmt.Sprintf("%d path(s) are not enforced: %s", len(rejected), strings.Join(parts, "; "))
}

func (l *LsmManager) recordCondition(rpUID string, cond metav1.Condition) {
	if l.status == nil || rpUID == "" {
		return
	}
	l.status.RecordCondition(rpUID, cond)
}
