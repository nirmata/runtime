package egressmgr

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Condition type and reasons the manager writes onto a RuntimePolicy's status.
// A network target the runtime cannot program must never be dropped silently
// (#41): every rejection reaches a V(0) log AND this condition.
const (
	ConditionTargetsValid      = "TargetsValid"
	ReasonUnsupportedTargets   = "UnsupportedTargets"
	ReasonAllTargetsSupported  = "AllTargetsSupported"
	ReasonNoTargets            = "NoTargets"
	maxReportedRejectedTargets = 10
)

// egressFilter is the narrow set of *egressfilter.EgressFilter methods the
// manager uses. It exists so the manager's bookkeeping can be exercised without
// loading or attaching BPF programs.
//
// Note: *egressfilter.EgressFilter has no Close method, so the seam has none
// either. Pod deletion tears the cgroup (and therefore the links) down in the
// kernel; releasing the map/program FDs is tracked against pkg/bpf.
type egressFilter interface {
	AddIps(pair *compiler.AllowDenyPair) ([]egressfilter.RejectedTarget, error)
	DeleteIps(pair *compiler.AllowDenyPair) ([]egressfilter.RejectedTarget, error)
	SetFlagIdx(idx uint8, val bool)
	Attach(cgPath string) (link.Link, error)
	ReadIPEvents() (map[egressfilter.IPEventKey]uint32, error)
}

// filterFactory builds the per-pod egress filter. It defaults to the real
// egressfilter constructor and is only swapped out in tests.
type filterFactory func(logger *logr.Logger) (egressFilter, error)

// Option customizes an EgressManager at construction time.
type Option func(*EgressManager)

// WithClock overrides the time source used for event and condition timestamps.
func WithClock(clock func() time.Time) Option {
	return func(e *EgressManager) {
		if clock != nil {
			e.clock = clock
		}
	}
}

// withFilterFactory injects the filter constructor. It is unexported because
// the seam interface it returns is unexported: only in-package tests can use it.
func withFilterFactory(f filterFactory) Option {
	return func(e *EgressManager) {
		if f != nil {
			e.newFilter = f
		}
	}
}

type EgressManager struct {
	logger logr.Logger

	// status surfaces policy-level problems (rejected targets) back onto the
	// RuntimePolicy. It may be nil, in which case only logging happens.
	status runtimeevent.PolicyStatusRecorder

	// while each informer is serial, both the pod and the policy informers run in parallel.
	// we need to guard against them both modifying the internal state concurrently
	mu sync.Mutex

	pods map[string]*podAttachment
	rps  map[string]*compiler.EvaluationResult

	newFilter filterFactory
	clock     func() time.Time
}

type podAttachment struct {
	defaultDeny map[string]struct{} // the group of runtime policy uids that contained a default deny
	// observe is the group of observe-mode (monitor) policy uids that
	// asked for observation on this pod. Like defaultDeny it is a refcount: the
	// OBSERVE flag may only clear when the last of them is gone.
	observe map[string]struct{}

	labels          map[string]string
	cgs             map[containers.ContainerCgroupInfo]link.Link
	filter          egressFilter
	attachedFilters map[string]*compiler.EvaluationResult
}

func NewEgressManager(logger logr.Logger, status runtimeevent.PolicyStatusRecorder, opts ...Option) *EgressManager {
	e := &EgressManager{
		logger: logger,
		status: status,
		pods:   make(map[string]*podAttachment),
		rps:    make(map[string]*compiler.EvaluationResult),
		newFilter: func(logger *logr.Logger) (egressFilter, error) {
			return egressfilter.New(logger)
		},
		clock: time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	return e
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
	default:
		return fmt.Errorf("invalid pod event type")
	}
}

// PodDeleted tears down the pod's egress filter and bookkeeping.
func (e *EgressManager) PodDeleted(uid string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.podDeleted(uid)
	return nil
}

// attachPolicy programs rp's contribution onto one pod and records the
// bookkeeping. Observe-mode policies program NO allow/deny entries: they only
// turn the OBSERVE flag on, so the BPF program never returns -EPERM for them.
func (e *EgressManager) attachPolicy(podUid string, pa *podAttachment, rp *compiler.EvaluationResult) {
	pa.attachedFilters[rp.UID] = rp

	if compiler.IsObserveMode(rp.Mode) {
		e.logger.V(2).Info("enabling egress observation for pod", "podUid", podUid, "uid", rp.UID, "mode", rp.Mode)
		pa.observe[rp.UID] = struct{}{}
		pa.filter.SetFlagIdx(egressfilter.OBSERVE, true)
		return
	}

	e.addIps(podUid, rp.UID, pa.filter, rp.IPs)
	if denyHasStar(rp.IPs) {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
		pa.defaultDeny[rp.UID] = struct{}{}
	}
}

// detachPolicy removes the contribution of the policy uid from one pod.
// programmed is the pair that was actually written to the maps (it may differ
// from the policy's current pair when a policy changed generation), and is
// ignored for observe-mode policies, which never programmed anything.
func (e *EgressManager) detachPolicy(podUid string, pa *podAttachment, uid string, observe bool, programmed *compiler.AllowDenyPair) {
	delete(pa.attachedFilters, uid)

	if observe {
		delete(pa.observe, uid)
		// refcount: only the last observe-mode policy leaving clears the flag
		if len(pa.observe) == 0 {
			pa.filter.SetFlagIdx(egressfilter.OBSERVE, false)
		}
		return
	}

	e.deleteIps(podUid, uid, pa.filter, programmed)
	delete(pa.defaultDeny, uid)
	if len(pa.defaultDeny) == 0 {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, false)
	}
}

// addIps programs a pair and surfaces anything the kernel maps could not hold.
// uid may be empty when the pair aggregates several policies (pod creation), in
// which case the rejections are logged but not attributed to a policy status —
// the policy-level condition was already recorded when the policy was admitted.
func (e *EgressManager) addIps(podUid, uid string, f egressFilter, pair *compiler.AllowDenyPair) {
	rejected, err := f.AddIps(pair)
	if err != nil {
		e.logger.Error(err, "failed to program egress targets", "podUid", podUid, "policy", uid)
	}
	e.surfaceRejected(podUid, uid, rejected)
}

func (e *EgressManager) deleteIps(podUid, uid string, f egressFilter, pair *compiler.AllowDenyPair) {
	rejected, err := f.DeleteIps(pair)
	if err != nil {
		e.logger.Error(err, "failed to remove egress targets", "podUid", podUid, "policy", uid)
	}
	// a removal of an unprogrammable target is not news for an operator: the
	// add already said it out loud. Keep it at V(2).
	for _, r := range rejected {
		e.logger.V(2).Info("skipped removal of an unsupported egress target", "podUid", podUid, "policy", uid,
			"target", r.Value, "reason", r.Reason)
	}
}

// surfaceRejected is #41's loud half: every target the runtime cannot honor is
// logged at V(0) and attached to the policy's status.
func (e *EgressManager) surfaceRejected(podUid, uid string, rejected []egressfilter.RejectedTarget) {
	if len(rejected) == 0 {
		return
	}
	for _, r := range rejected {
		e.logger.V(0).Info("egress network target cannot be enforced and was NOT programmed",
			"podUid", podUid, "policy", uid, "target", r.Value, "reason", r.Reason)
	}
	e.recordCondition(uid, metav1.Condition{
		Type:               ConditionTargetsValid,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonUnsupportedTargets,
		Message:            rejectionMessage(rejected),
		LastTransitionTime: metav1.NewTime(e.clock()),
	})
}

// recordTargetsCondition reports, once per policy event, whether every network
// target of the policy can be programmed. It runs the policy's own values
// through the same parser the filter uses, so the answer does not depend on
// which pods happen to match.
func (e *EgressManager) recordTargetsCondition(rp *compiler.EvaluationResult) {
	if rp == nil {
		return
	}
	values := make([]string, 0)
	if rp.IPs != nil {
		values = append(values, rp.IPs.Allow...)
		values = append(values, rp.IPs.Deny...)
	}
	if len(values) == 0 {
		e.recordCondition(rp.UID, metav1.Condition{
			Type:               ConditionTargetsValid,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonNoTargets,
			Message:            "the policy declares no network targets",
			LastTransitionTime: metav1.NewTime(e.clock()),
		})
		return
	}

	_, _, rejected := egressfilter.ParseTargets(values)
	if len(rejected) == 0 {
		e.recordCondition(rp.UID, metav1.Condition{
			Type:               ConditionTargetsValid,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonAllTargetsSupported,
			Message:            fmt.Sprintf("all %d network targets are supported", len(values)),
			LastTransitionTime: metav1.NewTime(e.clock()),
		})
		return
	}
	for _, r := range rejected {
		e.logger.V(0).Info("egress network target cannot be enforced and was NOT programmed",
			"policy", rp.UID, "target", r.Value, "reason", r.Reason)
	}
	e.recordCondition(rp.UID, metav1.Condition{
		Type:               ConditionTargetsValid,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonUnsupportedTargets,
		Message:            rejectionMessage(rejected),
		LastTransitionTime: metav1.NewTime(e.clock()),
	})
}

func (e *EgressManager) recordCondition(uid string, cond metav1.Condition) {
	if e.status == nil || uid == "" {
		return
	}
	e.status.RecordCondition(uid, cond)
}

func rejectionMessage(rejected []egressfilter.RejectedTarget) string {
	parts := make([]string, 0, len(rejected))
	for i, r := range rejected {
		if i == maxReportedRejectedTargets {
			parts = append(parts, fmt.Sprintf("and %d more", len(rejected)-maxReportedRejectedTargets))
			break
		}
		parts = append(parts, r.String())
	}
	return fmt.Sprintf("%d network target(s) are not enforced: %s", len(rejected), strings.Join(parts, "; "))
}

// clonePair copies a pair so later mutations of the policy cannot rewrite what
// a pod believes it programmed. A nil pair yields an empty (non-nil) one.
func clonePair(pair *compiler.AllowDenyPair) *compiler.AllowDenyPair {
	if pair == nil {
		return &compiler.AllowDenyPair{}
	}
	return &compiler.AllowDenyPair{
		Allow: slices.Clone(pair.Allow),
		Deny:  slices.Clone(pair.Deny),
	}
}

func denyHasStar(pair *compiler.AllowDenyPair) bool {
	return pair != nil && slices.Contains(pair.Deny, compiler.StarTarget)
}
