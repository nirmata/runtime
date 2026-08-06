package egressmgr

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/protofilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const maxReportedRejectedTargets = 10

// filterFactory builds the per-pod egress filter.
type filterFactory func(logger *logr.Logger) (egressFilter, error)

// protoFilterFactory builds the per-pod protocol classifier.
type protoFilterFactory func(logger *logr.Logger) (protoFilter, error)

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

	newFilter      filterFactory
	newProtoFilter protoFilterFactory
	clock          func() time.Time
}

type podAttachment struct {
	defaultDeny      map[string]struct{} // the group of runtime policy uids that contained a default deny
	protoDefaultDeny map[string]struct{} // same refcount for the protocol behavior's star

	labels          map[string]string
	cgs             map[containers.ContainerCgroupInfo]link.Link
	protoCgs        map[containers.ContainerCgroupInfo]link.Link
	filter          egressFilter
	protoFilter     protoFilter
	attachedFilters map[string]*compiler.EvaluationResult
}

func NewEgressManager(logger logr.Logger, status runtimeevent.PolicyStatusRecorder) *EgressManager {
	return &EgressManager{
		logger: logger,
		status: status,
		pods:   make(map[string]*podAttachment),
		rps:    make(map[string]*compiler.EvaluationResult),
		newFilter: func(logger *logr.Logger) (egressFilter, error) {
			return egressfilter.New(logger)
		},
		newProtoFilter: func(logger *logr.Logger) (protoFilter, error) {
			return protofilter.New(logger)
		},
		clock: time.Now,
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
// bookkeeping. Observe-mode policies program no allow/deny entries, so the bpf
// program cannot return -EPERM for them.
func (e *EgressManager) attachPolicy(podUid string, pa *podAttachment, rp *compiler.EvaluationResult) {
	pa.attachedFilters[rp.UID] = rp
	pa.filter.SetFlagIdx(egressfilter.OBSERVE, true)
	pa.protoFilter.SetFlagIdx(protofilter.OBSERVE, true)

	if compiler.IsObserveMode(rp.Mode) {
		e.logger.V(2).Info("attached observe-mode policy to pod", "podUid", podUid, "uid", rp.UID, "mode", rp.Mode)
		return
	}

	e.addIps(podUid, rp.UID, pa.filter, rp.IPs)
	if denyHasStar(rp.IPs) {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
		pa.defaultDeny[rp.UID] = struct{}{}
	}

	e.addProtos(podUid, rp.UID, pa.protoFilter, rp.Protocols)
	if denyHasStar(rp.Protocols) {
		pa.protoFilter.SetFlagIdx(protofilter.DEFAULT_DENY, true)
		pa.protoDefaultDeny[rp.UID] = struct{}{}
	}
}

// detachPolicy removes the contribution of the policy uid from one pod.
// programmedIPs and programmedProtos are the pairs that were actually written
// to the maps, which differ from the policy's current pairs when the policy
// changed generation.
func (e *EgressManager) detachPolicy(podUid string, pa *podAttachment, uid string, programmedIPs, programmedProtos *compiler.AllowDenyPair) {
	rp, tracked := pa.attachedFilters[uid]
	delete(pa.attachedFilters, uid)
	// observation follows the attachments: the last policy leaving stops it
	if len(pa.attachedFilters) == 0 {
		pa.filter.SetFlagIdx(egressfilter.OBSERVE, false)
		pa.protoFilter.SetFlagIdx(protofilter.OBSERVE, false)
	}

	// an observe-mode policy programmed no targets, so deleting its pairs would
	// drop entries another policy owns
	if tracked && compiler.IsObserveMode(rp.Mode) {
		return
	}

	e.deleteIps(podUid, uid, pa.filter, programmedIPs)
	delete(pa.defaultDeny, uid)
	if len(pa.defaultDeny) == 0 {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, false)
	}

	e.deleteProtos(podUid, uid, pa.protoFilter, programmedProtos)
	delete(pa.protoDefaultDeny, uid)
	if len(pa.protoDefaultDeny) == 0 {
		pa.protoFilter.SetFlagIdx(protofilter.DEFAULT_DENY, false)
	}
}

// addIps programs a pair and surfaces anything the kernel maps could not hold.
// uid is empty when the pair aggregates several policies (pod creation), and the
// rejections are then logged without a policy status to attribute them to.
func (e *EgressManager) addIps(podUid, uid string, f egressFilter, pair *compiler.AllowDenyPair) {
	rejected, err := f.AddIps(pair)
	if err != nil {
		e.logger.Error(err, "failed to program egress targets", "podUid", podUid, "policy", uid)
	}
	e.surfaceRejected(podUid, uid, rejected)
}

func (e *EgressManager) addProtos(podUid, uid string, f protoFilter, pair *compiler.AllowDenyPair) {
	rejected, err := f.AddProtocols(pair)
	if err != nil {
		e.logger.Error(err, "failed to program egress protocol targets", "podUid", podUid, "policy", uid)
	}
	e.surfaceRejected(podUid, uid, rejected)
}

func (e *EgressManager) deleteIps(podUid, uid string, f egressFilter, pair *compiler.AllowDenyPair) {
	rejected, err := f.DeleteIps(pair)
	if err != nil {
		e.logger.Error(err, "failed to remove egress targets", "podUid", podUid, "policy", uid)
	}
	e.logSkippedRemovals(podUid, uid, rejected)
}

func (e *EgressManager) deleteProtos(podUid, uid string, f protoFilter, pair *compiler.AllowDenyPair) {
	rejected, err := f.DeleteProtocols(pair)
	if err != nil {
		e.logger.Error(err, "failed to remove egress protocol targets", "podUid", podUid, "policy", uid)
	}
	e.logSkippedRemovals(podUid, uid, rejected)
}

func (e *EgressManager) logSkippedRemovals(podUid, uid string, rejected []compiler.RejectedTarget) {
	for _, r := range rejected {
		e.logger.V(2).Info("skipped removal of an unsupported egress target", "podUid", podUid, "policy", uid,
			"target", r.Value, "reason", r.Reason)
	}
}

// surfaceRejected records every target the runtime cannot honor on the policy's
// status. The per-pod log stays at V(2); recordTargetsCondition already reports
// the same targets once per policy event.
func (e *EgressManager) surfaceRejected(podUid, uid string, rejected []compiler.RejectedTarget) {
	if len(rejected) == 0 {
		return
	}
	for _, r := range rejected {
		e.logger.V(2).Info("egress target was not programmed",
			"podUid", podUid, "policy", uid, "target", r.Value, "reason", r.Reason)
	}
	e.recordCondition(uid, metav1.Condition{
		Type:               v1alpha1.ConditionTargetsValid,
		Status:             metav1.ConditionFalse,
		Reason:             v1alpha1.ReasonUnsupportedTargets,
		Message:            rejectionMessage(rejected),
		LastTransitionTime: metav1.NewTime(e.clock()),
	})
}

// recordTargetsCondition reports, once per policy event, whether every network
// and protocol target of the policy can be programmed. It parses the policy's
// own values with the parsers the filters use, so the answer does not depend on
// which pods match.
func (e *EgressManager) recordTargetsCondition(rp *compiler.EvaluationResult) {
	if rp == nil {
		return
	}
	netValues := make([]string, 0)
	if rp.IPs != nil {
		netValues = append(netValues, rp.IPs.Allow...)
		netValues = append(netValues, rp.IPs.Deny...)
	}
	protoValues := make([]string, 0)
	if rp.Protocols != nil {
		protoValues = append(protoValues, rp.Protocols.Allow...)
		protoValues = append(protoValues, rp.Protocols.Deny...)
	}
	total := len(netValues) + len(protoValues)
	if total == 0 {
		e.recordCondition(rp.UID, metav1.Condition{
			Type:               v1alpha1.ConditionTargetsValid,
			Status:             metav1.ConditionTrue,
			Reason:             v1alpha1.ReasonNoTargets,
			Message:            "the policy declares no network or protocol targets",
			LastTransitionTime: metav1.NewTime(e.clock()),
		})
		return
	}

	_, _, netRejected := egressfilter.ParseTargets(netValues)
	_, _, protoRejected := protofilter.ParseTargets(protoValues)
	rejected := append(netRejected, protoRejected...)
	if len(rejected) == 0 {
		e.recordCondition(rp.UID, metav1.Condition{
			Type:               v1alpha1.ConditionTargetsValid,
			Status:             metav1.ConditionTrue,
			Reason:             v1alpha1.ReasonAllTargetsSupported,
			Message:            fmt.Sprintf("all %d egress targets are supported", total),
			LastTransitionTime: metav1.NewTime(e.clock()),
		})
		return
	}
	for _, r := range rejected {
		e.logger.V(0).Info("egress target cannot be enforced",
			"policy", rp.UID, "target", r.Value, "reason", r.Reason)
	}
	e.recordCondition(rp.UID, metav1.Condition{
		Type:               v1alpha1.ConditionTargetsValid,
		Status:             metav1.ConditionFalse,
		Reason:             v1alpha1.ReasonUnsupportedTargets,
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

func rejectionMessage(rejected []compiler.RejectedTarget) string {
	parts := make([]string, 0, len(rejected))
	for i, r := range rejected {
		if i == maxReportedRejectedTargets {
			parts = append(parts, fmt.Sprintf("and %d more", len(rejected)-maxReportedRejectedTargets))
			break
		}
		parts = append(parts, r.String())
	}
	return fmt.Sprintf("%d egress target(s) are not enforced: %s", len(rejected), strings.Join(parts, "; "))
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
	return pair != nil && slices.ContainsFunc(pair.Deny, compiler.IsStarTarget)
}
