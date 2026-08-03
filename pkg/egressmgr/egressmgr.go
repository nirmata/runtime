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
const (
	ConditionTargetsValid      = "TargetsValid"
	ReasonUnsupportedTargets   = "UnsupportedTargets"
	ReasonUnresolvedServices   = "UnresolvedServices"
	ReasonAllTargetsSupported  = "AllTargetsSupported"
	ReasonNoTargets            = "NoTargets"
	maxReportedRejectedTargets = 10
)

// filterFactory builds the per-pod egress filter.
type filterFactory func(logger *logr.Logger) (egressFilter, error)

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

	labels          map[string]string
	cgs             map[containers.ContainerCgroupInfo][]link.Link
	filter          egressFilter
	attachedFilters map[string]*compiler.EvaluationResult

	// the policy uids that asked for each programmed target, per side
	allowOwners sideOwners
	denyOwners  sideOwners
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

	if compiler.IsObserveMode(rp.Mode) {
		e.logger.V(2).Info("attached observe-mode policy to pod", "podUid", podUid, "uid", rp.UID, "mode", rp.Mode)
		return
	}

	e.addIps(podUid, rp.UID, pa, rp.IPs)
	if denyHasStar(rp.IPs) {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
		pa.defaultDeny[rp.UID] = struct{}{}
	}
}

// detachPolicy removes the contribution of the policy uid from one pod.
// programmed is the pair that was actually written to the maps, which differs
// from the policy's current pair when the policy changed generation.
func (e *EgressManager) detachPolicy(podUid string, pa *podAttachment, uid string, programmed *compiler.AllowDenyPair) {
	rp, tracked := pa.attachedFilters[uid]
	delete(pa.attachedFilters, uid)
	// observation follows the attachments: the last policy leaving stops it
	if len(pa.attachedFilters) == 0 {
		pa.filter.SetFlagIdx(egressfilter.OBSERVE, false)
	}

	// an observe-mode policy programmed no ips, so deleting its pair would drop
	// entries another policy owns
	if tracked && compiler.IsObserveMode(rp.Mode) {
		return
	}

	e.deleteIps(podUid, uid, pa, programmed)
	delete(pa.defaultDeny, uid)
	if len(pa.defaultDeny) == 0 {
		pa.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, false)
	}
}

// addIps programs a pair and surfaces anything the kernel maps could not hold.
func (e *EgressManager) addIps(podUid, uid string, pa *podAttachment, pair *compiler.AllowDenyPair) {
	pa.claim(uid, pair)
	rejected, err := pa.filter.AddIps(pair)
	if err != nil {
		e.logger.Error(err, "failed to program egress targets", "podUid", podUid, "policy", uid)
	}
	e.surfaceRejected(podUid, uid, rejected)
}

func (e *EgressManager) deleteIps(podUid, uid string, pa *podAttachment, pair *compiler.AllowDenyPair) {
	orphaned := pa.release(uid, pair)
	if !orphaned.HasEntries() {
		return
	}
	rejected, err := pa.filter.DeleteIps(orphaned)
	if err != nil {
		e.logger.Error(err, "failed to remove egress targets", "podUid", podUid, "policy", uid)
	}
	for _, r := range rejected {
		e.logger.V(2).Info("skipped removal of an unsupported egress target", "podUid", podUid, "policy", uid,
			"target", r.Value, "reason", r.Reason)
	}
}

// surfaceRejected records every target the runtime cannot honor on the policy's
// status. The per-pod log stays at V(2); recordTargetsCondition already reports
// the same targets once per policy event.
func (e *EgressManager) surfaceRejected(podUid, uid string, rejected []egressfilter.RejectedTarget) {
	if len(rejected) == 0 {
		return
	}
	for _, r := range rejected {
		e.logger.V(2).Info("egress network target was not programmed",
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
// target of the policy can be programmed. It parses the policy's own values with
// the parser the filter uses, so the answer does not depend on which pods match.
func (e *EgressManager) recordTargetsCondition(rp *compiler.EvaluationResult) {
	if rp == nil {
		return
	}
	values := make([]string, 0)
	if rp.IPs != nil {
		values = append(values, rp.IPs.Allow...)
		values = append(values, rp.IPs.Deny...)
	}
	unresolved := rp.UnresolvedServices
	if len(values) == 0 && len(unresolved) == 0 {
		e.recordCondition(rp.UID, metav1.Condition{
			Type:               ConditionTargetsValid,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonNoTargets,
			Message:            "the policy declares no network targets",
			LastTransitionTime: metav1.NewTime(e.clock()),
		})
		return
	}

	_, _, _, rejected := egressfilter.ParseTargets(values)
	if len(rejected) == 0 && len(unresolved) == 0 {
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
		e.logger.V(0).Info("egress network target cannot be enforced",
			"policy", rp.UID, "target", r.Value, "reason", r.Reason)
	}
	for _, value := range unresolved {
		e.logger.V(0).Info("egress service target did not resolve to any address",
			"policy", rp.UID, "target", value)
	}

	messages := make([]string, 0, 2)
	if len(rejected) > 0 {
		messages = append(messages, rejectionMessage(rejected))
	}
	// an unresolved Service programs nothing, so under deny "*" the destination
	// is blocked outright: it names the condition even when literals were also
	// rejected.
	reason := ReasonUnsupportedTargets
	if len(unresolved) > 0 {
		reason = ReasonUnresolvedServices
		messages = append(messages, unresolvedMessage(unresolved))
	}
	e.recordCondition(rp.UID, metav1.Condition{
		Type:               ConditionTargetsValid,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            strings.Join(messages, "; "),
		LastTransitionTime: metav1.NewTime(e.clock()),
	})
}

// recordCondition resolves the policy's name from the tracked evaluation
// results so callers that only hold a uid do not have to thread it through. An
// untracked uid records no name and the recorder waits for one.
func (e *EgressManager) recordCondition(uid string, cond metav1.Condition) {
	if e.status == nil || uid == "" {
		return
	}
	var name string
	if rp := e.rps[uid]; rp != nil {
		name = rp.Name
	}
	e.status.RecordCondition(uid, name, cond)
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

func unresolvedMessage(values []string) string {
	parts := make([]string, 0, len(values))
	for i, value := range values {
		if i == maxReportedRejectedTargets {
			parts = append(parts, fmt.Sprintf("and %d more", len(values)-maxReportedRejectedTargets))
			break
		}
		parts = append(parts, value)
	}
	return fmt.Sprintf("%d service target(s) did not resolve: %s", len(values), strings.Join(parts, "; "))
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
