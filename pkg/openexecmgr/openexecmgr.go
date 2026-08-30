package openexecmgr

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/bpf/openexec"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/containers"
	"github.com/nirmata/runtime/pkg/events"
	"github.com/nirmata/runtime/pkg/runtimeevent"
	"github.com/nirmata/runtime/pkg/utils"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const maxReportedRejectedPaths = 10

// enforcerFactory builds an enforcer for a bpf lsm attach target.
type enforcerFactory func(logger *logr.Logger, target string) (openExecMap, error)

type OpenExecManager struct {
	logger logr.Logger

	// surfaces per-policy conditions so a policy that cannot be honored does not
	// look healthy. may be nil
	status runtimeevent.PolicyStatusRecorder

	newEnforcer enforcerFactory
	clock       func() time.Time

	// onLoss reports kernel-side observation losses, normally to a metrics
	// counter. may be nil
	onLoss runtimeevent.LossFunc

	// cgroupSinks gate observation-only sources on the pods the exec policies
	// select. Set before the informers start and not mutated afterwards.
	cgroupSinks []CgroupSink

	// while each informer is serial, both the pod and the policy informers run in parallel.
	// we need to guard against them both modifying the internal state concurrently
	mu sync.Mutex

	// labels are stored in several places, costing memory, because the alternative is
	// one more centralized dependency to consult on every read
	pods                map[string]*podRepresentation
	openExecAttachments map[string]*openExecAttachment
	programs            map[string]monitoringIface

	lsm bool
}

type podRepresentation struct {
	cgids             []uint64
	labels            map[string]string
	nsLabels          map[string]string
	attachedOpenExecs map[string]*openExecAttachment
}

type progState struct {
	enf   openExecMap
	files *compiler.AllowDenyPair
}

type openExecAttachment struct {
	policyMaps   map[string]*progState
	target       compiler.PodTarget
	attachedPods map[string]*podRepresentation

	// monitor policies: the enforcers are attached with empty banned and allowed
	// maps and default-deny unset, so the program cannot return -EPERM. they only
	// count open and exec paths per cgroup
	observe bool

	// badProgs names, for each program type currently failing (an attach that
	// never took, or a later cgid/observation operation that did), why. The
	// shared EnforcementAvailable/ObservationAvailable condition is written as
	// an aggregate over this set rather than from any single operation's
	// outcome, so one program type recovering can never mask another that is
	// still broken, and vice versa.
	badProgs map[string]string
}

// NewOpenExecManager loads and attaches the dispatcher for each lsm hook the
// manager enforces through. The dispatchers are the only programs linked to
// the kernel; enforcers built later join their tail-call chains.
func NewOpenExecManager(logger logr.Logger, status runtimeevent.PolicyStatusRecorder, onLoss runtimeevent.LossFunc, lsm bool, cgroupSinks ...CgroupSink) (*OpenExecManager, error) {
	if err := openexec.ClearPins(); err != nil {
		return nil, err
	}

	progArrayType := []string{openexec.PROG_TYPE_TRACE_OPEN, openexec.PROG_TYPE_TRACE_EXEC}
	if lsm {
		logger.V(2).Info("BPF-LSM is not available, using fmod_ret based enforcement")
		progArrayType = []string{openexec.PROG_TYPE_LSM_OPEN, openexec.PROG_TYPE_LSM_EXEC}
	}

	dispatchers := make(map[string]*openexec.Dispatcher, 2)
	programs := make(map[string]monitoringIface, 2)

	for _, target := range progArrayType {
		d, err := openexec.NewDispatcherForTarget(target)
		if err != nil {
			return nil, fmt.Errorf("loading the %s dispatcher: %w", target, err)
		}
		if err := d.Attach(); err != nil {
			return nil, fmt.Errorf("attaching the %s dispatcher: %w", target, err)
		}
		dispatchers[target] = d

		p, err := openexec.NewProgram(d)
		if err != nil {
			return nil, fmt.Errorf("creating the %s enforcer program: %w", target, err)
		}

		programs[target] = p
	}

	newEnforcer := func(logger *logr.Logger, target string) (openExecMap, error) {
		d, ok := dispatchers[target]
		if !ok {
			return nil, fmt.Errorf("unknown lsm attach target %q", target)
		}
		return openexec.NewPolicyMap(d, logger)
	}

	return newOpenExecManager(logger, status, onLoss, newEnforcer, programs, lsm, cgroupSinks...), nil
}

func newOpenExecManager(logger logr.Logger, status runtimeevent.PolicyStatusRecorder, onLoss runtimeevent.LossFunc,
	newEnforcer enforcerFactory, programs map[string]monitoringIface, lsm bool, cgroupSinks ...CgroupSink) *OpenExecManager {
	return &OpenExecManager{
		logger:              logger,
		status:              status,
		onLoss:              onLoss,
		cgroupSinks:         cgroupSinks,
		newEnforcer:         newEnforcer,
		programs:            programs,
		clock:               time.Now,
		lsm:                 lsm,
		pods:                make(map[string]*podRepresentation),
		openExecAttachments: make(map[string]*openExecAttachment),
	}
}

func (l *OpenExecManager) RuntimePolicyEvent(compiledRb *compiler.EvaluationResult, eventType string) error {
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

func (l *OpenExecManager) PodEvent(pod corev1.Pod, nsLabels map[string]string, cgInfos []*containers.ContainerCgroupInfo, eventType string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch eventType {
	case events.EventTypeCreate:
		l.podCreated(pod, nsLabels, cgInfos)
		return nil
	case events.EventTypeUpdate:
		return l.podUpdated(pod, nsLabels, cgInfos)
	}
	return nil
}

// PodDeleted removes the pod's cgroups from every attached program and drops
// its bookkeeping.
func (l *OpenExecManager) PodDeleted(uid string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.podDeleted(uid)
	return nil
}

// addPodCgids adds cgids to one program's cgroup map and turns observation on
// for them. Attached implies observed, in enforce mode as well: the counted
// paths feed userspace deny delivery. Keep the two calls together.
func (l *OpenExecManager) addPodCgids(rpUID, progType string, prog *progState, cgids []uint64, observe bool) {
	if len(cgids) == 0 {
		return
	}
	if err := prog.enf.AddCgids(cgids); err != nil {
		if observe {
			l.observationUnavailable(rpUID, progType, "failed to add cgids to enforcer", err)
		} else {
			l.enforcementUnavailable(rpUID, progType, "failed to add cgids to enforcer", err)
		}
	}
	if p, ok := l.programs[progType]; ok {
		if err := p.EnableObservation(cgids); err != nil {
			l.observationUnavailable(rpUID, progType, "failed to enable observation", err)
		}
	}
	l.mirrorCgids(rpUID, progType, cgids, true)
}

// disableObservation stops the per-cgid path counting on one program type.
// Observation is shared across every policy watching a cgid, so callers only
// pass cgids no attached policy needs anymore.
func (l *OpenExecManager) disableObservation(progType string, cgids []uint64) {
	if len(cgids) == 0 {
		return
	}
	p, ok := l.programs[progType]
	if !ok {
		return
	}
	if err := p.DisableObservation(cgids); err != nil {
		l.logger.Error(err, "failed to disable observation", "progType", progType)
	}
}

// removePodCgids takes cgids out of one policy's map. Observation is not
// paired here: it is shared across policies, so callers turn it off through
// disableObservation only for cgids no attached policy needs anymore.
func (l *OpenExecManager) removePodCgids(rpUID, progType string, prog *progState, cgids []uint64) {
	if len(cgids) == 0 {
		return
	}
	if err := prog.enf.DeleteCgids(cgids); err != nil {
		l.logger.Error(err, "failed to remove cgids from enforcer", "uid", rpUID, "progType", progType)
	}
	l.mirrorCgids(rpUID, progType, cgids, false)
}

// mirrorCgids forwards the exec target's cgroup set to the cgroup sinks. The
// sinks hold one unqualified set, so only the exec target is mirrored, and a
// removal reaches them only for cgroups no other exec attachment still holds.
func (l *OpenExecManager) mirrorCgids(rpUID, progType string, cgids []uint64, add bool) {
	if progType != openexec.PROG_TYPE_LSM_EXEC {
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
func (l *OpenExecManager) cgidsUnwantedByOtherExecPolicies(excludeUID string, cgids []uint64) []uint64 {
	wanted := make(map[uint64]struct{})
	for uid, la := range l.openExecAttachments {
		if uid == excludeUID {
			continue
		}
		if _, ok := la.policyMaps[openexec.PROG_TYPE_LSM_EXEC]; !ok {
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
func (l *OpenExecManager) observationUnavailable(rpUID, progType, msg string, err error) {
	if errors.Is(err, openexec.ErrObservationUnavailable) {
		l.logger.V(2).Info(msg, "uid", rpUID, "progType", progType, "reason", err.Error())
	} else {
		l.logger.Error(err, msg, "uid", rpUID, "progType", progType)
	}
	l.markBad(rpUID, progType, true, msg+" for "+progType+": "+err.Error())
}

// enforcementUnavailable records a policy condition for a kernel map the
// runtime could not program: the workload runs on, unenforced, so the failure
// is invisible everywhere else.
func (l *OpenExecManager) enforcementUnavailable(rpUID, progType, msg string, err error) {
	l.logger.Error(err, msg, "uid", rpUID, "progType", progType)
	l.markBad(rpUID, progType, false, msg+" for "+progType+": "+err.Error())
}

// reportAttachFailure records why an enforcer could not be built or attached
// for one program type, so a node that can never honor a policy's open/exec
// rules does not read the same as one that is honoring them. rpCreated and
// syncProgType are the two places an attach is first attempted.
func (l *OpenExecManager) reportAttachFailure(rpUID, progType string, observe bool, err error) {
	err = l.diagnoseAttachErr(err)
	if observe {
		l.observationUnavailable(rpUID, progType, "failed to attach lsm enforcer", err)
	} else {
		l.enforcementUnavailable(rpUID, progType, "failed to attach lsm enforcer", err)
	}
}

// clearAttachFailure asserts that a program type is attached and programmed,
// undoing a previous reportAttachFailure once a retry of the same event
// succeeds — this is on the requeue path, so a transient cause (unlike a
// missing BPF-LSM) can clear between attempts.
func (l *OpenExecManager) clearAttachFailure(rpUID, progType string, observe bool) {
	l.markGood(rpUID, progType, observe)
}

// markBad records progType as currently failing for rpUID's attachment and
// reasserts EnforcementAvailable/ObservationAvailable as an aggregate over
// every program type that attachment currently knows about. A policy with no
// tracked attachment yet — the very first attach attempt, before rpCreated
// has stored one — has nothing to aggregate against, so the condition is
// written directly instead.
func (l *OpenExecManager) markBad(rpUID, progType string, observe bool, message string) {
	if la, ok := l.openExecAttachments[rpUID]; ok {
		if la.badProgs == nil {
			la.badProgs = make(map[string]string)
		}
		la.badProgs[progType] = message
		l.recordAttachAggregate(rpUID, la, observe)
		return
	}
	l.recordAvailability(rpUID, observe, metav1.ConditionFalse, message)
}

// markGood is markBad's inverse: it clears progType out of a tracked
// attachment's bad set once it recovers, so a different program type that is
// still bad keeps the aggregate condition False instead of being masked by
// this one's recovery.
func (l *OpenExecManager) markGood(rpUID, progType string, observe bool) {
	if la, ok := l.openExecAttachments[rpUID]; ok {
		delete(la.badProgs, progType)
		l.recordAttachAggregate(rpUID, la, observe)
		return
	}
	l.recordAvailability(rpUID, observe, metav1.ConditionTrue, "the "+progType+" enforcer is attached and programmed")
}

// recordAttachAggregate writes EnforcementAvailable/ObservationAvailable from
// la's current bad set: True only when it is empty, False naming every
// program type still in it otherwise.
func (l *OpenExecManager) recordAttachAggregate(rpUID string, la *openExecAttachment, observe bool) {
	if len(la.badProgs) == 0 {
		l.recordAvailability(rpUID, observe, metav1.ConditionTrue, "every attached program type is programmed and functioning")
		return
	}
	progTypes := make([]string, 0, len(la.badProgs))
	for p := range la.badProgs {
		progTypes = append(progTypes, p)
	}
	sort.Strings(progTypes)
	parts := make([]string, 0, len(progTypes))
	for _, p := range progTypes {
		parts = append(parts, p+": "+la.badProgs[p])
	}
	l.recordAvailability(rpUID, observe, metav1.ConditionFalse, strings.Join(parts, "; "))
}

// recordAvailability writes EnforcementAvailable (enforce mode) or
// ObservationAvailable (monitor mode), the one shared condition type every
// program type of a policy reports through.
func (l *OpenExecManager) recordAvailability(rpUID string, observe bool, status metav1.ConditionStatus, message string) {
	condType := v1alpha1.ConditionEnforcementAvailable
	reason := v1alpha1.ReasonEnforcementUnavailable
	if observe {
		condType = v1alpha1.ConditionObservationAvailable
		reason = v1alpha1.ReasonObservationUnavailable
	}
	if status == metav1.ConditionTrue {
		reason = v1alpha1.ReasonEnforcementAvailable
		if observe {
			reason = v1alpha1.ReasonObservationAvailable
		}
	}
	l.recordCondition(rpUID, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.NewTime(l.clock()),
	})
}

// diagnoseAttachErr names BPF-LSM absence as the cause of an attach failure
// when it is: that is the one cause an operator can act on (boot the node
// with lsm=bpf), as opposed to a raw kernel errno from link.AttachLSM. A
// BpfLSMEnabled error means the check itself was inconclusive, so the
// original error is left as is rather than asserted to be something else.
func (l *OpenExecManager) diagnoseAttachErr(err error) error {
	if enabled, lsmErr := utils.BpfLSMEnabled(); lsmErr == nil && !enabled {
		return fmt.Errorf("BPF-LSM is not active on this node: %w", err)
	}
	return err
}

// recordPathRulesCondition reports, once per policy event, whether every path
// value of one behavior can be programmed. It parses the policy's own values
// with the parser the enforcer uses, so the answer holds in observe mode too,
// where nothing reaches a kernel map at all.
func (l *OpenExecManager) recordPathRulesCondition(rpUID, condType string, pair *compiler.AllowDenyPair) {
	if !pair.HasEntries() {
		l.recordCondition(rpUID, metav1.Condition{
			Type:               condType,
			Status:             metav1.ConditionTrue,
			Reason:             v1alpha1.ReasonNoPaths,
			Message:            "the policy declares no paths for this behavior",
			LastTransitionTime: metav1.NewTime(l.clock()),
		})
		return
	}

	_, _, rejected := compiler.ParsePathList(pair.Deny)
	_, _, allowRejected := compiler.ParsePathList(pair.Allow)
	rejected = append(rejected, allowRejected...)
	if len(rejected) == 0 {
		l.recordCondition(rpUID, metav1.Condition{
			Type:               condType,
			Status:             metav1.ConditionTrue,
			Reason:             v1alpha1.ReasonAllPathsSupported,
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
		Reason:             v1alpha1.ReasonUnsupportedPaths,
		Message:            rejectionMessage(rejected),
		LastTransitionTime: metav1.NewTime(l.clock()),
	})
}

// logRejected reports what one enforcer refused to key. recordPathRulesCondition
// already carries the same values onto the policy status, so this stays at V(2)
// and only adds the program type.
func (l *OpenExecManager) logRejected(rpUID, progType string, rejected []compiler.RejectedTarget) {
	for _, r := range rejected {
		l.logger.V(2).Info("path was not programmed", "uid", rpUID, "progType", progType,
			"path", r.Value, "reason", r.Reason)
	}
}

func rejectionMessage(rejected []compiler.RejectedTarget) string {
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

func (l *OpenExecManager) recordCondition(rpUID string, cond metav1.Condition) {
	if l.status == nil || rpUID == "" {
		return
	}
	l.status.RecordCondition(rpUID, "", cond)
}
