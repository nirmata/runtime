package reportevents

import (
	"fmt"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/reporter"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
)

// Reasons this package emits.
const (
	ReasonPolicyViolation    = "PolicyViolation"
	ReasonPolicyWouldViolate = "PolicyWouldViolate"
	ReasonPolicyError        = "PolicyError"
)

// Actions this package emits, naming what the daemon did with regarding.
const (
	actionEnforce = "Enforce"
	actionMonitor = "Monitor"
	actionApply   = "Apply"
)

// Recorder turns reporter findings and RuntimePolicy status transitions into
// Kubernetes Events. It rides the same volume controls as everything else in
// the event plane: reporter.FlushSink already deduplicates per fingerprint per
// flush, and events.EventRecorder spam-filters repeats of an identical event
// on the same object.
type Recorder struct {
	rec events.EventRecorder
	log logr.Logger
}

// New builds a Recorder that emits through rec.
func New(rec events.EventRecorder, log logr.Logger) *Recorder {
	return &Recorder{rec: rec, log: log}
}

// FindingFlushed satisfies reporter.Options.FlushSink. f arrives raw from the
// reporter's dedup buffer; every field reaching the Event note passes through
// reporter.Redact/reporter.Sanitize first.
func (r *Recorder) FindingFlushed(f reporter.Finding, count int) {
	f = reporter.Redact(f)

	regarding := &corev1.ObjectReference{
		APIVersion: "v1",
		Kind:       "Pod",
		Namespace:  f.Pod.Namespace,
		Name:       f.Pod.Name,
		UID:        types.UID(f.Pod.UID),
	}
	related := &corev1.ObjectReference{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "RuntimePolicy",
		Name:       f.PolicyName,
		UID:        types.UID(f.PolicyUID),
	}

	eventtype, reason, action := corev1.EventTypeNormal, ReasonPolicyWouldViolate, actionMonitor
	if f.Enforced {
		eventtype, reason, action = corev1.EventTypeWarning, ReasonPolicyViolation, actionEnforce
	}

	note := f.Message
	if count > 1 {
		note = f.Message + fmt.Sprintf(" (%d occurrences this interval)", count)
	}

	r.rec.Eventf(regarding, related, eventtype, reason, action, "%s", note)
}

// ConditionChanged satisfies the StatusWriter's onConditionChanged callback.
// It emits only for a False transition of Applied or TargetsValid, and only
// once the policy's name is known: a RuntimePolicy is cluster-scoped, so
// nothing else can address it as regarding.
func (r *Recorder) ConditionChanged(policyUID, policyName string, cond metav1.Condition) {
	if cond.Status != metav1.ConditionFalse {
		return
	}
	if cond.Type != v1alpha1.ConditionApplied && cond.Type != v1alpha1.ConditionTargetsValid {
		return
	}
	if policyName == "" {
		r.log.V(2).Info("skipping policy error event: policy name not yet known",
			"policyUid", policyUID, "condition", cond.Type)
		return
	}

	regarding := &corev1.ObjectReference{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "RuntimePolicy",
		Name:       policyName,
		UID:        types.UID(policyUID),
	}
	note := reporter.Sanitize(cond.Reason) + ": " + reporter.Sanitize(cond.Message)

	r.rec.Eventf(regarding, nil, corev1.EventTypeWarning, ReasonPolicyError, actionApply, "%s", note)
}
