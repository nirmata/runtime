package reportevents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/reporter"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	typedeventsv1 "k8s.io/client-go/kubernetes/typed/events/v1"
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

// reportingController identifies this package's Events to a consumer of the
// Events API, and doubles as the reporting instance: nothing here needs to
// distinguish which daemon pod wrote a given Event.
const reportingController = "kyverno-runtime"

// eventWriteTimeout bounds each Event write so a slow or unreachable API
// server cannot stall the reporter flush or status write that triggered it.
const eventWriteTimeout = 5 * time.Second

// Recorder turns reporter findings and RuntimePolicy status transitions into
// Kubernetes Events.
//
// It writes eventsv1.Event objects directly through the typed client instead
// of through events.EventRecorder. That recorder's correlator keys solely on
// (type, action, reason, reportingController, reportingInstance, regarding,
// related) — it never looks at the note — so two distinct causes that share
// those fields (different targets of the same policy and pod, or a changed
// failure reason under an unchanged condition type) collapse into one Event
// series and silently lose every message but the first. Naming each Event
// deterministically from the finding's fingerprint, or from the policy UID
// and condition type for a policy error, gives every distinct cause its own
// object, while a genuine repeat of the identical cause still coalesces: the
// second write patches the existing object's series and note instead of
// creating a new one.
type Recorder struct {
	client typedeventsv1.EventsV1Interface
	clock  func() time.Time
	log    logr.Logger
}

// New builds a Recorder that writes through client.
func New(client typedeventsv1.EventsV1Interface, log logr.Logger) *Recorder {
	return &Recorder{client: client, clock: time.Now, log: log}
}

// FindingFlushed satisfies reporter.Options.FlushSink. The fingerprint is
// captured before redaction, matching the identity the reporter itself
// dedupes findings by; f then passes through reporter.Redact/Sanitize before
// any of it reaches the Event note.
func (r *Recorder) FindingFlushed(f reporter.Finding, count int) {
	fingerprint := f.Fingerprint()
	f = reporter.Redact(f)

	regarding := corev1.ObjectReference{
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
		note = fmt.Sprintf("%s (%d occurrences this interval)", f.Message, count)
	}

	r.emit(objectName("finding", fingerprint), f.Pod.Namespace, eventtype, reason, action, regarding, related, note, int32(count))
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

	regarding := corev1.ObjectReference{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "RuntimePolicy",
		Name:       policyName,
		UID:        types.UID(policyUID),
	}
	note := reporter.Sanitize(cond.Reason) + ": " + reporter.Sanitize(cond.Message)

	r.emit(objectName("policyerror", policyUID+":"+cond.Type), corev1.NamespaceDefault,
		corev1.EventTypeWarning, ReasonPolicyError, actionApply, regarding, nil, note, 1)
}

// emit creates the named Event, or, if an occurrence of the same cause
// already exists, patches its series and note in place. name is deterministic
// per distinguishable cause, so a genuinely repeated cause updates one object
// instead of creating a new one on every flush.
func (r *Recorder) emit(name, namespace, eventtype, reason, action string,
	regarding corev1.ObjectReference, related *corev1.ObjectReference, note string, count int32) {
	now := metav1.MicroTime{Time: r.clock()}
	ev := &eventsv1.Event{
		ObjectMeta:          metav1.ObjectMeta{Name: name, Namespace: namespace},
		EventTime:           now,
		Series:              &eventsv1.EventSeries{Count: count, LastObservedTime: now},
		ReportingController: reportingController,
		ReportingInstance:   reportingController,
		Action:              action,
		Reason:              reason,
		Regarding:           regarding,
		Related:             related,
		Note:                note,
		Type:                eventtype,
	}

	ctx, cancel := context.WithTimeout(context.Background(), eventWriteTimeout)
	defer cancel()

	client := r.client.Events(namespace)
	if _, err := client.Create(ctx, ev, metav1.CreateOptions{}); err == nil {
		return
	} else if !apierrors.IsAlreadyExists(err) {
		r.log.Error(err, "failed to record event", "name", name, "namespace", namespace)
		return
	}

	patch, err := json.Marshal(map[string]any{
		"note": note,
		"series": map[string]any{
			"count":            count,
			"lastObservedTime": now,
		},
	})
	if err != nil {
		r.log.Error(err, "failed to build event patch", "name", name, "namespace", namespace)
		return
	}
	if _, err := client.Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		r.log.Error(err, "failed to update recurring event", "name", name, "namespace", namespace)
	}
}

// objectName derives a stable, valid Kubernetes object name from an Event's
// identity: a kind label plus whatever distinguishes one cause from another
// (a finding's fingerprint, or a policy UID and condition type). Hashing
// keeps the name within the API's length and character limits regardless of
// what the caller passes in.
func objectName(kind, identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return "kyverno-runtime-" + kind + "-" + hex.EncodeToString(sum[:16])
}
