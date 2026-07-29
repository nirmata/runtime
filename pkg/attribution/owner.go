package attribution

import (
	"strings"

	"github.com/nirmata/kyverno-runtime/pkg/events"

	corev1 "k8s.io/api/core/v1"
)

var _ events.PodEventHandler = (*Index)(nil)

// podTemplateHashLabel is set by the Deployment controller on the ReplicaSet it
// creates and on every pod of that ReplicaSet.
const podTemplateHashLabel = "pod-template-hash"

// deriveOwner reports the workload that owns pod without reading any object
// besides the pod itself (no ReplicaSet GET, hence no extra RBAC).
//
// The first owner reference wins. A ReplicaSet owner is rewritten to its
// Deployment when the pod carries a pod-template-hash label that is the
// trailing segment of the ReplicaSet name -- which is exactly how the
// Deployment controller names ReplicaSets. Anything else (StatefulSet,
// DaemonSet, Job, a hand-made ReplicaSet without the label) is reported
// verbatim, and a bare pod has no owner at all.
func deriveOwner(pod *corev1.Pod) (kind string, name string) {
	if pod == nil || len(pod.OwnerReferences) == 0 {
		return "", ""
	}
	owner := pod.OwnerReferences[0]
	kind, name = owner.Kind, owner.Name
	if kind != "ReplicaSet" {
		return kind, name
	}
	hash := pod.Labels[podTemplateHashLabel]
	if hash == "" {
		return kind, name
	}
	if trimmed, ok := strings.CutSuffix(name, "-"+hash); ok && trimmed != "" {
		return "Deployment", trimmed
	}
	return kind, name
}
