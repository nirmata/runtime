package attribution

import (
	"strings"

	"github.com/nirmata/runtime/pkg/events"

	corev1 "k8s.io/api/core/v1"
)

var _ events.PodEventHandler = (*Index)(nil)

// set by the Deployment controller on the ReplicaSet it creates and on every pod
// of that ReplicaSet.
const podTemplateHashLabel = "pod-template-hash"

// deriveOwner reports the workload that owns pod, reading nothing but the pod
// itself so no extra RBAC is needed. The first owner reference wins, and a
// ReplicaSet owner is rewritten to its Deployment when the pod-template-hash
// label is the trailing segment of the ReplicaSet name, which is how the
// Deployment controller names them. Any other owner is reported verbatim.
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
