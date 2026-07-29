package events

import (
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"

	corev1 "k8s.io/api/core/v1"
)

const EventTypeCreate = "create"
const EventTypeUpdate = "update"
const EventTypeDelete = "delete"

type Event[T any] struct {
	Type   string
	Obj    T
	OldObj T
}

// PodEventHandler receives the pod stream from the pod watcher. Handlers that
// only care about policies implement RuntimePolicyEventHandler instead.
type PodEventHandler interface {
	// PodEvent delivers create and update. Deletes arrive via PodDeleted.
	PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error
	// PodDeleted announces that the pod with the given UID is gone. Only the
	// UID is delivered: the object itself may no longer exist anywhere, and
	// handing out a synthesized pod would invite reads of fields that are
	// silently empty on the delete path only.
	PodDeleted(uid string) error
}

// RuntimePolicyEventHandler receives the RuntimePolicy stream from the policy
// informer.
type RuntimePolicyEventHandler interface {
	RuntimePolicyEvent(rp *compiler.EvaluationResult, rpEventType string) error
}
