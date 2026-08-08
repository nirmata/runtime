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
	//
	// nsLabels is the label set of the pod's namespace, read by the watcher so
	// a policy's namespaceSelector can be matched without every handler
	// holding its own namespace cache.
	PodEvent(pod corev1.Pod, nsLabels map[string]string, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error
	// PodDeleted announces that the pod with the given UID is gone. Only the
	// UID is delivered: the object itself may no longer exist anywhere, and
	// handing out a synthesized pod would invite reads of fields that are
	// silently empty on the delete path only.
	PodDeleted(uid string) error
}

// NamespaceEventHandler receives namespace labels from the pod watcher's
// namespace informer. It exists for handlers that match a policy's
// namespaceSelector but hold no pod state, so they cannot read the labels off a
// pod event.
type NamespaceEventHandler interface {
	// NamespaceEvent delivers create and update; on delete, nsLabels is nil.
	NamespaceEvent(name string, nsLabels map[string]string, evType string)
}

// RuntimePolicyEventHandler receives the RuntimePolicy stream from the policy
// informer.
type RuntimePolicyEventHandler interface {
	RuntimePolicyEvent(rp *compiler.EvaluationResult, rpEventType string) error
}
