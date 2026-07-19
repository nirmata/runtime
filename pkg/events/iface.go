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

type EventIface interface {
	PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error
	RuntimePolicyEvent(rp *compiler.EvaluationResult, rpEventType string) error
}
