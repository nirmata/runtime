package events

import (
	"time"

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

type LearningIface interface {
	// start learning the behaviors for pods that match `labels` for `dur` and the UID
	// of the workload profile is `uid`
	Start(uid string, labels map[string]string, dur time.Duration)
	// stop any on going learning for workload profile with `uid`
	Stop(uid string)
}
