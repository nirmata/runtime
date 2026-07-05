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
	// i will give you a label, if you have pods that match it start learning their behavior
	// labels are the group of labels on a single workload profile that should ALL exist on a single
	// pod for it to count as a workload profile target. duration is how long you should learn for.
	// when it ends nothing happens other than recording stops. but its still the caller's responsibility
	// to read. but hold on a second, if the whole pod attachment and the filter goes away whe pod is gone.
	// what do we do with the ips ?

	// the uid also must be provided so i can track durations. you tell me that the duration dur is tied to
	// id uid. so later if you give me an update for a different timing interval i can stop the old one
	Start(uid string, labels map[string]string, dur time.Duration)
	Stop(uid string)
	Read(uid string)
}
