package events

import (
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	corev1 "k8s.io/api/core/v1"
)

type EventIface interface {
	PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error
	RuntimeBehaviorEvent(rb *compiler.EvaluationResult, rbEventType string) error
}
