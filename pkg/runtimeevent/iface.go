package runtimeevent

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Source produces events.
type Source interface {
	Name() string
	// Run blocks until ctx is done. Sends events on out. Must not close out.
	Run(ctx context.Context, out chan<- Event) error
}

// Sink consumes events after the collector's stages have run. HandleEvent must
// be fast, non-blocking, and must never panic outward.
type Sink interface {
	Name() string
	HandleEvent(ev Event)
}

// PolicyStatusRecorder is implemented by controller.StatusWriter and consumed
// by the managers. policyName is what addresses the object, so a caller that
// knows it makes the condition flushable even for a policy the recorder has
// never seen an event for; an empty name leaves the recorder to find it.
type PolicyStatusRecorder interface {
	RecordCondition(policyUID, policyName string, cond metav1.Condition)
}
