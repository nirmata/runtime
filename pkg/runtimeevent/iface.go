package runtimeevent

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SourceState is the lifecycle state of an event source.
type SourceState string

const (
	SourceStateStarting    SourceState = "Starting"
	SourceStateAvailable   SourceState = "Available"
	SourceStateUnavailable SourceState = "Unavailable"
)

const (
	SourceReasonInitializationFailed  = "InitializationFailed"
	SourceReasonReaderFailed          = "ReaderFailed"
	SourceReasonUnexpectedExit        = "UnexpectedExit"
	SourceReasonDependencyUnavailable = "DependencyUnavailable"
	SourceReasonStarting              = "Starting"
	SourceReasonReady                 = "Ready"
)

// SourceStatusFunc observes source lifecycle changes. Reasons are stable
// diagnostic categories and must not include raw error text.
type SourceStatusFunc func(source string, state SourceState, reason string)

type sourceReadyContextKey struct{}

// WithSourceReady installs the callback a source calls once it can produce
// events. A nil callback leaves ctx unchanged.
func WithSourceReady(ctx context.Context, ready func()) context.Context {
	if ready == nil {
		return ctx
	}
	return context.WithValue(ctx, sourceReadyContextKey{}, ready)
}

// SourceReady reports that a source initialized from ctx is ready to produce
// events. Contexts without a readiness callback are valid.
func SourceReady(ctx context.Context) {
	if ready, ok := ctx.Value(sourceReadyContextKey{}).(func()); ok {
		ready()
	}
}

// Source produces events.
type Source interface {
	Name() string
	// Run calls SourceReady after initialization, then sends events until ctx
	// is done. It must not close out.
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
