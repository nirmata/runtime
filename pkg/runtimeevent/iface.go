package runtimeevent

import (
	"context"
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ErrSourceNotWired is returned by sources whose kernel-side bindings are not
// available on this build/platform. The collector logs it once and does not
// restart the source.
var ErrSourceNotWired = errors.New("runtimeevent: source not wired: BPF bindings not generated on this platform")

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
// by the managers.
type PolicyStatusRecorder interface {
	RecordCondition(policyUID string, cond metav1.Condition)
}
