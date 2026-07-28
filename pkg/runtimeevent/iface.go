package runtimeevent

import (
	"context"
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ErrSourceNotWired is returned by sources whose kernel-side bindings are not
// available on this build/platform. Collectors log it once at V(0) and do not
// restart the source.
var ErrSourceNotWired = errors.New("runtimeevent: source not wired: BPF bindings not generated on this platform")

// Source produces events.
type Source interface {
	Name() string
	// Run blocks until ctx is done. Sends events on out. Must not close out.
	Run(ctx context.Context, out chan<- Event) error
}

// Sink consumes events after the collector's stages have run.
type Sink interface {
	Name() string
	HandleEvent(ev Event) // must be fast + non-blocking; never panics outward
}

// PolicyStatusRecorder is implemented by controller.StatusWriter (PR A)
// and consumed by pkg/monitor, pkg/egressmgr, pkg/detect (PR B).
type PolicyStatusRecorder interface {
	RecordViolation(policyUID string, podUID string)
	RecordCondition(policyUID string, cond metav1.Condition)
}
