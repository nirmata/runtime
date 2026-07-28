package netflow

import (
	"context"
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
)

// The kernel object for _cprog/netflow.bpf.c is not generated in this
// repository: bpf2go needs clang, libbpf headers and a BTF-derived vmlinux.h,
// none of which exist on the development host this package was written on.
// Until the generation runs on a linux toolchain the directive below stays
// commented and NewSource reports runtimeevent.ErrSourceNotWired.
//
// TODO(#63):
// uncomment, run `go generate ./pkg/bpf/...` on linux, and replace notWired
// with a real ringbuf reader that calls DecodeFlowEvent on every record.
//
// //go:generate go tool bpf2go netFlow ./_cprog/netflow.bpf.c -- -I./_cprog

// SourceName is the name this source reports to the collector. It is also the
// label used for per-source drop metrics.
const SourceName = "netflow"

// NewSource returns the egress flow source.
//
// Both return values are non-nil today: the error wraps
// runtimeevent.ErrSourceNotWired so a caller that checks it can skip the source
// outright, and the returned Source is still safe to hand to the collector —
// its Run reports the same sentinel, which the collector logs once at V(0) and
// never restarts. Callers may therefore ignore the error or act on it; both
// behave.
func NewSource(log logr.Logger) (runtimeevent.Source, error) {
	return notWired{log: log}, fmt.Errorf("%s: %w", SourceName, runtimeevent.ErrSourceNotWired)
}

type notWired struct {
	log logr.Logger
}

func (notWired) Name() string { return SourceName }

func (s notWired) Run(context.Context, chan<- runtimeevent.Event) error {
	s.log.V(2).Info("flow source has no kernel bindings on this build", "source", SourceName)
	return fmt.Errorf("%s: %w", SourceName, runtimeevent.ErrSourceNotWired)
}
