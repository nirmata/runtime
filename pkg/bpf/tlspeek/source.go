package tlspeek

import (
	"context"
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
)

// SourceName is the collector-visible name of this source.
const SourceName = "tlspeek"

// The kernel object for _cprog/tlspeek.bpf.c is NOT generated: this repository
// is developed on a host without clang, bpf2go, or vmlinux.h, and committing an
// object built somewhere else would be a binary blob nobody could reproduce.
// The directive below is therefore intentionally commented out; uncomment it in
// the follow-up that adds a linux toolchain lane.
//
// TODO(#63): generate on a linux toolchain and wire the reader --
// tracked by the "bpf2go generation + wiring of the five new BPF sources"
// follow-up issue filed with PR B (task B11). That change must also add a
// verifier-load smoke test, because none of the C in _cprog has ever been
// compiled or verified.
//
// //go:generate go tool bpf2go tlsPeek ./_cprog/tlspeek.bpf.c -- -I ./_cprog

// Source is the tlspeek event source. It exists so daemon wiring, the
// collector's source list, and the not-wired logging path can all be written
// and tested today, ahead of the generated bindings.
type Source struct {
	log logr.Logger
}

// NewSource returns the tlspeek source together with
// runtimeevent.ErrSourceNotWired.
//
// Both return values are non-nil on purpose. The error lets a caller that
// checks it log the gap at V(0) and skip the source; the value lets a caller
// that adds the source to a collector anyway get the same sentinel from Run,
// which the collector logs once at V(0) and does not restart. Whichever wiring
// style the daemon uses, the gap is reported exactly once and nothing silently
// pretends to observe TLS.
func NewSource(log logr.Logger) (runtimeevent.Source, error) {
	return &Source{log: log}, fmt.Errorf("%s: %w", SourceName, runtimeevent.ErrSourceNotWired)
}

// Name implements runtimeevent.Source.
func (s *Source) Name() string { return SourceName }

// Run implements runtimeevent.Source. It never emits an event and never blocks:
// it reports that the kernel side is not wired and returns immediately.
func (s *Source) Run(_ context.Context, _ chan<- runtimeevent.Event) error {
	s.log.V(2).Info("tlspeek source has no kernel bindings on this build", "source", SourceName)
	return fmt.Errorf("%s: %w", SourceName, runtimeevent.ErrSourceNotWired)
}

// Compile-time proof that the constructor's contract is satisfiable.
var _ runtimeevent.Source = (*Source)(nil)
