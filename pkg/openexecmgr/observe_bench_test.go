package openexecmgr

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"

	"github.com/go-logr/logr"
)

// benchSeed is one program's kernel-side counts for one cgroup. ReadEvents is
// read-and-reset, so the whole set is put back before every timed collect.
type benchSeed struct {
	prog  *fakeProgram
	cgid  uint64
	paths map[string]uint32
}

func reseed(seeds []benchSeed) {
	for _, s := range seeds {
		s.prog.seed(s.cgid, s.paths)
	}
}

func benchManager() (*OpenExecManager, map[string]*fakeProgram) {
	progs := map[string]*fakeProgram{
		open: newFakeProgram(open, nil),
		exec: newFakeProgram(exec, nil),
	}
	programs := make(map[string]monitoringIface, len(progs))
	for target, p := range progs {
		programs[target] = p
	}
	l := newOpenExecManager(logr.Discard(), newFakeStatus(), nil, func(_ *logr.Logger, target string) (openExecMap, error) {
		return newFakeEnforcer(target, nil), nil
	}, programs, true)
	l.clock = func() time.Time { return fixedTime }
	return l, progs
}

func benchPaths(n int) map[string]uint32 {
	out := make(map[string]uint32, n)
	for i := range n {
		out[fmt.Sprintf("/var/lib/app/file-%04d", i)] = uint32(i + 1)
	}
	return out
}

// benchObservationFixture builds monitor-mode policies with both program
// types attached. sharedCgid decides whether they cover one cgroup each or all
// cover the same one, which is the difference between the counters spreading
// over many cgids and collapsing onto one key set.
func benchObservationFixture(b *testing.B, attachments, pathsPerCgid int, sharedCgid bool) (*OpenExecManager, []benchSeed) {
	b.Helper()
	l, progs := benchManager()

	label := func(i int) map[string]string {
		if sharedCgid {
			return map[string]string{"app": "shared"}
		}
		return map[string]string{"app": fmt.Sprintf("w%d", i)}
	}
	cgidFor := func(i int) uint64 {
		if sharedCgid {
			return 1
		}
		return uint64(i + 1)
	}

	if sharedCgid {
		if err := l.PodEvent(testPod("pod-shared", label(0)), nil, cgs(1), events.EventTypeCreate); err != nil {
			b.Fatalf("PodEvent: %v", err)
		}
	} else {
		for i := range attachments {
			if err := l.PodEvent(testPod(fmt.Sprintf("pod-%d", i), label(i)), nil, cgs(cgidFor(i)), events.EventTypeCreate); err != nil {
				b.Fatalf("PodEvent: %v", err)
			}
		}
	}

	paths := benchPaths(pathsPerCgid)
	for i := range attachments {
		uid := fmt.Sprintf("rp%d", i)
		rp := result(uid, compiler.ModeMonitor, selFor(label(i)),
			pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"}))
		if err := l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
			b.Fatalf("RuntimePolicyEvent: %v", err)
		}
	}

	// one counter set per (program, cgid): the kernel counts an operation once,
	// however many policies cover the pod
	seeds := make([]benchSeed, 0, 2*attachments)
	for _, p := range progs {
		if sharedCgid {
			seeds = append(seeds, benchSeed{prog: p, cgid: 1, paths: paths})
			continue
		}
		for i := range attachments {
			seeds = append(seeds, benchSeed{prog: p, cgid: cgidFor(i), paths: paths})
		}
	}
	return l, seeds
}

// runCollectBenchmark drains a seeded fixture once per iteration. Reseeding is
// what keeps every iteration real work: the fake mirrors the kernel's
// read-and-reset, so without it the first collect empties the maps and the rest
// measure an empty drain.
func runCollectBenchmark(b *testing.B, l *OpenExecManager, seeds []benchSeed, wantEvents int) {
	b.Helper()
	ctx := context.Background()

	reseed(seeds)
	first, err := l.CollectObservations(ctx)
	if err != nil {
		b.Fatalf("CollectObservations: %v", err)
	}
	if len(first) != wantEvents {
		b.Fatalf("events = %d, want %d", len(first), wantEvents)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		reseed(seeds)
		b.StartTimer()
		evs, err := l.CollectObservations(ctx)
		if err != nil {
			b.Fatalf("CollectObservations: %v", err)
		}
		if len(evs) != wantEvents {
			b.Fatalf("events = %d, want %d", len(evs), wantEvents)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(wantEvents), "events/op")
}

func BenchmarkCollectObservations(b *testing.B) {
	for _, attachments := range []int{1, 8, 64} {
		for _, paths := range []int{16, 256} {
			b.Run(fmt.Sprintf("attachments=%d/paths=%d", attachments, paths), func(b *testing.B) {
				l, seeds := benchObservationFixture(b, attachments, paths, false)
				runCollectBenchmark(b, l, seeds, attachments*2*paths)
			})
		}
	}
}

// every policy over one cgroup counts the same kernel operations once, so the
// emitted event count must stay flat as attachments are added instead of
// growing one duplicate set per attachment.
func BenchmarkCollectObservationsSharedCgid(b *testing.B) {
	const paths = 256
	for _, attachments := range []int{1, 8, 64} {
		b.Run(fmt.Sprintf("attachments=%d", attachments), func(b *testing.B) {
			l, seeds := benchObservationFixture(b, attachments, paths, true)
			runCollectBenchmark(b, l, seeds, 2*paths)
		})
	}
}
