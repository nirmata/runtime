package openexecmgr

import (
	"context"
	"errors"
	"testing"

	"github.com/nirmata/runtime/pkg/bpf/openexec"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/labels"
)

// CollectObservations turns the per-cgroup path counters into events for both
// modes: monitor gets its findings from them and enforce gets deny
// delivery data from them.
func TestCollectObservations_EmitsOpenAndExecEvents(t *testing.T) {
	for _, mode := range []string{compiler.ModeEnforce, compiler.ModeMonitor} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), nil, cgs(11, 12), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			if err := h.l.RuntimePolicyEvent(result("rp1", mode, selFor(map[string]string{"app": "web"}),
				pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			h.prog(open).seed(11, map[string]uint32{"/etc/shadow": 3})
			h.prog(exec).seed(12, map[string]uint32{"/bin/sh": 1})

			got, err := h.l.CollectObservations(context.Background())
			if err != nil {
				t.Fatalf("CollectObservations returned %v", err)
			}
			want := []runtimeevent.Event{{
				Kind:     runtimeevent.KindOpen,
				Time:     fixedTime,
				CgroupID: 11,
				Count:    3,
				Open:     &runtimeevent.OpenFacts{Path: "/etc/shadow"},
				Pod:      runtimeevent.PodIdentity{UID: "podA"},
			}, {
				Kind:     runtimeevent.KindExec,
				Time:     fixedTime,
				CgroupID: 12,
				Count:    1,
				Exec:     &runtimeevent.ExecFacts{Filename: "/bin/sh"},
				Pod:      runtimeevent.PodIdentity{UID: "podA"},
			}}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("events (-want +got):\n%s", diff)
			}
			assertInvariant(t, h.l)
		})
	}
}

// one path counted under both decisions yields two events, the deny one sorted
// after the allow one. the counter key carries the decision, so a Count never
// mixes the two.
func TestCollectObservations_SplitsEventsByKernelDecision(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), nil, cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	h.prog(open).seedDecision(11, obsKey("/etc/shadow", runtimeevent.DecisionDeny), 2)
	h.prog(open).seedDecision(11, obsKey("/etc/shadow", runtimeevent.DecisionAllow), 5)

	got, err := h.l.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations returned %v", err)
	}
	want := []runtimeevent.Event{{
		Kind:     runtimeevent.KindOpen,
		Time:     fixedTime,
		CgroupID: 11,
		Count:    5,
		Open:     &runtimeevent.OpenFacts{Path: "/etc/shadow"},
		Pod:      runtimeevent.PodIdentity{UID: "podA"},
	}, {
		Kind:         runtimeevent.KindOpen,
		Time:         fixedTime,
		CgroupID:     11,
		Count:        2,
		KernelDenied: true,
		Open:         &runtimeevent.OpenFacts{Path: "/etc/shadow"},
		Pod:          runtimeevent.PodIdentity{UID: "podA"},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
}

// the read loop drains every program: a break or early return after the first
// one drops what the other counted.
func TestCollectObservationsReadsAllPrograms(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), nil, cgs(11, 12), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.PodEvent(testPod("podB", map[string]string{"app": "web"}), nil, cgs(21), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	seeded := map[string]struct {
		cgid  uint64
		path  string
		count uint32
	}{
		open: {11, "/etc/shadow", 2},
		exec: {21, "/bin/sh", 4},
	}
	for progType, v := range seeded {
		h.prog(progType).seed(v.cgid, map[string]uint32{v.path: v.count})
	}

	got, err := h.l.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations returned %v", err)
	}

	// every seeded program's counts must be present
	if len(got) != len(seeded) {
		t.Fatalf("got %d events, want %d (one per program): %+v", len(got), len(seeded), got)
	}
	for progType, v := range seeded {
		found := false
		for _, ev := range got {
			if ev.CgroupID != v.cgid || ev.Count != v.count {
				continue
			}
			if eventPath(ev) == v.path {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no event for %s (%s on cgid %d): the program was never read", progType, v.path, v.cgid)
		}
	}

	// and every program was drained exactly once
	for progType := range seeded {
		if calls := h.prog(progType).readCalls; calls != 1 {
			t.Errorf("%s ReadEvents called %d times, want 1", progType, calls)
		}
	}
	assertInvariant(t, h.l)
}

// the kernel maps are read-and-reset, so counts are deltas: nothing is re-emitted
// on the next poll.
func TestCollectObservations_CountsAreDeltas(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", nil), nil, cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	f := h.prog(open)
	f.seed(11, map[string]uint32{"/etc/shadow": 3})

	first, err := h.l.CollectObservations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Count != 3 {
		t.Fatalf("first poll = %+v, want a single event with count 3", first)
	}

	second, err := h.l.CollectObservations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Errorf("second poll = %+v, want no events (counts were already drained)", second)
	}

	f.seed(11, map[string]uint32{"/etc/shadow": 5})
	third, err := h.l.CollectObservations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 1 || third[0].Count != 5 {
		t.Fatalf("third poll = %+v, want a single event with count 5", third)
	}
}

func TestCollectObservations_NothingToRead(t *testing.T) {
	t.Run("no attachments", func(t *testing.T) {
		h := newHarness(t)
		got, err := h.l.CollectObservations(context.Background())
		if err != nil || len(got) != 0 {
			t.Fatalf("got (%v, %v), want (empty, nil)", got, err)
		}
	})

	t.Run("attachment with no observed cgids yields no events", func(t *testing.T) {
		h := newHarness(t)
		if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, selFor(map[string]string{"app": "web"}),
			pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		got, err := h.l.CollectObservations(context.Background())
		if err != nil || len(got) != 0 {
			t.Fatalf("got (%v, %v), want (empty, nil)", got, err)
		}
	})

	t.Run("zero counts and empty paths are dropped", func(t *testing.T) {
		h := newHarness(t)
		if err := h.l.PodEvent(testPod("podA", nil), nil, cgs(11), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
			pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		h.prog(open).seed(11, map[string]uint32{"/etc/shadow": 0, "": 4})
		got, err := h.l.CollectObservations(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("events = %+v, want none", got)
		}
	})
}

func TestCollectObservations_ReadFailures(t *testing.T) {
	t.Run("observation unavailable is not a poll failure", func(t *testing.T) {
		h := newHarness(t)
		h.failMethod(open, "ReadEvents", openexec.ErrObservationUnavailable)
		if err := h.l.PodEvent(testPod("podA", nil), nil, cgs(11), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
			pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		if _, err := h.l.CollectObservations(context.Background()); err != nil {
			t.Errorf("CollectObservations returned %v, want nil: an unavailable map reports the same thing every poll", err)
		}
	})

	t.Run("other read errors are joined and partial counts are kept", func(t *testing.T) {
		h := newHarness(t)
		boom := errors.New("map iteration failed")
		h.failMethod(exec, "ReadEvents", boom)
		if err := h.l.PodEvent(testPod("podA", nil), nil, cgs(11), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
			pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		h.prog(open).seed(11, map[string]uint32{"/etc/shadow": 1})
		h.prog(exec).seed(11, map[string]uint32{"/bin/sh": 2})

		got, err := h.l.CollectObservations(context.Background())
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		// the failing program must not cost us the other one's counts, nor the
		// counts it did manage to read
		if len(got) != 2 {
			t.Errorf("events = %+v, want both the open and the exec observation", got)
		}
	})
}

func TestCollectObservations_CancelledContext(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", nil), nil, cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	h.prog(open).seed(11, map[string]uint32{"/etc/shadow": 1})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := h.l.CollectObservations(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(got) != 0 {
		t.Errorf("events = %+v, want none for a cancelled context", got)
	}
}

// attachPolicies creates a pod plus one monitor policy per uid, every one of them
// selecting that pod, and returns the harness.
func attachPolicies(t *testing.T, podUID string, cgids []uint64, policyUIDs ...string) *harness {
	t.Helper()
	h := newHarness(t)
	if err := h.l.PodEvent(testPod(podUID, nil), nil, cgs(cgids...), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	for _, uid := range policyUIDs {
		if err := h.l.RuntimePolicyEvent(result(uid, compiler.ModeMonitor, labels.Everything(),
			pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// the kernel counts each operation once, whatever number of policies cover the
// pod, so one counter yields exactly one event.
func TestCollectObservationsEmitsOnePathEventAcrossAttachments(t *testing.T) {
	h := attachPolicies(t, "podA", []uint64{11}, "rp1", "rp2")
	h.prog(open).seed(11, map[string]uint32{"/etc/shadow": 4})

	got, err := h.l.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations returned %v", err)
	}
	want := []runtimeevent.Event{{
		Kind:     runtimeevent.KindOpen,
		Time:     fixedTime,
		CgroupID: 11,
		Count:    4,
		Open:     &runtimeevent.OpenFacts{Path: "/etc/shadow"},
		Pod:      runtimeevent.PodIdentity{UID: "podA"},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
}

// the kernel records the final merged decision per operation, and the counter
// key carries it: an allow and a deny for the same path stay two counters.
func TestCollectObservationsKeepsDistinctDecisionsSeparate(t *testing.T) {
	h := attachPolicies(t, "podA", []uint64{11}, "rp1", "rp2")
	h.prog(open).seedDecision(11, obsKey("/etc/shadow", runtimeevent.DecisionDeny), 2)
	h.prog(open).seedDecision(11, obsKey("/etc/shadow", runtimeevent.DecisionAllow), 2)

	got, err := h.l.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations returned %v", err)
	}
	want := []runtimeevent.Event{{
		Kind:     runtimeevent.KindOpen,
		Time:     fixedTime,
		CgroupID: 11,
		Count:    2,
		Open:     &runtimeevent.OpenFacts{Path: "/etc/shadow"},
		Pod:      runtimeevent.PodIdentity{UID: "podA"},
	}, {
		Kind:         runtimeevent.KindOpen,
		Time:         fixedTime,
		CgroupID:     11,
		Count:        2,
		KernelDenied: true,
		Open:         &runtimeevent.OpenFacts{Path: "/etc/shadow"},
		Pod:          runtimeevent.PodIdentity{UID: "podA"},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
}

// what an operator sees is a property of the pod's traffic, so adding policies that
// select the same pod must not change the emitted events at all.
func TestCollectObservationsEventCountIndependentOfPolicyCount(t *testing.T) {
	collect := func(policyUIDs ...string) []runtimeevent.Event {
		t.Helper()
		h := attachPolicies(t, "podA", []uint64{11}, policyUIDs...)
		h.prog(open).seed(11, map[string]uint32{"/etc/shadow": 7})
		got, err := h.l.CollectObservations(context.Background())
		if err != nil {
			t.Fatalf("CollectObservations returned %v", err)
		}
		return got
	}

	one := collect("rp1")
	many := collect("rp1", "rp2", "rp3", "rp4", "rp5", "rp6", "rp7", "rp8")
	if diff := cmp.Diff(one, many); diff != "" {
		t.Errorf("8 policies vs 1 (-one +many):\n%s", diff)
	}
}

// sortEvents is what makes the emitted slice reproducible despite the map
// iteration in CollectObservations.
func TestSortEvents_Deterministic(t *testing.T) {
	mk := func(cgid uint64, kind runtimeevent.Kind, path string) runtimeevent.Event {
		ev := runtimeevent.Event{Kind: kind, CgroupID: cgid}
		if kind == runtimeevent.KindOpen {
			ev.Open = &runtimeevent.OpenFacts{Path: path}
		} else {
			ev.Exec = &runtimeevent.ExecFacts{Filename: path}
		}
		return ev
	}
	in := []runtimeevent.Event{
		mk(12, runtimeevent.KindOpen, "/b"),
		mk(11, runtimeevent.KindOpen, "/b"),
		mk(11, runtimeevent.KindExec, "/a"),
		mk(11, runtimeevent.KindOpen, "/a"),
	}
	want := []runtimeevent.Event{
		mk(11, runtimeevent.KindExec, "/a"),
		mk(11, runtimeevent.KindOpen, "/a"),
		mk(11, runtimeevent.KindOpen, "/b"),
		mk(12, runtimeevent.KindOpen, "/b"),
	}
	if diff := cmp.Diff(want, sortEvents(in)); diff != "" {
		t.Errorf("sortEvents (-want +got):\n%s", diff)
	}
}

// the kernel's own drop counter is the only signal that a program's
// observations are incomplete; dropping it makes a truncated view look quiet.
func TestCollectObservationsReportsKernelDrops(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", nil), nil, cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	h.prog(open).seedLost(4)

	if _, err := h.l.CollectObservations(context.Background()); err != nil {
		t.Fatalf("CollectObservations: %v", err)
	}
	want := []loss{{reason: runtimeevent.ReasonCountMapFull, delta: 4}}
	if diff := cmp.Diff(want, h.recordedLosses(), cmp.AllowUnexported(loss{})); diff != "" {
		t.Errorf("losses (-want +got):\n%s", diff)
	}
}

// the kernel counter is cumulative and never resets, so a poll that sees no new
// drops must report nothing rather than the running total again.
func TestKernelDropDeltaNotRepeated(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", nil), nil, cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	h.prog(open).seedLost(4)
	if _, err := h.l.CollectObservations(context.Background()); err != nil {
		t.Fatalf("first CollectObservations: %v", err)
	}
	if _, err := h.l.CollectObservations(context.Background()); err != nil {
		t.Fatalf("second CollectObservations: %v", err)
	}
	h.prog(open).seedLost(3)
	if _, err := h.l.CollectObservations(context.Background()); err != nil {
		t.Fatalf("third CollectObservations: %v", err)
	}

	want := []loss{
		{reason: runtimeevent.ReasonCountMapFull, delta: 4},
		{reason: runtimeevent.ReasonCountMapFull, delta: 3},
	}
	if diff := cmp.Diff(want, h.recordedLosses(), cmp.AllowUnexported(loss{})); diff != "" {
		t.Errorf("losses (-want +got):\n%s", diff)
	}
}
