package lsmmgr

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

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
			if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11, 12), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			if err := h.l.RuntimePolicyEvent(result("rp1", mode, selFor(map[string]string{"app": "web"}),
				pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			h.enf("rp1", open).seed(11, map[string]uint32{"/etc/shadow": 3})
			h.enf("rp1", exec).seed(12, map[string]uint32{"/bin/sh": 1})

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

// One path counted under both verdicts yields two events — the kernel counter
// key carries the verdict, so a Count is always homogeneous with respect to
// KernelDenied — and the deny event sorts after the allow one for the same
// path, deterministically.
func TestCollectObservations_SplitsEventsByKernelVerdict(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	enf := h.enf("rp1", open)
	enf.seedVerdict(11, lsm.PathEventKey{Path: "/etc/shadow", Verdict: runtimeevent.VerdictDeny}, 2)
	enf.seedVerdict(11, lsm.PathEventKey{Path: "/etc/shadow", Verdict: runtimeevent.VerdictAllow}, 5)

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

// TestCollectObservationsReadsAllEnforcers pins the read-loop structure: an
// early `break` in the read loop meant that for a pod with both an open and an exec
// enforcer, everything after the first enforcer was silently dropped. This test
// fails if anyone reintroduces a break (or any early return) that stops after the
// first enforcer of an attachment, or after the first attachment.
func TestCollectObservationsReadsAllEnforcers(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11, 12), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.PodEvent(testPod("podB", map[string]string{"app": "web"}), cgs(21), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	// two policies, each with BOTH prog types, both attached to both pods: four
	// enforcers in total, every one of which holds counts
	for _, uid := range []string{"rp1", "rp2"} {
		if err := h.l.RuntimePolicyEvent(result(uid, compiler.ModeMonitor, selFor(map[string]string{"app": "web"}),
			pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
	}
	type key struct {
		rp, progType string
	}
	seeded := map[key]struct {
		cgid  uint64
		path  string
		count uint32
	}{
		{"rp1", open}: {11, "/etc/shadow", 2},
		{"rp1", exec}: {12, "/bin/sh", 4},
		{"rp2", open}: {21, "/etc/passwd", 6},
		{"rp2", exec}: {21, "/usr/bin/curl", 8},
	}
	for k, v := range seeded {
		h.enf(k.rp, k.progType).seed(v.cgid, map[string]uint32{v.path: v.count})
	}

	got, err := h.l.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations returned %v", err)
	}

	// every seeded enforcer's counts must be present
	if len(got) != len(seeded) {
		t.Fatalf("got %d events, want %d (one per enforcer): %+v", len(got), len(seeded), got)
	}
	for k, v := range seeded {
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
			t.Errorf("no event for %s/%s (%s on cgid %d): the enforcer was never read", k.rp, k.progType, v.path, v.cgid)
		}
	}

	// and every enforcer of every attachment was asked, exactly once, for the full
	// cgid set of the pods attached to its policy
	for k := range seeded {
		f := h.enf(k.rp, k.progType)
		assertCgidCalls(t, k.rp+" "+k.progType+" ReadEvents", f.readCalls, [][]uint64{{11, 12, 21}})
	}
	assertInvariant(t, h.l)
}

// the kernel maps are read-and-reset, so counts are deltas: nothing is re-emitted
// on the next poll.
func TestCollectObservations_CountsAreDeltas(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", nil), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	f := h.enf("rp1", open)
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

	t.Run("attachment with no attached pods is not read", func(t *testing.T) {
		h := newHarness(t)
		if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, selFor(map[string]string{"app": "web"}),
			pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		got, err := h.l.CollectObservations(context.Background())
		if err != nil || len(got) != 0 {
			t.Fatalf("got (%v, %v), want (empty, nil)", got, err)
		}
		if calls := h.enf("rp1", open).readCalls; len(calls) != 0 {
			t.Errorf("ReadEvents called %v for a policy with no attached pods", calls)
		}
	})

	t.Run("zero counts and empty paths are dropped", func(t *testing.T) {
		h := newHarness(t)
		if err := h.l.PodEvent(testPod("podA", nil), cgs(11), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
			pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		h.enf("rp1", open).seed(11, map[string]uint32{"/etc/shadow": 0, "": 4})
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
	t.Run("observation unavailable is reported, not returned", func(t *testing.T) {
		h := newHarness(t)
		h.failMethod(open, "ReadEvents", lsm.ErrObservationUnavailable)
		if err := h.l.PodEvent(testPod("podA", nil), cgs(11), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
			pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		if _, err := h.l.CollectObservations(context.Background()); err != nil {
			t.Errorf("CollectObservations returned %v, want nil: an unavailable map is a policy condition, not a poll failure", err)
		}
		if got := h.status.conditionTypes("rp1"); !slices.Contains(got, "ObservationAvailable") {
			t.Errorf("conditions = %v, want an ObservationAvailable condition", got)
		}
	})

	t.Run("other read errors are joined and partial counts are kept", func(t *testing.T) {
		h := newHarness(t)
		boom := errors.New("map iteration failed")
		h.failMethod(exec, "ReadEvents", boom)
		if err := h.l.PodEvent(testPod("podA", nil), cgs(11), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
			pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
		h.enf("rp1", open).seed(11, map[string]uint32{"/etc/shadow": 1})
		h.enf("rp1", exec).seed(11, map[string]uint32{"/bin/sh": 2})

		got, err := h.l.CollectObservations(context.Background())
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		// the failing enforcer must not cost us the other one's counts, nor the
		// counts it did manage to read
		if len(got) != 2 {
			t.Errorf("events = %+v, want both the open and the exec observation", got)
		}
	})
}

func TestCollectObservations_CancelledContext(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", nil), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rp1", compiler.ModeMonitor, labels.Everything(),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	h.enf("rp1", open).seed(11, map[string]uint32{"/etc/shadow": 1})

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
