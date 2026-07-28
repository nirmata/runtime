package lsmmgr

import (
	"errors"
	"slices"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
)

func TestPodCreated_MatchingAndNonMatchingPolicies(t *testing.T) {
	h := newHarness(t)
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rpDb", compiler.ModeEnforce, selFor(map[string]string{"app": "db"}),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11, 12), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	// both prog types of the matching policy get the pod's cgids and observe them
	for _, pt := range []string{open, exec} {
		f := h.enf("rpWeb", pt)
		assertCgidCalls(t, "rpWeb "+pt+" AddCgids", f.addCgids, [][]uint64{{11, 12}})
		assertCgidCalls(t, "rpWeb "+pt+" EnableObservation", f.enableObs, [][]uint64{{11, 12}})
	}
	// the non matching policy is untouched
	if got := h.enf("rpDb", open).addCgids; len(got) != 0 {
		t.Errorf("rpDb AddCgids = %v, want none", got)
	}

	pr := h.l.pods["podA"]
	if pr == nil {
		t.Fatal("pod not stored")
	}
	if !slices.Equal(pr.cgids, []uint64{11, 12}) {
		t.Errorf("stored cgids = %v, want [11 12]", pr.cgids)
	}
	if got := attachedPolicyUIDs(pr); !slices.Equal(got, []string{"rpWeb"}) {
		t.Errorf("attachedLsms = %v, want [rpWeb]", got)
	}
	assertInvariant(t, h.l)
}

func TestPodCreated_NoPolicies(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	pr := h.l.pods["podA"]
	if pr == nil || len(pr.attachedLsms) != 0 {
		t.Fatalf("pod representation = %+v, want stored with no attachments", pr)
	}
	if h.createdCount() != 0 {
		t.Errorf("created %d enforcers for a pod event, want 0", h.createdCount())
	}
	assertInvariant(t, h.l)
}

func TestPodUpdated_CgidDiff(t *testing.T) {
	tests := []struct {
		name      string
		initial   []uint64
		updated   []uint64
		wantAdd   [][]uint64
		wantDel   [][]uint64
		wantCgids []uint64
		// the stored slice is only rewritten when the cgid set actually changed
		wantStored []uint64
	}{{
		name:       "no change produces no calls",
		initial:    []uint64{11, 12},
		updated:    []uint64{11, 12},
		wantCgids:  []uint64{11, 12},
		wantStored: []uint64{11, 12},
	}, {
		name:       "reordering is not a change",
		initial:    []uint64{11, 12},
		updated:    []uint64{12, 11},
		wantCgids:  []uint64{11, 12},
		wantStored: []uint64{11, 12},
	}, {
		name:      "container added",
		initial:   []uint64{11},
		updated:   []uint64{11, 12},
		wantAdd:   [][]uint64{{12}},
		wantCgids: []uint64{11, 12},
	}, {
		name:      "container removed",
		initial:   []uint64{11, 12},
		updated:   []uint64{11},
		wantDel:   [][]uint64{{12}},
		wantCgids: []uint64{11},
	}, {
		name:      "containers replaced",
		initial:   []uint64{11, 12},
		updated:   []uint64{12, 13},
		wantAdd:   [][]uint64{{13}},
		wantDel:   [][]uint64{{11}},
		wantCgids: []uint64{12, 13},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantStored == nil {
				tt.wantStored = tt.updated
			}
			h := newHarness(t)
			if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(tt.initial...), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			// one attached policy and one that never matched the pod
			if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
				pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			if err := h.l.RuntimePolicyEvent(result("rpDb", compiler.ModeEnforce, selFor(map[string]string{"app": "db"}),
				pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			attached, unattached := h.enf("rpWeb", open), h.enf("rpDb", open)
			h.resetAll()

			if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(tt.updated...), events.EventTypeUpdate); err != nil {
				t.Fatal(err)
			}

			assertCgidCalls(t, "AddCgids", attached.addCgids, tt.wantAdd)
			assertCgidCalls(t, "DeleteCgids", attached.delCgids, tt.wantDel)
			// observation follows the cgid set exactly
			assertCgidCalls(t, "EnableObservation", attached.enableObs, tt.wantAdd)
			assertCgidCalls(t, "DisableObservation", attached.disableObs, tt.wantDel)
			if got := attached.cgidSet(); !slices.Equal(got, tt.wantCgids) {
				t.Errorf("enforcer cgid set = %v, want %v", got, tt.wantCgids)
			}
			if got := attached.observedSet(); !slices.Equal(got, tt.wantCgids) {
				t.Errorf("observed cgids = %v, want %v", got, tt.wantCgids)
			}
			if len(unattached.addCgids) != 0 || len(unattached.delCgids) != 0 {
				t.Errorf("unattached policy saw cgid calls: add=%v del=%v", unattached.addCgids, unattached.delCgids)
			}
			if got := h.l.pods["podA"].cgids; !slices.Equal(got, tt.wantStored) {
				t.Errorf("stored cgids = %v, want %v", got, tt.wantStored)
			}
			assertInvariant(t, h.l)
		})
	}
}

func TestPodUpdated_UnknownPodErrors(t *testing.T) {
	h := newHarness(t)
	err := h.l.PodEvent(testPod("ghost", nil), cgs(1), events.EventTypeUpdate)
	if err == nil {
		t.Fatal("expected an error for an update of an unknown pod")
	}
	if len(h.l.pods) != 0 {
		t.Errorf("unknown pod was stored: %v", h.l.pods)
	}
}

// TestPodUpdated_LabelChangeReEvaluatesSelectors_Issue58 replaces PR #57's
// TestPodUpdated_LabelChangeAloneIsNotReEvaluated, which pinned the buggy
// behavior: labels were snapshotted at pod creation, so enforcement outlived its
// selector and a newly matching pod was never picked up. Both directions are
// asserted here, plus the refreshed cache.
func TestPodUpdated_LabelChangeReEvaluatesSelectors_Issue58(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "db"}), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	// rpWeb does not select the pod yet, rpDb does
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rpDb", compiler.ModeEnforce, selFor(map[string]string{"app": "db"}),
		pair(nil, []string{"/etc/passwd"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if got := attachedPodUIDs(h.l.lsmAttachments["rpDb"]); !slices.Equal(got, []string{"podA"}) {
		t.Fatalf("rpDb attached pods = %v, want [podA]", got)
	}
	h.resetAll()

	// relabel in place: app=db -> app=web, cgids unchanged
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11), events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}

	// the cached labels are refreshed
	if got := h.l.pods["podA"].labels["app"]; got != "web" {
		t.Errorf("stored label app = %q, want the refreshed %q", got, "web")
	}
	// the policy that now selects the pod attaches it, on every prog type
	for _, pt := range []string{open, exec} {
		f := h.enf("rpWeb", pt)
		assertCgidCalls(t, "rpWeb "+pt+" AddCgids", f.addCgids, [][]uint64{{11}})
		assertCgidCalls(t, "rpWeb "+pt+" EnableObservation", f.enableObs, [][]uint64{{11}})
		if got := f.cgidSet(); !slices.Equal(got, []uint64{11}) {
			t.Errorf("rpWeb %s cgid set = %v, want [11]", pt, got)
		}
	}
	if got := attachedPodUIDs(h.l.lsmAttachments["rpWeb"]); !slices.Equal(got, []string{"podA"}) {
		t.Errorf("rpWeb attached pods = %v, want [podA]", got)
	}
	// and the policy that no longer selects it detaches: enforcement must not
	// outlive its selector
	dbEnf := h.enf("rpDb", open)
	assertCgidCalls(t, "rpDb DeleteCgids", dbEnf.delCgids, [][]uint64{{11}})
	assertCgidCalls(t, "rpDb DisableObservation", dbEnf.disableObs, [][]uint64{{11}})
	if got := dbEnf.cgidSet(); len(got) != 0 {
		t.Errorf("rpDb cgid set = %v, want empty", got)
	}
	if got := attachedPodUIDs(h.l.lsmAttachments["rpDb"]); len(got) != 0 {
		t.Errorf("rpDb attached pods = %v, want none", got)
	}
	if got := attachedPolicyUIDs(h.l.pods["podA"]); !slices.Equal(got, []string{"rpWeb"}) {
		t.Errorf("podA attachedLsms = %v, want [rpWeb]", got)
	}
	assertInvariant(t, h.l)
}

// a label change that does not move any selector must not churn the enforcers.
func TestPodUpdated_IrrelevantLabelChangeIsQuiet(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	h.resetAll()

	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web", "pod-template-hash": "abc"}), cgs(11), events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	f := h.enf("rpWeb", open)
	if len(f.addCgids) != 0 || len(f.delCgids) != 0 || len(f.enableObs) != 0 || len(f.disableObs) != 0 {
		t.Errorf("irrelevant label change churned the enforcer: add=%v del=%v enable=%v disable=%v",
			f.addCgids, f.delCgids, f.enableObs, f.disableObs)
	}
	if got := h.l.pods["podA"].labels["pod-template-hash"]; got != "abc" {
		t.Errorf("new label not cached: %q", got)
	}
	assertInvariant(t, h.l)
}

// a relabel and a container restart arriving in the same update: the newly
// attached policy must be seeded with the NEW cgid set, not the old one.
func TestPodUpdated_LabelAndCgidChangeTogether(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "db"}), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rpDb", compiler.ModeEnforce, selFor(map[string]string{"app": "db"}),
		pair(nil, []string{"/etc/passwd"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	h.resetAll()

	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(22), events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	if got := h.enf("rpWeb", open).cgidSet(); !slices.Equal(got, []uint64{22}) {
		t.Errorf("rpWeb cgid set = %v, want [22] (the new cgid)", got)
	}
	if got := h.enf("rpDb", open).cgidSet(); len(got) != 0 {
		t.Errorf("rpDb cgid set = %v, want empty (both the old and the new cgid must be gone)", got)
	}
	assertInvariant(t, h.l)
}

func TestPodDeleted(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11, 12), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.PodEvent(testPod("podB", map[string]string{"app": "web"}), cgs(21), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	h.resetAll()

	if err := h.l.PodEvent(testPod("podA", nil), nil, events.EventTypeDelete); err != nil {
		t.Fatal(err)
	}

	for _, pt := range []string{open, exec} {
		f := h.enf("rpWeb", pt)
		assertCgidCalls(t, pt+" DeleteCgids", f.delCgids, [][]uint64{{11, 12}})
		assertCgidCalls(t, pt+" DisableObservation", f.disableObs, [][]uint64{{11, 12}})
		if got := f.cgidSet(); !slices.Equal(got, []uint64{21}) {
			t.Errorf("%s cgid set = %v, want [21] (only the surviving pod)", pt, got)
		}
		if got := f.observedSet(); !slices.Equal(got, []uint64{21}) {
			t.Errorf("%s observed cgids = %v, want [21]", pt, got)
		}
	}
	if _, ok := h.l.pods["podA"]; ok {
		t.Error("deleted pod still present in l.pods")
	}
	if got := attachedPodUIDs(h.l.lsmAttachments["rpWeb"]); !slices.Equal(got, []string{"podB"}) {
		t.Errorf("attached pods = %v, want [podB]", got)
	}
	assertInvariant(t, h.l)

	// deleting an unknown pod must not touch the enforcers
	h.resetAll()
	if err := h.l.PodEvent(testPod("ghost", nil), nil, events.EventTypeDelete); err != nil {
		t.Fatal(err)
	}
	if got := h.enf("rpWeb", open).delCgids; len(got) != 0 {
		t.Errorf("deleting an unknown pod produced DeleteCgids %v", got)
	}
	assertInvariant(t, h.l)
}

// cgid map failures are per pod and must not abort the manager's bookkeeping:
// pod events keep succeeding and the attachment maps stay consistent.
func TestPodEvents_CgidFailuresAreNonFatal(t *testing.T) {
	h := newHarness(t)
	h.failMethod(open, "AddCgids", errors.New("cgid map full"))
	h.failMethod(open, "DeleteCgids", errors.New("cgid missing"))
	h.failMethod(open, "EnableObservation", errors.New("no inner map"))
	h.failMethod(open, "DisableObservation", errors.New("no inner map"))
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatalf("podCreated returned %v, want nil", err)
	}
	if got := attachedPodUIDs(h.l.lsmAttachments["rpWeb"]); !slices.Equal(got, []string{"podA"}) {
		t.Errorf("attached pods = %v, want [podA] despite the AddCgids failure", got)
	}
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(12), events.EventTypeUpdate); err != nil {
		t.Fatalf("podUpdated returned %v, want nil", err)
	}
	if err := h.l.PodEvent(testPod("podA", nil), nil, events.EventTypeDelete); err != nil {
		t.Fatalf("podDeleted returned %v, want nil", err)
	}
	if _, ok := h.l.pods["podA"]; ok {
		t.Error("pod not removed after a DeleteCgids failure")
	}
	assertInvariant(t, h.l)
}

// the same for the policy driven cgid calls in rpCreated and syncPodAttachment.
func TestPolicyEvents_CgidFailuresAreNonFatal(t *testing.T) {
	h := newHarness(t)
	h.failMethod(open, "AddCgids", errors.New("cgid map full"))
	h.failMethod(open, "DeleteCgids", errors.New("cgid missing"))
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	files := pair(nil, []string{"/etc/shadow"})
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}), files, nil), events.EventTypeCreate); err != nil {
		t.Fatalf("rpCreated returned %v, want nil", err)
	}
	if got := attachedPodUIDs(h.l.lsmAttachments["rpWeb"]); !slices.Equal(got, []string{"podA"}) {
		t.Errorf("attached pods = %v, want [podA]", got)
	}
	// selector moves away: the detach must still happen even though DeleteCgids failed
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "db"}), files, nil), events.EventTypeUpdate); err != nil {
		t.Fatalf("rpUpdated returned %v, want nil", err)
	}
	if got := attachedPodUIDs(h.l.lsmAttachments["rpWeb"]); len(got) != 0 {
		t.Errorf("attached pods = %v, want none", got)
	}
	assertInvariant(t, h.l)
}

func TestPodEvent_UnknownEventTypeIsIgnored(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", nil), cgs(11), "bogus"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(h.l.pods) != 0 {
		t.Errorf("unknown event type stored a pod: %v", h.l.pods)
	}
}

func TestPodDeleted_ThenRecreatedGetsFreshRepresentation(t *testing.T) {
	h := newHarness(t)
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	first := h.l.pods["podA"]
	if err := h.l.PodEvent(testPod("podA", nil), nil, events.EventTypeDelete); err != nil {
		t.Fatal(err)
	}
	// recreated with a different cgid, as happens when a pod is rescheduled
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(99), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	second := h.l.pods["podA"]
	if first == second {
		t.Fatal("recreated pod reused the deleted podRepresentation")
	}
	f := h.enf("rpWeb", open)
	if got := f.cgidSet(); !slices.Equal(got, []uint64{99}) {
		t.Errorf("cgid set = %v, want [99]", got)
	}
	assertInvariant(t, h.l)
}

// guards against ExtractCgids being fed a nil slice, which the pod watcher does for
// pods with no running containers.
func TestPodCreated_NoContainers(t *testing.T) {
	h := newHarness(t)
	if err := h.l.RuntimePolicyEvent(result("rpWeb", compiler.ModeEnforce, selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), []*containers.ContainerCgroupInfo{}, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if got := h.l.pods["podA"].cgids; len(got) != 0 {
		t.Errorf("cgids = %v, want empty", got)
	}
	// the pod is still attached so later cgid updates reach the enforcer
	if got := attachedPodUIDs(h.l.lsmAttachments["rpWeb"]); !slices.Equal(got, []string{"podA"}) {
		t.Errorf("attached pods = %v, want [podA]", got)
	}
	h.resetAll()
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(7), events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	if got := h.enf("rpWeb", open).cgidSet(); !slices.Equal(got, []uint64{7}) {
		t.Errorf("cgid set = %v, want [7]", got)
	}
	assertInvariant(t, h.l)
}
