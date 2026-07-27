package lsmmgr

import (
	"errors"
	"slices"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"k8s.io/apimachinery/pkg/labels"
)

const (
	open = lsm.PROG_TYPE_LSM_OPEN
	exec = lsm.PROG_TYPE_LSM_EXEC
)

func TestRpCreated_ProgTypeSelection(t *testing.T) {
	tests := []struct {
		name          string
		mode          string
		openPair      *compiler.AllowDenyPair
		execPair      *compiler.AllowDenyPair
		wantAttached  bool
		wantProgTypes []string
		wantDenyAll   map[string]bool
	}{{
		name:     "audit mode is a no-op",
		mode:     "audit",
		openPair: pair(nil, []string{"/etc/shadow"}),
		execPair: pair(nil, []string{"/bin/sh"}),
	}, {
		name:     "empty mode is a no-op",
		mode:     "",
		openPair: pair(nil, []string{"/etc/shadow"}),
	}, {
		name:          "open only",
		mode:          "enforce",
		openPair:      pair(nil, []string{"/etc/shadow"}),
		wantAttached:  true,
		wantProgTypes: []string{open},
		wantDenyAll:   map[string]bool{open: false},
	}, {
		name:          "exec only",
		mode:          "enforce",
		execPair:      pair([]string{"/bin/ls"}, nil),
		wantAttached:  true,
		wantProgTypes: []string{exec},
		wantDenyAll:   map[string]bool{exec: false},
	}, {
		name:          "both prog types",
		mode:          "enforce",
		openPair:      pair(nil, []string{"*"}),
		execPair:      pair([]string{"/bin/ls"}, []string{"*"}),
		wantAttached:  true,
		wantProgTypes: []string{exec, open},
		wantDenyAll:   map[string]bool{open: true, exec: true},
	}, {
		name:     "no entries creates nothing",
		mode:     "enforce",
		openPair: pair(nil, nil),
		execPair: nil,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			rp := result("rp1", tt.mode, labels.Everything(), tt.openPair, tt.execPair)
			if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			la, attached := h.l.lsmAttachments["rp1"]
			if attached != tt.wantAttached {
				t.Fatalf("attachment stored = %v, want %v", attached, tt.wantAttached)
			}
			if !tt.wantAttached {
				if h.createdCount() != 0 {
					t.Errorf("created %d enforcers, want 0", h.createdCount())
				}
				return
			}
			if got := progTypes(la); !slices.Equal(got, tt.wantProgTypes) {
				t.Errorf("prog types = %v, want %v", got, tt.wantProgTypes)
			}
			if h.createdCount() != len(tt.wantProgTypes) {
				t.Errorf("created %d enforcers, want %d", h.createdCount(), len(tt.wantProgTypes))
			}

			for _, pt := range tt.wantProgTypes {
				f := h.enf("rp1", pt)
				want := tt.openPair
				if pt == exec {
					want = tt.execPair
				}
				// the initial target set is written in one AddTargets call
				assertPairCalls(t, pt+" AddTargets", f.addTargets, []compiler.AllowDenyPair{clonePair(want)})
				if len(f.delTargets) != 0 {
					t.Errorf("%s: unexpected DeleteTargets calls %v", pt, f.delTargets)
				}
				if !slices.Equal(f.defaultDeny, []bool{tt.wantDenyAll[pt]}) {
					t.Errorf("%s: SetDefaultDeny calls = %v, want [%v]", pt, f.defaultDeny, tt.wantDenyAll[pt])
				}
				if f.attachCount != 1 {
					t.Errorf("%s: Attach called %d times, want 1", pt, f.attachCount)
				}
				if f.closeCount != 0 {
					t.Errorf("%s: Close called %d times, want 0", pt, f.closeCount)
				}
			}
			assertInvariant(t, h.l)
		})
	}
}

func TestRpCreated_AttachesPreExistingMatchingPods(t *testing.T) {
	h := newHarness(t)
	// two matching pods and one that doesn't match
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11, 12), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.PodEvent(testPod("podB", map[string]string{"app": "web"}), cgs(21), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if err := h.l.PodEvent(testPod("podC", map[string]string{"app": "db"}), cgs(31), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	rp := result("rp1", "enforce", selFor(map[string]string{"app": "web"}),
		pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"}))
	if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	la := h.l.lsmAttachments["rp1"]
	if got := attachedPodUIDs(la); !slices.Equal(got, []string{"podA", "podB"}) {
		t.Errorf("attached pods = %v, want [podA podB]", got)
	}
	for _, uid := range []string{"podA", "podB"} {
		if got := attachedPolicyUIDs(h.l.pods[uid]); !slices.Equal(got, []string{"rp1"}) {
			t.Errorf("%s attachedLsms = %v, want [rp1]", uid, got)
		}
	}
	if got := attachedPolicyUIDs(h.l.pods["podC"]); len(got) != 0 {
		t.Errorf("podC attachedLsms = %v, want empty", got)
	}

	// both enforcers get exactly the cgids of the matching pods, in one aggregated call
	for _, pt := range []string{open, exec} {
		f := h.enf("rp1", pt)
		if len(f.addCgids) != 1 {
			t.Fatalf("%s: AddCgids calls = %v, want a single aggregated call", pt, f.addCgids)
		}
		if got := f.cgidSet(); !slices.Equal(got, []uint64{11, 12, 21}) {
			t.Errorf("%s: cgid set = %v, want [11 12 21]", pt, got)
		}
	}
	assertInvariant(t, h.l)
}

func TestRpCreated_NoMatchingPodsSkipsCgidCalls(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podC", map[string]string{"app": "db"}), cgs(31), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	rp := result("rp1", "enforce", selFor(map[string]string{"app": "web"}), pair(nil, []string{"/etc/shadow"}), nil)
	if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	f := h.enf("rp1", open)
	if len(f.addCgids) != 0 {
		t.Errorf("AddCgids calls = %v, want none", f.addCgids)
	}
	if got := attachedPodUIDs(h.l.lsmAttachments["rp1"]); len(got) != 0 {
		t.Errorf("attached pods = %v, want none", got)
	}
	assertInvariant(t, h.l)
}

func TestRpCreated_ErrorPaths(t *testing.T) {
	t.Run("enforcer construction failure propagates and stores nothing", func(t *testing.T) {
		h := newHarness(t)
		boom := errors.New("no bpf lsm")
		h.failCreate(open, boom)
		rp := result("rp1", "enforce", labels.Everything(), pair(nil, []string{"/etc/shadow"}), nil)
		if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		if _, ok := h.l.lsmAttachments["rp1"]; ok {
			t.Error("attachment stored despite construction failure")
		}
	})

	// every setup step after construction must close the half built enforcer
	for _, method := range []string{"AddTargets", "SetDefaultDeny", "Attach"} {
		t.Run(method+" failure closes the new enforcer", func(t *testing.T) {
			h := newHarness(t)
			boom := errors.New("bpf map failure in " + method)
			h.failMethod(open, method, boom)
			rp := result("rp1", "enforce", labels.Everything(), pair(nil, []string{"/etc/shadow"}), nil)
			if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); !errors.Is(err, boom) {
				t.Fatalf("err = %v, want %v", err, boom)
			}
			created := h.createdFor(open)
			if len(created) != 1 {
				t.Fatalf("created %d open enforcers, want 1", len(created))
			}
			if created[0].closeCount != 1 {
				t.Errorf("Close called %d times, want 1 (leaked bpf objects)", created[0].closeCount)
			}
			if _, ok := h.l.lsmAttachments["rp1"]; ok {
				t.Errorf("attachment stored despite %s failure", method)
			}
		})
	}

	t.Run("exec construction failure closes the already created open enforcer", func(t *testing.T) {
		h := newHarness(t)
		boom := errors.New("exec enforcer unavailable")
		h.failCreate(exec, boom)
		rp := result("rp1", "enforce", labels.Everything(),
			pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"}))
		if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want %v", err, boom)
		}
		created := h.createdFor(open)
		if len(created) != 1 {
			t.Fatalf("created %d open enforcers, want 1", len(created))
		}
		if created[0].closeCount != 1 {
			t.Errorf("open enforcer Close called %d times, want 1 (leaked bpf objects)", created[0].closeCount)
		}
		if _, ok := h.l.lsmAttachments["rp1"]; ok {
			t.Error("attachment stored despite exec construction failure")
		}
	})
}

func TestRpUpdated_NoAttachment(t *testing.T) {
	tests := []struct {
		name        string
		openPair    *compiler.AllowDenyPair
		execPair    *compiler.AllowDenyPair
		wantCreated int
	}{
		{name: "nil pairs stay unattached", wantCreated: 0},
		{name: "empty pairs stay unattached", openPair: pair(nil, nil), execPair: pair(nil, nil), wantCreated: 0},
		{name: "open entries route through creation", openPair: pair(nil, []string{"/etc/shadow"}), wantCreated: 1},
		{name: "exec entries route through creation", execPair: pair(nil, []string{"/bin/sh"}), wantCreated: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			rp := result("rp1", "enforce", labels.Everything(), tt.openPair, tt.execPair)
			if err := h.l.RuntimePolicyEvent(rp, events.EventTypeUpdate); err != nil {
				t.Fatal(err)
			}
			if h.createdCount() != tt.wantCreated {
				t.Errorf("created %d enforcers, want %d", h.createdCount(), tt.wantCreated)
			}
			_, attached := h.l.lsmAttachments["rp1"]
			if attached != (tt.wantCreated > 0) {
				t.Errorf("attachment stored = %v, want %v", attached, tt.wantCreated > 0)
			}
			assertInvariant(t, h.l)
		})
	}
}

func TestRpUpdated_ModeFlipTearsDown(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", map[string]string{"app": "web"}), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	sel := selFor(map[string]string{"app": "web"})
	rp := result("rp1", "enforce", sel, pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"}))
	if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	openEnf, execEnf := h.enf("rp1", open), h.enf("rp1", exec)

	// flipping away from enforce must tear the whole attachment down
	audit := result("rp1", "audit", sel, pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"}))
	if err := h.l.RuntimePolicyEvent(audit, events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.l.lsmAttachments["rp1"]; ok {
		t.Error("attachment still present after mode flip")
	}
	for name, f := range map[string]*fakeEnforcer{open: openEnf, exec: execEnf} {
		if f.closeCount != 1 {
			t.Errorf("%s: Close called %d times, want 1", name, f.closeCount)
		}
	}
	if got := attachedPolicyUIDs(h.l.pods["podA"]); len(got) != 0 {
		t.Errorf("podA attachedLsms = %v, want empty", got)
	}
	assertInvariant(t, h.l)
}

func TestRpUpdated_EmptyingAllProgsDeletesAttachment(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", nil), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	rp := result("rp1", "enforce", labels.Everything(), pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"}))
	if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	openEnf, execEnf := h.enf("rp1", open), h.enf("rp1", exec)

	empty := result("rp1", "enforce", labels.Everything(), pair(nil, nil), pair(nil, nil))
	if err := h.l.RuntimePolicyEvent(empty, events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.l.lsmAttachments["rp1"]; ok {
		t.Error("attachment still present after all prog types were emptied")
	}
	// each enforcer must be closed exactly once: syncProgType closes it and removes
	// it from the map, so the follow up rpDeleted must not close it again
	if openEnf.closeCount != 1 || execEnf.closeCount != 1 {
		t.Errorf("close counts = open:%d exec:%d, want 1 each", openEnf.closeCount, execEnf.closeCount)
	}
	if got := attachedPolicyUIDs(h.l.pods["podA"]); len(got) != 0 {
		t.Errorf("podA attachedLsms = %v, want empty", got)
	}
	assertInvariant(t, h.l)
}

func TestSyncProgType_TargetDiffs(t *testing.T) {
	tests := []struct {
		name        string
		oldPair     *compiler.AllowDenyPair
		newPair     *compiler.AllowDenyPair
		wantAdd     []compiler.AllowDenyPair
		wantDel     []compiler.AllowDenyPair
		wantDenyAll []bool
		wantAllow   []string
		wantDeny    []string
	}{{
		name:      "identical targets produce no calls",
		oldPair:   pair([]string{"/bin/ls"}, []string{"/etc/shadow"}),
		newPair:   pair([]string{"/bin/ls"}, []string{"/etc/shadow"}),
		wantAllow: []string{"/bin/ls"},
		wantDeny:  []string{"/etc/shadow"},
	}, {
		name:        "deny addition",
		oldPair:     pair(nil, []string{"/etc/shadow"}),
		newPair:     pair(nil, []string{"/etc/shadow", "/etc/passwd"}),
		wantAdd:     []compiler.AllowDenyPair{{Deny: []string{"/etc/passwd"}}},
		wantDenyAll: []bool{false},
		wantDeny:    []string{"/etc/passwd", "/etc/shadow"},
	}, {
		name:        "deny removal",
		oldPair:     pair(nil, []string{"/etc/shadow", "/etc/passwd"}),
		newPair:     pair(nil, []string{"/etc/shadow"}),
		wantDel:     []compiler.AllowDenyPair{{Deny: []string{"/etc/passwd"}}},
		wantDenyAll: []bool{false},
		wantDeny:    []string{"/etc/shadow"},
	}, {
		name:        "allow and deny churn in both directions",
		oldPair:     pair([]string{"/bin/ls", "/bin/cat"}, []string{"/etc/shadow"}),
		newPair:     pair([]string{"/bin/cat", "/bin/sh"}, []string{"/etc/passwd"}),
		wantAdd:     []compiler.AllowDenyPair{{Allow: []string{"/bin/sh"}, Deny: []string{"/etc/passwd"}}},
		wantDel:     []compiler.AllowDenyPair{{Allow: []string{"/bin/ls"}, Deny: []string{"/etc/shadow"}}},
		wantDenyAll: []bool{false},
		wantAllow:   []string{"/bin/cat", "/bin/sh"},
		wantDeny:    []string{"/etc/passwd"},
	}, {
		name:        "star entering deny turns default deny on",
		oldPair:     pair(nil, []string{"/etc/shadow"}),
		newPair:     pair(nil, []string{"/etc/shadow", "*"}),
		wantAdd:     []compiler.AllowDenyPair{{Deny: []string{"*"}}},
		wantDenyAll: []bool{true},
		wantDeny:    []string{"*", "/etc/shadow"},
	}, {
		name:        "star leaving deny turns default deny off",
		oldPair:     pair(nil, []string{"*", "/etc/shadow"}),
		newPair:     pair(nil, []string{"/etc/shadow"}),
		wantDel:     []compiler.AllowDenyPair{{Deny: []string{"*"}}},
		wantDenyAll: []bool{false},
		wantDeny:    []string{"/etc/shadow"},
	}, {
		name:        "star retained across an unrelated change keeps default deny on",
		oldPair:     pair(nil, []string{"*"}),
		newPair:     pair([]string{"/bin/ls"}, []string{"*"}),
		wantAdd:     []compiler.AllowDenyPair{{Allow: []string{"/bin/ls"}}},
		wantDenyAll: []bool{true},
		wantAllow:   []string{"/bin/ls"},
		wantDeny:    []string{"*"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			// no pods, so the recorded calls are only the target diff
			create := result("rp1", "enforce", labels.Everything(), tt.oldPair, nil)
			if err := h.l.RuntimePolicyEvent(create, events.EventTypeCreate); err != nil {
				t.Fatal(err)
			}
			f := h.enf("rp1", open)
			f.reset()

			update := result("rp1", "enforce", labels.Everything(), tt.newPair, nil)
			if err := h.l.RuntimePolicyEvent(update, events.EventTypeUpdate); err != nil {
				t.Fatal(err)
			}
			if f != h.enf("rp1", open) {
				t.Fatal("enforcer was replaced by an update that should have reused it")
			}

			assertPairCalls(t, "AddTargets", f.addTargets, tt.wantAdd)
			assertPairCalls(t, "DeleteTargets", f.delTargets, tt.wantDel)
			if !slices.Equal(f.defaultDeny, tt.wantDenyAll) {
				t.Errorf("SetDefaultDeny calls = %v, want %v", f.defaultDeny, tt.wantDenyAll)
			}
			if got := f.allowSet(); !slices.Equal(got, tt.wantAllow) {
				t.Errorf("effective allow set = %v, want %v", got, tt.wantAllow)
			}
			if got := f.denySet(); !slices.Equal(got, tt.wantDeny) {
				t.Errorf("effective deny set = %v, want %v", got, tt.wantDeny)
			}
			if want := slices.Contains(tt.newPair.Deny, "*"); f.denyAll != want {
				t.Errorf("effective default deny = %v, want %v", f.denyAll, want)
			}

			// replaying the same update must be a no-op, which only holds if the
			// synced file set was recorded on the prog state
			f.reset()
			if err := h.l.RuntimePolicyEvent(update, events.EventTypeUpdate); err != nil {
				t.Fatal(err)
			}
			if len(f.addTargets) != 0 || len(f.delTargets) != 0 || len(f.defaultDeny) != 0 {
				t.Errorf("replaying the same update was not a no-op: add=%v del=%v denyAll=%v",
					f.addTargets, f.delTargets, f.defaultDeny)
			}
			assertInvariant(t, h.l)
		})
	}
}

func TestSyncProgType_LateEnforcerSeededWithAttachedPodCgids(t *testing.T) {
	h := newHarness(t)
	sel := selFor(map[string]string{"app": "web"})
	for _, p := range []struct {
		uid   string
		cgids []uint64
	}{{"podA", []uint64{11, 12}}, {"podB", []uint64{21}}} {
		if err := h.l.PodEvent(testPod(p.uid, map[string]string{"app": "web"}), cgs(p.cgids...), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
	}
	// start with open only
	if err := h.l.RuntimePolicyEvent(result("rp1", "enforce", sel, pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	if len(h.createdFor(exec)) != 0 {
		t.Fatal("exec enforcer created for an open only policy")
	}

	// the update introduces exec entries: a new enforcer must be created and seeded
	// with the cgids of the pods that are already attached
	update := result("rp1", "enforce", sel, pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"*"}))
	if err := h.l.RuntimePolicyEvent(update, events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	execEnf := h.enf("rp1", exec)
	assertCgidCalls(t, "exec AddCgids", execEnf.addCgids, [][]uint64{{11, 12}, {21}})
	if got := execEnf.cgidSet(); !slices.Equal(got, []uint64{11, 12, 21}) {
		t.Errorf("exec cgid set = %v, want [11 12 21]", got)
	}
	if !execEnf.denyAll {
		t.Error("exec enforcer default deny = false, want true (deny contains \"*\")")
	}
	if got := execEnf.denySet(); !slices.Equal(got, []string{"*"}) {
		t.Errorf("exec deny set = %v, want [*]", got)
	}
	// the open enforcer must be untouched by the exec addition
	openEnf := h.enf("rp1", open)
	if len(openEnf.addTargets) != 1 || len(openEnf.delTargets) != 0 {
		t.Errorf("open enforcer target calls changed: add=%v del=%v", openEnf.addTargets, openEnf.delTargets)
	}
	assertInvariant(t, h.l)
}

func TestSyncProgType_DropsProgTypeThatLostAllEntries(t *testing.T) {
	h := newHarness(t)
	if err := h.l.RuntimePolicyEvent(result("rp1", "enforce", labels.Everything(),
		pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	openEnf := h.enf("rp1", open)

	// open loses all entries, exec keeps them
	if err := h.l.RuntimePolicyEvent(result("rp1", "enforce", labels.Everything(),
		pair(nil, nil), pair(nil, []string{"/bin/sh"})), events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	la := h.l.lsmAttachments["rp1"]
	if got := progTypes(la); !slices.Equal(got, []string{exec}) {
		t.Fatalf("prog types = %v, want [%s]", got, exec)
	}
	if openEnf.closeCount != 1 {
		t.Errorf("open enforcer Close called %d times, want 1", openEnf.closeCount)
	}

	// open regains entries: a brand new enforcer must be built, never the closed one
	if err := h.l.RuntimePolicyEvent(result("rp1", "enforce", labels.Everything(),
		pair(nil, []string{"/etc/hosts"}), pair(nil, []string{"/bin/sh"})), events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	created := h.createdFor(open)
	if len(created) != 2 {
		t.Fatalf("created %d open enforcers, want 2", len(created))
	}
	if h.enf("rp1", open) == openEnf {
		t.Error("closed open enforcer was reused")
	}
	if got := h.enf("rp1", open).denySet(); !slices.Equal(got, []string{"/etc/hosts"}) {
		t.Errorf("new open enforcer deny set = %v, want [/etc/hosts]", got)
	}
	if len(openEnf.usedClosed) != 0 {
		t.Errorf("closed enforcer was used after Close: %v", openEnf.usedClosed)
	}
	assertInvariant(t, h.l)
}

// a failing Close must still drop the prog state, otherwise every later sync
// would operate on a dead enforcer.
func TestSyncProgType_CloseFailureStillDropsProgState(t *testing.T) {
	h := newHarness(t)
	boom := errors.New("close failed")
	h.failMethod(open, "Close", boom)
	if err := h.l.RuntimePolicyEvent(result("rp1", "enforce", labels.Everything(),
		pair(nil, []string{"/etc/shadow"}), pair(nil, []string{"/bin/sh"})), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	openEnf := h.enf("rp1", open)

	err := h.l.RuntimePolicyEvent(result("rp1", "enforce", labels.Everything(),
		pair(nil, nil), pair(nil, []string{"/bin/sh"})), events.EventTypeUpdate)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	la := h.l.lsmAttachments["rp1"]
	if _, ok := la.progs[open]; ok {
		t.Fatal("closed open enforcer is still registered in la.progs")
	}
	if openEnf.closeCount != 1 {
		t.Errorf("Close called %d times, want 1", openEnf.closeCount)
	}
	assertInvariant(t, h.l)
}

func TestSyncPodAttachment_SelectorChange(t *testing.T) {
	h := newHarness(t)
	for _, p := range []struct {
		uid   string
		lbls  map[string]string
		cgids []uint64
	}{
		{"podWeb", map[string]string{"app": "web"}, []uint64{11}},
		{"podDb", map[string]string{"app": "db"}, []uint64{21, 22}},
	} {
		if err := h.l.PodEvent(testPod(p.uid, p.lbls), cgs(p.cgids...), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
	}

	files := pair(nil, []string{"/etc/shadow"})
	if err := h.l.RuntimePolicyEvent(result("rp1", "enforce", selFor(map[string]string{"app": "web"}), files, nil), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	f := h.enf("rp1", open)
	if got := f.cgidSet(); !slices.Equal(got, []uint64{11}) {
		t.Fatalf("cgid set after create = %v, want [11]", got)
	}
	f.reset()

	// the selector now points at the db pod instead: the web pod must be detached
	// and the db pod attached, with exact cgid arguments
	if err := h.l.RuntimePolicyEvent(result("rp1", "enforce", selFor(map[string]string{"app": "db"}), files, nil), events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	assertCgidCalls(t, "AddCgids", f.addCgids, [][]uint64{{21, 22}})
	assertCgidCalls(t, "DeleteCgids", f.delCgids, [][]uint64{{11}})
	if got := f.cgidSet(); !slices.Equal(got, []uint64{21, 22}) {
		t.Errorf("cgid set = %v, want [21 22]", got)
	}
	la := h.l.lsmAttachments["rp1"]
	if got := attachedPodUIDs(la); !slices.Equal(got, []string{"podDb"}) {
		t.Errorf("attached pods = %v, want [podDb]", got)
	}
	if got := attachedPolicyUIDs(h.l.pods["podWeb"]); len(got) != 0 {
		t.Errorf("podWeb attachedLsms = %v, want empty", got)
	}
	if got := attachedPolicyUIDs(h.l.pods["podDb"]); !slices.Equal(got, []string{"rp1"}) {
		t.Errorf("podDb attachedLsms = %v, want [rp1]", got)
	}
	assertInvariant(t, h.l)

	// an update that keeps the same selector must not re-add the cgids
	f.reset()
	if err := h.l.RuntimePolicyEvent(result("rp1", "enforce", selFor(map[string]string{"app": "db"}), files, nil), events.EventTypeUpdate); err != nil {
		t.Fatal(err)
	}
	if len(f.addCgids) != 0 || len(f.delCgids) != 0 {
		t.Errorf("stable selector produced cgid churn: add=%v del=%v", f.addCgids, f.delCgids)
	}
}

func TestRpDeleted(t *testing.T) {
	h := newHarness(t)
	if err := h.l.PodEvent(testPod("podA", nil), cgs(11), events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}
	// two policies on the same pod, only one is deleted
	for _, uid := range []string{"rp1", "rp2"} {
		if err := h.l.RuntimePolicyEvent(result(uid, "enforce", labels.Everything(), pair(nil, []string{"/etc/shadow"}), nil), events.EventTypeCreate); err != nil {
			t.Fatal(err)
		}
	}
	rp1Enf, rp2Enf := h.enf("rp1", open), h.enf("rp2", open)

	if err := h.l.RuntimePolicyEvent(&compiler.EvaluationResult{UID: "rp1"}, events.EventTypeDelete); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.l.lsmAttachments["rp1"]; ok {
		t.Error("rp1 attachment not removed")
	}
	if rp1Enf.closeCount != 1 {
		t.Errorf("rp1 enforcer Close called %d times, want 1", rp1Enf.closeCount)
	}
	if rp2Enf.closeCount != 0 {
		t.Errorf("rp2 enforcer Close called %d times, want 0", rp2Enf.closeCount)
	}
	if got := attachedPolicyUIDs(h.l.pods["podA"]); !slices.Equal(got, []string{"rp2"}) {
		t.Errorf("podA attachedLsms = %v, want [rp2]", got)
	}
	assertInvariant(t, h.l)

	// deleting an unknown policy is a no-op
	if err := h.l.RuntimePolicyEvent(&compiler.EvaluationResult{UID: "nope"}, events.EventTypeDelete); err != nil {
		t.Fatal(err)
	}
	if rp2Enf.closeCount != 0 {
		t.Error("deleting an unknown policy closed a live enforcer")
	}
	assertInvariant(t, h.l)
}

func TestRuntimePolicyEvent_UnknownEventTypeIsIgnored(t *testing.T) {
	h := newHarness(t)
	if err := h.l.RuntimePolicyEvent(result("rp1", "enforce", labels.Everything(), pair(nil, []string{"/etc/shadow"}), nil), "bogus"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.createdCount() != 0 || len(h.l.lsmAttachments) != 0 {
		t.Errorf("unknown event type mutated state: created=%d attachments=%d", h.createdCount(), len(h.l.lsmAttachments))
	}
}
