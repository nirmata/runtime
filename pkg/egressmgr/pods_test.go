package egressmgr

import (
	"errors"
	"slices"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
)

func cg(id uint64, path string) *containers.ContainerCgroupInfo {
	return &containers.ContainerCgroupInfo{ID: id, Path: path}
}

func TestPodCreatedAggregatesAllMatchingPolicies(t *testing.T) {
	e, factory, _ := newTestManager()
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, []string{"2.2.2.2"}, []string{"8.8.8.8"}), events.EventTypeCreate)
	mustRpEvent(t, e, rp("rp-3", "enforce", apiLabels, []string{"3.3.3.3"}, nil), events.EventTypeCreate)

	f := addPod(t, e, "pod-web", webLabels, "/cg/a", "/cg/b")

	if len(factory.created) != 1 {
		t.Fatalf("filters created: got %d, want 1", len(factory.created))
	}
	// the ips of every matching policy are programmed in a single call
	if len(f.adds) != 1 {
		t.Fatalf("AddIps calls: got %d (%v), want 1", len(f.adds), f.adds)
	}
	wantLiveIps(t, f, []string{"1.1.1.1", "2.2.2.2"}, []string{"8.8.8.8"})
	wantAttachedRps(t, e, "pod-web", "rp-1", "rp-2")
	wantDefaultDeny(t, f, true)
	wantDefaultDenyOwners(t, e, "pod-web", "rp-1")

	// the pod must hold the manager's shared policy pointers, not copies
	for _, uid := range []string{"rp-1", "rp-2"} {
		assertSharedPointer(t, e, uid, "pod-web")
	}

	if !slices.Equal(f.attaches, []string{"/cg/a", "/cg/b"}) {
		t.Errorf("attached cgroups: got %v, want [/cg/a /cg/b]", f.attaches)
	}
	if got := cgPathsOf(t, e, "pod-web"); !slices.Equal(got, []string{"/cg/a", "/cg/b"}) {
		t.Errorf("tracked cgroups: got %v, want [/cg/a /cg/b]", got)
	}
	if got := e.pods["pod-web"].labels; got["app"] != "web" {
		t.Errorf("stored labels: got %v", got)
	}
}

func TestPodCreatedWithNoMatchingPolicyLeavesFilterUntouched(t *testing.T) {
	e, _, _ := newTestManager()
	mustRpEvent(t, e, rp("rp-1", "enforce", apiLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)

	f := addPod(t, e, "pod-web", webLabels, "/cg/a")

	wantPairs(t, "AddIps", f.adds, nil)
	if len(f.toggles) != 0 {
		t.Errorf("flags touched with no matching policy: %v", f.toggles)
	}
	wantAttachedRps(t, e, "pod-web")
	// the cgroup attachment still happens: the filter must be live before a
	// policy shows up later
	if !slices.Equal(f.attaches, []string{"/cg/a"}) {
		t.Errorf("attached cgroups: got %v, want [/cg/a]", f.attaches)
	}
}

// a pod that matches only an observe-mode policy at creation time must come up
// counting, not enforcing.
func TestPodCreatedWithObservePolicySetsObserveOnly(t *testing.T) {
	e, _, _ := newTestManager()
	mustRpEvent(t, e, rp("rp-1", compiler.ModeMonitor, webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)

	f := addPod(t, e, "pod-web", webLabels, "/cg/a")

	wantPairs(t, "AddIps", f.adds, nil)
	wantLiveIps(t, f, []string{}, []string{})
	wantObserveFlag(t, f, true)
	wantDefaultDeny(t, f, false)
	wantObserveOwners(t, e, "pod-web", "rp-1")
	wantDefaultDenyOwners(t, e, "pod-web")
	wantAttachedRps(t, e, "pod-web", "rp-1")
}

func TestPodCreatedAttachFailureDoesNotRegisterPod(t *testing.T) {
	e, factory, _ := newTestManager()
	factory.attachErr = errors.New("attach boom")

	err := e.PodEvent(makePod("pod-1", webLabels), cgInfos("/cg/a"), events.EventTypeCreate)
	if err == nil {
		t.Fatal("expected an error when the cgroup attach fails")
	}
	if _, ok := e.pods["pod-1"]; ok {
		t.Error("pod was registered despite a failed attach")
	}
}

func TestPodCreatedFilterConstructionFailurePropagates(t *testing.T) {
	e, factory, _ := newTestManager()
	factory.newErr = errors.New("no bpf here")

	err := e.PodEvent(makePod("pod-1", webLabels), cgInfos("/cg/a"), events.EventTypeCreate)
	if err == nil {
		t.Fatal("expected an error when the filter cannot be created")
	}
	if len(e.pods) != 0 {
		t.Errorf("pods tracked after a failed filter construction: %v", e.pods)
	}
}

func TestPodUpdatedAttachesOnlyNewCgroupsAndDropsStaleOnes(t *testing.T) {
	e, _, _ := newTestManager()
	a, b, c := cg(1, "/cg/a"), cg(2, "/cg/b"), cg(3, "/cg/c")

	if err := e.PodEvent(makePod("pod-1", webLabels), []*containers.ContainerCgroupInfo{a, b}, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	f := filterOf(t, e, "pod-1")
	f.reset()

	// container "a" is gone, "c" is new, "b" is unchanged
	if err := e.PodEvent(makePod("pod-1", webLabels), []*containers.ContainerCgroupInfo{b, c}, events.EventTypeUpdate); err != nil {
		t.Fatalf("update: %v", err)
	}

	if !slices.Equal(f.attaches, []string{"/cg/c"}) {
		t.Errorf("attaches on update: got %v, want only [/cg/c] (b must not be re-attached)", f.attaches)
	}
	if got := cgPathsOf(t, e, "pod-1"); !slices.Equal(got, []string{"/cg/b", "/cg/c"}) {
		t.Errorf("tracked cgroups after update: got %v, want [/cg/b /cg/c]", got)
	}
}

func TestPodUpdatedAttachFailureLeavesCgroupsUnchanged(t *testing.T) {
	e, _, _ := newTestManager()
	a := cg(1, "/cg/a")
	if err := e.PodEvent(makePod("pod-1", webLabels), []*containers.ContainerCgroupInfo{a}, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	f := filterOf(t, e, "pod-1")
	f.attachErr = errors.New("attach boom")

	err := e.PodEvent(makePod("pod-1", webLabels), []*containers.ContainerCgroupInfo{a, cg(2, "/cg/b")}, events.EventTypeUpdate)
	if err == nil {
		t.Fatal("expected the attach error to propagate")
	}
	if got := cgPathsOf(t, e, "pod-1"); !slices.Equal(got, []string{"/cg/a"}) {
		t.Errorf("tracked cgroups after a failed update: got %v, want [/cg/a]", got)
	}
}

func TestPodUpdatedForUnknownPodErrors(t *testing.T) {
	e, factory, _ := newTestManager()

	err := e.PodEvent(makePod("ghost", webLabels), cgInfos("/cg/a"), events.EventTypeUpdate)
	if err == nil {
		t.Fatal("expected an error for an update of an untracked pod")
	}
	if len(factory.created) != 0 {
		t.Errorf("a filter was created for an untracked pod: %d", len(factory.created))
	}
}

func TestPodDeletedDropsStateAndStopsFutureUpdates(t *testing.T) {
	e, _, _ := newTestManager()
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	addPod(t, e, "pod-1", webLabels, "/cg/a")

	if err := e.PodDeleted("pod-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(e.pods) != 0 {
		t.Errorf("pod state left behind after delete: %v", e.pods)
	}
	// the policy is untouched by a pod deletion
	if _, ok := e.rps["rp-1"]; !ok {
		t.Error("rp-1 was dropped by a pod delete")
	}
	// a later policy update must not resurrect the pod
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"2.2.2.2"}, nil), events.EventTypeUpdate)
	if len(e.pods) != 0 {
		t.Errorf("deleted pod resurrected by a policy update: %v", e.pods)
	}
}

// TestPodUpdatedRefreshesLabelsAndReEvaluatesSelectors: an in-place relabel
// must both stop enforcement that no longer selects the pod and start
// enforcement that now does, without routing through a delete/create pair.
func TestPodUpdatedRefreshesLabelsAndReEvaluatesSelectors(t *testing.T) {
	tests := []struct {
		name string
		// policies created before the relabel
		policies  []*compiler.EvaluationResult
		from, to  map[string]string
		wantAllow []string
		wantDeny  []string
		// bookkeeping after the relabel
		wantAttached    []string
		wantDefaultDeny []string
		wantObserve     []string
		wantDDFlag      bool
		wantObserveFlag bool
	}{
		{
			name:            "policy that no longer selects the pod is detached",
			policies:        []*compiler.EvaluationResult{rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"})},
			from:            webLabels,
			to:              apiLabels,
			wantAllow:       []string{},
			wantDeny:        []string{},
			wantAttached:    nil,
			wantDefaultDeny: nil,
			wantDDFlag:      false,
		},
		{
			name:            "policy that now selects the pod is attached",
			policies:        []*compiler.EvaluationResult{rp("rp-1", "enforce", apiLabels, []string{"1.1.1.1"}, []string{"*"})},
			from:            webLabels,
			to:              apiLabels,
			wantAllow:       []string{"1.1.1.1"},
			wantDeny:        []string{},
			wantAttached:    []string{"rp-1"},
			wantDefaultDeny: []string{"rp-1"},
			wantDDFlag:      true,
		},
		{
			name: "default deny survives while an overlapping policy still requires it",
			policies: []*compiler.EvaluationResult{
				rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}),
				rp("rp-2", "enforce", nil, []string{"9.9.9.9"}, []string{"*"}),
			},
			from:            webLabels,
			to:              apiLabels,
			wantAllow:       []string{"9.9.9.9"},
			wantDeny:        []string{},
			wantAttached:    []string{"rp-2"},
			wantDefaultDeny: []string{"rp-2"},
			wantDDFlag:      true,
		},
		{
			name: "observe flag survives while an overlapping observe policy still requires it",
			policies: []*compiler.EvaluationResult{
				rp("rp-1", compiler.ModeMonitor, webLabels, nil, []string{"*"}),
				rp("rp-2", compiler.ModeMonitor, nil, nil, nil),
			},
			from:            webLabels,
			to:              apiLabels,
			wantAllow:       []string{},
			wantDeny:        []string{},
			wantAttached:    []string{"rp-2"},
			wantObserve:     []string{"rp-2"},
			wantObserveFlag: true,
		},
		{
			name:            "last observe policy leaving clears the observe flag",
			policies:        []*compiler.EvaluationResult{rp("rp-1", compiler.ModeMonitor, webLabels, nil, []string{"*"})},
			from:            webLabels,
			to:              apiLabels,
			wantAllow:       []string{},
			wantDeny:        []string{},
			wantAttached:    nil,
			wantObserve:     nil,
			wantObserveFlag: false,
		},
		{
			name:            "relabel that changes nothing leaves the attachment alone",
			policies:        []*compiler.EvaluationResult{rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"})},
			from:            webLabels,
			to:              map[string]string{"app": "web", "tier": "front"},
			wantAllow:       []string{"1.1.1.1"},
			wantDeny:        []string{},
			wantAttached:    []string{"rp-1"},
			wantDefaultDeny: []string{"rp-1"},
			wantDDFlag:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _, _ := newTestManager()
			for _, p := range tc.policies {
				mustRpEvent(t, e, p, events.EventTypeCreate)
			}
			f := addPod(t, e, "pod-1", tc.from, "/cg/pod-1")

			relabelPod(t, e, "pod-1", tc.to, "/cg/pod-1")

			if got := e.pods["pod-1"].labels["app"]; got != tc.to["app"] {
				t.Errorf("cached labels were not refreshed: got app=%q, want %q", got, tc.to["app"])
			}
			wantLiveIps(t, f, tc.wantAllow, tc.wantDeny)
			wantAttachedRps(t, e, "pod-1", tc.wantAttached...)
			wantDefaultDenyOwners(t, e, "pod-1", tc.wantDefaultDeny...)
			wantObserveOwners(t, e, "pod-1", tc.wantObserve...)
			wantDefaultDeny(t, f, tc.wantDDFlag)
			wantObserveFlag(t, f, tc.wantObserveFlag)
			// the pod must hold the shared pointer for anything it kept
			for _, uid := range tc.wantAttached {
				assertSharedPointer(t, e, uid, "pod-1")
			}
		})
	}
}
