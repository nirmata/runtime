package egressmgr

import (
	"slices"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
)

var (
	webLabels = map[string]string{"app": "web"}
	apiLabels = map[string]string{"app": "api"}
)

func mustRpEvent(t *testing.T, e *EgressManager, r *compiler.EvaluationResult, eventType string) {
	t.Helper()
	if err := e.RuntimePolicyEvent(r, eventType); err != nil {
		t.Fatalf("RuntimePolicyEvent(%s, %s): unexpected error: %v", r.UID, eventType, err)
	}
}

// TestRpUpdatedKeepsSharedRpPointer is the regression test for #53 / 82acb1f.
// rpUpdated mutates the *shared* EvaluationResult in place; it must not replace
// e.rps[uid] with the incoming object, otherwise the pods' attachedFilters
// pointer freezes on a stale generation and the eventual detach deletes the
// wrong IP set from the pod's BPF map.
func TestRpUpdatedKeepsSharedRpPointerAcrossUpdates(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")

	gen1 := rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil)
	mustRpEvent(t, e, gen1, events.EventTypeCreate)
	assertSharedPointer(t, e, "rp-1", "pod-1")

	// second generation: 1.1.1.1 -> 2.2.2.2
	gen2 := rp("rp-1", "enforce", webLabels, []string{"2.2.2.2"}, nil)
	mustRpEvent(t, e, gen2, events.EventTypeUpdate)
	assertSharedPointer(t, e, "rp-1", "pod-1")
	wantLiveIps(t, f, []string{"2.2.2.2"}, []string{})

	// third generation: this is the one the bug broke. with the reassignment
	// present, e.rps holds gen2 while the pod still holds gen1, whose IPs pointer
	// was frozen at the gen2 pair.
	gen3 := rp("rp-1", "enforce", webLabels, []string{"3.3.3.3"}, nil)
	mustRpEvent(t, e, gen3, events.EventTypeUpdate)
	assertSharedPointer(t, e, "rp-1", "pod-1")
	wantLiveIps(t, f, []string{"3.3.3.3"}, []string{})

	attached := e.pods["pod-1"].attachedFilters["rp-1"]
	if !slices.Equal(attached.IPs.Allow, []string{"3.3.3.3"}) {
		t.Errorf("pod's attached rp holds stale ips %v, want [3.3.3.3]", attached.IPs.Allow)
	}

	// the delete path reads the IPs off the pointer the pod holds, so a stale
	// pointer removes a previous generation's ips and leaks the current ones.
	f.reset()
	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)
	wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair([]string{"3.3.3.3"}, nil)})
	wantLiveIps(t, f, []string{}, []string{})
	wantAttachedRps(t, e, "pod-1")
	if _, ok := e.rps["rp-1"]; ok {
		t.Error("rp-1 still tracked after delete")
	}
}

func assertSharedPointer(t *testing.T, e *EgressManager, rpUid, podUid string) {
	t.Helper()
	shared, ok := e.rps[rpUid]
	if !ok {
		t.Fatalf("rp %s is not tracked by the manager", rpUid)
	}
	held, ok := e.pods[podUid].attachedFilters[rpUid]
	if !ok {
		t.Fatalf("pod %s is not attached to rp %s", podUid, rpUid)
	}
	if shared != held {
		// deliberately not fatal: the follow up assertions show what the diverged
		// pointers do to the pod's programmed ip set
		t.Errorf("pod %s holds a different *EvaluationResult (%p) than e.rps[%s] (%p): the shared pointer was replaced",
			podUid, held, rpUid, shared)
	}
}

func TestRpCreatedIgnoresNonEnforceMode(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")

	mustRpEvent(t, e, rp("rp-1", "audit", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)

	if len(e.rps) != 0 {
		t.Errorf("audit mode policy was tracked: %v", e.rps)
	}
	wantPairs(t, "AddIps", f.adds, nil)
	wantAttachedRps(t, e, "pod-1")
	wantDefaultDeny(t, f, false)
}

func TestRpCreatedAppliesToMatchingPodsOnly(t *testing.T) {
	e, _ := newTestManager()
	web := addPod(t, e, "pod-web", webLabels, "/cg/web")
	api := addPod(t, e, "pod-api", apiLabels, "/cg/api")

	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"9.9.9.9", "*"}), events.EventTypeCreate)

	wantPairs(t, "AddIps(web)", web.adds, []ipPair{pair([]string{"1.1.1.1"}, []string{"9.9.9.9", "*"})})
	wantLiveIps(t, web, []string{"1.1.1.1"}, []string{"9.9.9.9"})
	wantDefaultDeny(t, web, true)
	wantDefaultDenyOwners(t, e, "pod-web", "rp-1")
	wantAttachedRps(t, e, "pod-web", "rp-1")

	wantPairs(t, "AddIps(api)", api.adds, nil)
	wantDefaultDeny(t, api, false)
	wantAttachedRps(t, e, "pod-api")
}

func TestRpUpdatedUnknownUidRoutesToCreate(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")

	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeUpdate)

	if _, ok := e.rps["rp-1"]; !ok {
		t.Fatal("update for an unknown uid did not register the policy")
	}
	wantPairs(t, "AddIps", f.adds, []ipPair{pair([]string{"1.1.1.1"}, nil)})
	assertSharedPointer(t, e, "rp-1", "pod-1")
}

func TestRpUpdatedLeavingEnforceModeTearsDown(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)
	f.reset()

	mustRpEvent(t, e, rp("rp-1", "audit", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeUpdate)

	if _, ok := e.rps["rp-1"]; ok {
		t.Error("policy still tracked after leaving enforce mode")
	}
	wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair([]string{"1.1.1.1"}, []string{"*"})})
	wantLiveIps(t, f, []string{}, []string{})
	wantDefaultDeny(t, f, false)
	wantDefaultDenyOwners(t, e, "pod-1")
	wantAttachedRps(t, e, "pod-1")
}

// the detach branch must use the copy of the old ips taken before currentRp.IPs
// is overwritten with the incoming generation, otherwise it deletes the new ips
// and leaks the ones actually programmed into the map.
func TestRpUpdatedDetachUsesCopiedOldIps(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1", "2.2.2.2"}, []string{"8.8.8.8"}), events.EventTypeCreate)
	f.reset()

	// selector moves off this pod AND the ip set changes at the same time
	mustRpEvent(t, e, rp("rp-1", "enforce", apiLabels, []string{"3.3.3.3"}, nil), events.EventTypeUpdate)

	wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair([]string{"1.1.1.1", "2.2.2.2"}, []string{"8.8.8.8"})})
	wantPairs(t, "AddIps", f.adds, nil)
	wantLiveIps(t, f, []string{}, []string{})
	wantAttachedRps(t, e, "pod-1")
	// the policy itself stays tracked, only the attachment went away
	if _, ok := e.rps["rp-1"]; !ok {
		t.Error("policy should still be tracked after a selector change")
	}
}

func TestRpUpdatedAppliesExactIpDiff(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1", "2.2.2.2"}, []string{"8.8.8.8"}), events.EventTypeCreate)
	f.reset()

	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"2.2.2.2", "3.3.3.3"}, []string{"8.8.8.8", "9.9.9.9"}), events.EventTypeUpdate)

	wantPairs(t, "AddIps", f.adds, []ipPair{pair([]string{"3.3.3.3"}, []string{"9.9.9.9"})})
	wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair([]string{"1.1.1.1"}, nil)})
	wantLiveIps(t, f, []string{"2.2.2.2", "3.3.3.3"}, []string{"8.8.8.8", "9.9.9.9"})
	if len(f.toggles) != 0 {
		t.Errorf("default deny flag touched without a wildcard change: %v", f.toggles)
	}
}

func TestRpUpdatedNoDiffStillMatchingIsNoop(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"8.8.8.8"}), events.EventTypeCreate)
	f.reset()

	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"8.8.8.8"}), events.EventTypeUpdate)

	wantPairs(t, "AddIps", f.adds, nil)
	wantPairs(t, "DeleteIps", f.deletes, nil)
	if len(f.toggles) != 0 {
		t.Errorf("unexpected flag toggles on a no-op update: %v", f.toggles)
	}
	wantLiveIps(t, f, []string{"1.1.1.1"}, []string{"8.8.8.8"})
}

func TestRpUpdatedWildcardAddedThenRemoved(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	wantDefaultDeny(t, f, false)
	f.reset()

	// "*" enters the deny list
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeUpdate)
	wantPairs(t, "AddIps", f.adds, []ipPair{pair(nil, []string{"*"})})
	wantDefaultDeny(t, f, true)
	wantDefaultDenyOwners(t, e, "pod-1", "rp-1")
	f.reset()

	// "*" leaves the deny list
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeUpdate)
	wantPairs(t, "DeleteIps", f.deletes, []ipPair{pair(nil, []string{"*"})})
	wantDefaultDeny(t, f, false)
	wantDefaultDenyOwners(t, e, "pod-1")
	wantLiveIps(t, f, []string{"1.1.1.1"}, []string{})
}

func TestRpUpdatedNewlyMatchedPodGetsFullIpSetAndSharedPointer(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", apiLabels, "/cg/pod-1")
	// initially selects a different pod set
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)
	wantAttachedRps(t, e, "pod-1")
	f.reset()

	mustRpEvent(t, e, rp("rp-1", "enforce", apiLabels, []string{"1.1.1.1", "2.2.2.2"}, []string{"*"}), events.EventTypeUpdate)

	wantPairs(t, "AddIps", f.adds, []ipPair{pair([]string{"1.1.1.1", "2.2.2.2"}, []string{"*"})})
	wantDefaultDeny(t, f, true)
	wantDefaultDenyOwners(t, e, "pod-1", "rp-1")
	assertSharedPointer(t, e, "rp-1", "pod-1")
}

// default deny is reference counted per pod: the flag may only clear when the
// last policy asking for it is gone.
func TestDefaultDenyRefcountAcrossPolicies(t *testing.T) {
	tests := []struct {
		name string
		// drop removes the wildcard contribution of the named policy
		drop func(t *testing.T, e *EgressManager, uid string)
	}{
		{
			name: "policy deleted",
			drop: func(t *testing.T, e *EgressManager, uid string) {
				mustRpEvent(t, e, deleteEvent(uid), events.EventTypeDelete)
			},
		},
		{
			name: "wildcard removed by update",
			drop: func(t *testing.T, e *EgressManager, uid string) {
				mustRpEvent(t, e, rp(uid, "enforce", webLabels, nil, []string{"7.7.7.7"}), events.EventTypeUpdate)
			},
		},
		{
			name: "selector no longer matches",
			drop: func(t *testing.T, e *EgressManager, uid string) {
				mustRpEvent(t, e, rp(uid, "enforce", apiLabels, nil, []string{"*"}), events.EventTypeUpdate)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newTestManager()
			f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
			mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, nil, []string{"*"}), events.EventTypeCreate)
			mustRpEvent(t, e, rp("rp-2", "enforce", webLabels, nil, []string{"*"}), events.EventTypeCreate)
			wantDefaultDeny(t, f, true)
			wantDefaultDenyOwners(t, e, "pod-1", "rp-1", "rp-2")

			tc.drop(t, e, "rp-1")
			wantDefaultDeny(t, f, true)
			wantDefaultDenyOwners(t, e, "pod-1", "rp-2")
			for _, tg := range f.toggles {
				if !tg.val {
					t.Fatalf("default deny was cleared while rp-2 still requires it (toggles: %v)", f.toggles)
				}
			}

			tc.drop(t, e, "rp-2")
			wantDefaultDeny(t, f, false)
			wantDefaultDenyOwners(t, e, "pod-1")
		})
	}
}

func TestRpDeletedRemovesAttachedIpsPerPod(t *testing.T) {
	e, _ := newTestManager()
	web := addPod(t, e, "pod-web", webLabels, "/cg/web")
	api := addPod(t, e, "pod-api", apiLabels, "/cg/api")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, []string{"*"}), events.EventTypeCreate)
	web.reset()
	api.reset()

	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)

	wantPairs(t, "DeleteIps(web)", web.deletes, []ipPair{pair([]string{"1.1.1.1"}, []string{"*"})})
	wantLiveIps(t, web, []string{}, []string{})
	wantDefaultDeny(t, web, false)
	wantAttachedRps(t, e, "pod-web")

	// a pod that was never attached must not be touched at all
	wantPairs(t, "DeleteIps(api)", api.deletes, nil)
	if len(api.toggles) != 0 {
		t.Errorf("unattached pod's flags were touched: %v", api.toggles)
	}
}

func TestRpDeletedUnknownUidIsNoop(t *testing.T) {
	e, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/pod-1")
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), events.EventTypeCreate)
	f.reset()

	mustRpEvent(t, e, deleteEvent("rp-unknown"), events.EventTypeDelete)

	wantPairs(t, "DeleteIps", f.deletes, nil)
	if len(f.toggles) != 0 {
		t.Errorf("flags touched deleting an unknown policy: %v", f.toggles)
	}
	wantAttachedRps(t, e, "pod-1", "rp-1")
	wantLiveIps(t, f, []string{"1.1.1.1"}, []string{})
}
