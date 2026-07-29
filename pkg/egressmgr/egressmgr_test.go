package egressmgr

import (
	"fmt"
	"sync"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/events"
)

func TestRuntimePolicyEventRejectsUnknownType(t *testing.T) {
	e, _, _ := newTestManager()
	f := addPod(t, e, "pod-1", webLabels, "/cg/a")

	if err := e.RuntimePolicyEvent(rp("rp-1", "enforce", webLabels, []string{"1.1.1.1"}, nil), "resync"); err == nil {
		t.Fatal("expected an error for an unknown runtime policy event type")
	}
	if len(e.rps) != 0 {
		t.Errorf("policy was applied for an unknown event type: %v", e.rps)
	}
	wantPairs(t, "AddIps", f.adds, nil)
}

func TestPodEventRejectsUnknownType(t *testing.T) {
	e, factory, _ := newTestManager()

	if err := e.PodEvent(makePod("pod-1", webLabels), cgInfos("/cg/a"), "resync"); err == nil {
		t.Fatal("expected an error for an unknown pod event type")
	}
	if len(e.pods) != 0 {
		t.Errorf("pod was registered for an unknown event type: %v", e.pods)
	}
	if len(factory.created) != 0 {
		t.Errorf("a filter was created for an unknown event type: %d", len(factory.created))
	}
}

// walks a realistic sequence, then asserts that tearing the policies down empties
// every pod's ip set, clears the default deny flag and leaves no cross references
// in either direction.
func TestFullLifecycleLeavesNoDanglingState(t *testing.T) {
	e, _, _ := newTestManager()

	// 1. two pods exist before any policy
	web := addPod(t, e, "pod-web", webLabels, "/cg/web")
	api := addPod(t, e, "pod-api", apiLabels, "/cg/api")
	wantLiveIps(t, web, []string{}, []string{})
	wantLiveIps(t, api, []string{}, []string{})

	// 2. a policy selecting only app=web, with a default deny
	mustRpEvent(t, e, rp("rp-1", "enforce", webLabels, []string{"1.1.1.1", "2.2.2.2"}, []string{"*"}), events.EventTypeCreate)
	wantLiveIps(t, web, []string{"1.1.1.1", "2.2.2.2"}, []string{})
	wantDefaultDeny(t, web, true)
	wantLiveIps(t, api, []string{}, []string{})
	wantDefaultDeny(t, api, false)

	// 3. a cluster wide policy, also with a default deny
	mustRpEvent(t, e, rp("rp-2", "enforce", nil, []string{"9.9.9.9"}, []string{"*"}), events.EventTypeCreate)
	wantLiveIps(t, web, []string{"1.1.1.1", "2.2.2.2", "9.9.9.9"}, []string{})
	wantLiveIps(t, api, []string{"9.9.9.9"}, []string{})
	wantDefaultDenyOwners(t, e, "pod-web", "rp-1", "rp-2")
	wantDefaultDenyOwners(t, e, "pod-api", "rp-2")

	// 4. rp-1 moves to app=api and changes its ip set at the same time
	mustRpEvent(t, e, rp("rp-1", "enforce", apiLabels, []string{"2.2.2.2", "3.3.3.3"}, []string{"*"}), events.EventTypeUpdate)
	wantLiveIps(t, web, []string{"9.9.9.9"}, []string{})
	wantDefaultDeny(t, web, true) // rp-2 still requires it
	wantDefaultDenyOwners(t, e, "pod-web", "rp-2")
	wantAttachedRps(t, e, "pod-web", "rp-2")
	wantLiveIps(t, api, []string{"2.2.2.2", "3.3.3.3", "9.9.9.9"}, []string{})
	wantAttachedRps(t, e, "pod-api", "rp-1", "rp-2")
	assertSharedPointer(t, e, "rp-1", "pod-api")

	// 5. pod-web is relabelled in place. the update path refreshes the labels and
	// re-evaluates every tracked selector, so the pod picks rp-1 up without a
	// delete/create pair.
	relabelPod(t, e, "pod-web", apiLabels, "/cg/web")
	wantLiveIps(t, web, []string{"2.2.2.2", "3.3.3.3", "9.9.9.9"}, []string{})
	wantDefaultDeny(t, web, true)
	wantAttachedRps(t, e, "pod-web", "rp-1", "rp-2")
	assertSharedPointer(t, e, "rp-1", "pod-web")

	// 6. rp-1 goes away. every pod keeps exactly rp-2's contribution.
	mustRpEvent(t, e, deleteEvent("rp-1"), events.EventTypeDelete)
	for uid, f := range map[string]*fakeFilter{"pod-web": web, "pod-api": api} {
		wantLiveIps(t, f, []string{"9.9.9.9"}, []string{})
		wantDefaultDeny(t, f, true)
		wantAttachedRps(t, e, uid, "rp-2")
		wantDefaultDenyOwners(t, e, uid, "rp-2")
	}

	// 7. rp-2 goes away: nothing may be left programmed or referenced
	mustRpEvent(t, e, deleteEvent("rp-2"), events.EventTypeDelete)
	if len(e.rps) != 0 {
		t.Errorf("policies still tracked: %v", e.rps)
	}
	for uid, f := range map[string]*fakeFilter{"pod-web": web, "pod-api": api} {
		wantLiveIps(t, f, []string{}, []string{})
		wantDefaultDeny(t, f, false)
		wantAttachedRps(t, e, uid)
		wantDefaultDenyOwners(t, e, uid)
	}
	if len(e.pods) != 2 {
		t.Errorf("pods tracked: got %d, want 2", len(e.pods))
	}
}

// the pod informer and the policy informer call into the manager from different
// goroutines. both event streams run concurrently (meaningful under -race) and the
// cross reference invariant is asserted afterwards: every attachment a pod holds
// is the pointer the manager tracks for that policy.
func TestConcurrentPodAndPolicyEventsKeepStateConsistent(t *testing.T) {
	e, _, _ := newTestManager()
	const n = 40

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			uid := fmt.Sprintf("pod-%d", i)
			if err := e.PodEvent(makePod(uid, webLabels), cgInfos("/cg/"+uid), events.EventTypeCreate); err != nil {
				t.Errorf("pod create %s: %v", uid, err)
			}
			// relabelling exercises the re-match path concurrently with the policy
			// stream
			if err := e.PodEvent(makePod(uid, apiLabels), cgInfos("/cg/"+uid), events.EventTypeUpdate); err != nil {
				t.Errorf("pod update %s: %v", uid, err)
			}
			if i%3 == 0 {
				if err := e.PodDeleted(uid); err != nil {
					t.Errorf("pod delete %s: %v", uid, err)
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			uid := fmt.Sprintf("rp-%d", i%4)
			ips := []string{fmt.Sprintf("10.0.0.%d", i)}
			mode := "enforce"
			if i%5 == 0 {
				mode = "monitor"
			}
			if err := e.RuntimePolicyEvent(rp(uid, mode, webLabels, ips, []string{"*"}), events.EventTypeUpdate); err != nil {
				t.Errorf("rp update %s: %v", uid, err)
			}
			if i%7 == 0 {
				if err := e.RuntimePolicyEvent(deleteEvent(uid), events.EventTypeDelete); err != nil {
					t.Errorf("rp delete %s: %v", uid, err)
				}
			}
		}
	}()

	wg.Wait()

	for podUid, pa := range e.pods {
		for rpUid, held := range pa.attachedFilters {
			tracked, ok := e.rps[rpUid]
			if !ok {
				t.Errorf("pod %s still references untracked policy %s", podUid, rpUid)
				continue
			}
			if tracked != held {
				t.Errorf("pod %s holds a stale pointer for policy %s", podUid, rpUid)
			}
		}
		for rpUid := range pa.defaultDeny {
			if _, ok := pa.attachedFilters[rpUid]; !ok {
				t.Errorf("pod %s keeps a default deny owner %s it is not attached to", podUid, rpUid)
			}
		}
	}
}
