package lsmmgr

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"
)

// TestScenario_PolicyAndPodLifecycle walks a realistic event sequence and checks the
// bidirectional bookkeeping after every step, plus the enforcer state the sequence
// should have produced.
func TestScenario_PolicyAndPodLifecycle(t *testing.T) {
	h := newHarness(t)
	webSel := selFor(map[string]string{"app": "web"})
	dbSel := selFor(map[string]string{"app": "db"})

	step := func(name string, fn func() error) {
		t.Helper()
		if err := fn(); err != nil {
			t.Fatalf("step %q: %v", name, err)
		}
		assertInvariant(t, h.l)
	}

	// 1. policy first, no pods yet
	step("create rp1", func() error {
		return h.l.RuntimePolicyEvent(result("rp1", "enforce", webSel,
			pair(nil, []string{"/etc/shadow"}), pair([]string{"/bin/ls"}, nil)), events.EventTypeCreate)
	})
	openEnf, execEnf := h.enf("rp1", open), h.enf("rp1", exec)

	// 2. two pods show up, one matching
	step("create podWeb", func() error {
		return h.l.PodEvent(testPod("podWeb", map[string]string{"app": "web"}), cgs(11, 12), events.EventTypeCreate)
	})
	step("create podDb", func() error {
		return h.l.PodEvent(testPod("podDb", map[string]string{"app": "db"}), cgs(21), events.EventTypeCreate)
	})
	if got := openEnf.cgidSet(); !slices.Equal(got, []uint64{11, 12}) {
		t.Fatalf("open cgids = %v, want [11 12]", got)
	}

	// 3. a second policy targets the db pod
	step("create rp2", func() error {
		return h.l.RuntimePolicyEvent(result("rp2", "enforce", dbSel, pair(nil, []string{"*"}), nil), events.EventTypeCreate)
	})
	rp2Enf := h.enf("rp2", open)
	if !rp2Enf.denyAll {
		t.Error("rp2 open enforcer default deny = false, want true")
	}

	// 4. rp1's selector moves to the db pod: podWeb detaches, podDb attaches to both policies
	step("retarget rp1 to db", func() error {
		return h.l.RuntimePolicyEvent(result("rp1", "enforce", dbSel,
			pair(nil, []string{"/etc/shadow"}), pair([]string{"/bin/ls"}, nil)), events.EventTypeUpdate)
	})
	if got := openEnf.cgidSet(); !slices.Equal(got, []uint64{21}) {
		t.Fatalf("open cgids after retarget = %v, want [21]", got)
	}
	if got := attachedPolicyUIDs(h.l.pods["podDb"]); !slices.Equal(got, []string{"rp1", "rp2"}) {
		t.Fatalf("podDb attachedLsms = %v, want [rp1 rp2]", got)
	}
	if got := attachedPolicyUIDs(h.l.pods["podWeb"]); len(got) != 0 {
		t.Fatalf("podWeb attachedLsms = %v, want empty", got)
	}

	// 5. rp1 drops exec enforcement and changes its open target set
	step("rp1 drops exec", func() error {
		return h.l.RuntimePolicyEvent(result("rp1", "enforce", dbSel,
			pair(nil, []string{"/etc/passwd", "*"}), pair(nil, nil)), events.EventTypeUpdate)
	})
	if execEnf.closeCount != 1 {
		t.Fatalf("exec enforcer Close called %d times, want 1", execEnf.closeCount)
	}
	if got := progTypes(h.l.lsmAttachments["rp1"]); !slices.Equal(got, []string{open}) {
		t.Fatalf("rp1 prog types = %v, want [%s]", got, open)
	}
	if got := openEnf.denySet(); !slices.Equal(got, []string{"*", "/etc/passwd"}) {
		t.Fatalf("open deny set = %v, want [* /etc/passwd]", got)
	}
	if !openEnf.denyAll {
		t.Fatal("open default deny = false, want true")
	}

	// 6. the db pod's containers churn
	step("podDb cgid churn", func() error {
		return h.l.PodEvent(testPod("podDb", map[string]string{"app": "db"}), cgs(22, 23), events.EventTypeUpdate)
	})
	for name, f := range map[string]*fakeEnforcer{"rp1": openEnf, "rp2": rp2Enf} {
		if got := f.cgidSet(); !slices.Equal(got, []uint64{22, 23}) {
			t.Fatalf("%s cgids after churn = %v, want [22 23]", name, got)
		}
	}

	// 7. the db pod goes away
	step("delete podDb", func() error {
		return h.l.PodEvent(testPod("podDb", nil), nil, events.EventTypeDelete)
	})
	for name, f := range map[string]*fakeEnforcer{"rp1": openEnf, "rp2": rp2Enf} {
		if got := f.cgidSet(); len(got) != 0 {
			t.Fatalf("%s cgids after pod delete = %v, want empty", name, got)
		}
	}
	for _, uid := range []string{"rp1", "rp2"} {
		if got := attachedPodUIDs(h.l.lsmAttachments[uid]); len(got) != 0 {
			t.Fatalf("%s attached pods = %v, want empty", uid, got)
		}
	}

	// 8. and finally both policies are deleted
	step("delete rp1", func() error {
		return h.l.RuntimePolicyEvent(&compiler.EvaluationResult{UID: "rp1"}, events.EventTypeDelete)
	})
	step("delete rp2", func() error {
		return h.l.RuntimePolicyEvent(&compiler.EvaluationResult{UID: "rp2"}, events.EventTypeDelete)
	})
	if len(h.l.lsmAttachments) != 0 {
		t.Fatalf("attachments = %v, want empty", h.l.lsmAttachments)
	}
	if openEnf.closeCount != 1 || rp2Enf.closeCount != 1 {
		t.Fatalf("close counts = rp1 open:%d rp2 open:%d, want 1 each", openEnf.closeCount, rp2Enf.closeCount)
	}
	// podWeb survived everything and must hold no stale policy pointers
	if got := attachedPolicyUIDs(h.l.pods["podWeb"]); len(got) != 0 {
		t.Fatalf("podWeb attachedLsms = %v, want empty", got)
	}
	for _, f := range []*fakeEnforcer{openEnf, execEnf, rp2Enf} {
		if len(f.usedClosed) != 0 {
			t.Fatalf("enforcer %s used after Close: %v", f.target, f.usedClosed)
		}
	}
}

// TestConcurrent_PodAndPolicyEvents drives the pod and policy informer entry points
// from separate goroutines (both real informers run in parallel). Beyond -race, the
// end state is deterministic because the manager serializes every event: a pod is
// attached to a policy iff its labels match, whatever order the events arrived in.
func TestConcurrent_PodAndPolicyEvents(t *testing.T) {
	const (
		numPods     = 12
		numPolicies = 6
	)
	h := newHarness(t)

	labelFor := func(i int) map[string]string {
		if i%2 == 0 {
			return map[string]string{"app": "web"}
		}
		return map[string]string{"app": "db"}
	}
	selForPolicy := func(i int) map[string]string {
		if i%2 == 0 {
			return map[string]string{"app": "web"}
		}
		return map[string]string{"app": "db"}
	}
	podUID := func(i int) string { return fmt.Sprintf("pod%02d", i) }
	rpUID := func(i int) string { return fmt.Sprintf("rp%02d", i) }
	matches := func(podIdx, rpIdx int) bool { return podIdx%2 == rpIdx%2 }

	// phase 1: pods and policies are created concurrently
	var wg sync.WaitGroup
	errCh := make(chan error, numPods+numPolicies)
	for i := range numPods {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.l.PodEvent(testPod(podUID(i), labelFor(i)), cgs(uint64(100+i)), events.EventTypeCreate); err != nil {
				errCh <- err
			}
		}()
	}
	for i := range numPolicies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rp := result(rpUID(i), "enforce", selFor(selForPolicy(i)), pair(nil, []string{"/etc/shadow"}), nil)
			if err := h.l.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	drainErrs(t, errCh)
	assertInvariant(t, h.l)
	assertConcurrentState(t, h, numPods, numPolicies, matches, rpUID, podUID, func(i int) uint64 { return uint64(100 + i) })

	// phase 2: pod cgids churn while the policies get new target paths, concurrently
	for i := range numPods {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.l.PodEvent(testPod(podUID(i), labelFor(i)), cgs(uint64(200+i)), events.EventTypeUpdate); err != nil {
				errCh <- err
			}
		}()
	}
	for i := range numPolicies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rp := result(rpUID(i), "enforce", selFor(selForPolicy(i)), pair(nil, []string{"/etc/shadow", "/etc/passwd"}), nil)
			if err := h.l.RuntimePolicyEvent(rp, events.EventTypeUpdate); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	drainErrs(t, errCh)
	assertInvariant(t, h.l)
	assertConcurrentState(t, h, numPods, numPolicies, matches, rpUID, podUID, func(i int) uint64 { return uint64(200 + i) })
	for i := range numPolicies {
		if got := h.enf(rpUID(i), open).denySet(); !slices.Equal(got, []string{"/etc/passwd", "/etc/shadow"}) {
			t.Errorf("%s deny set = %v, want [/etc/passwd /etc/shadow]", rpUID(i), got)
		}
	}

	// phase 3: half the pods are deleted while half the policies are deleted
	for i := range numPods {
		if i >= numPods/2 {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.l.PodEvent(testPod(podUID(i), labelFor(i)), nil, events.EventTypeDelete); err != nil {
				errCh <- err
			}
		}()
	}
	for i := range numPolicies {
		if i >= numPolicies/2 {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.l.RuntimePolicyEvent(&compiler.EvaluationResult{UID: rpUID(i)}, events.EventTypeDelete); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	drainErrs(t, errCh)
	assertInvariant(t, h.l)
	if len(h.l.pods) != numPods-numPods/2 {
		t.Errorf("pods = %d, want %d", len(h.l.pods), numPods-numPods/2)
	}
	if len(h.l.lsmAttachments) != numPolicies-numPolicies/2 {
		t.Errorf("attachments = %d, want %d", len(h.l.lsmAttachments), numPolicies-numPolicies/2)
	}
}

func drainErrs(t *testing.T, errCh chan error) {
	t.Helper()
	for {
		select {
		case err := <-errCh:
			t.Errorf("event returned an error: %v", err)
		default:
			return
		}
	}
}

func assertConcurrentState(
	t *testing.T,
	h *harness,
	numPods, numPolicies int,
	matches func(podIdx, rpIdx int) bool,
	rpUID, podUID func(int) string,
	cgidFor func(int) uint64,
) {
	t.Helper()
	if len(h.l.pods) != numPods {
		t.Fatalf("pods = %d, want %d", len(h.l.pods), numPods)
	}
	if len(h.l.lsmAttachments) != numPolicies {
		t.Fatalf("attachments = %d, want %d", len(h.l.lsmAttachments), numPolicies)
	}
	for i := range numPolicies {
		var wantPods []string
		var wantCgids []uint64
		for j := range numPods {
			if matches(j, i) {
				wantPods = append(wantPods, podUID(j))
				wantCgids = append(wantCgids, cgidFor(j))
			}
		}
		slices.Sort(wantPods)
		slices.Sort(wantCgids)
		la := h.l.lsmAttachments[rpUID(i)]
		if got := attachedPodUIDs(la); !slices.Equal(got, wantPods) {
			t.Errorf("%s attached pods = %v, want %v", rpUID(i), got, wantPods)
		}
		if got := h.enf(rpUID(i), open).cgidSet(); !slices.Equal(got, wantCgids) {
			t.Errorf("%s enforcer cgids = %v, want %v", rpUID(i), got, wantCgids)
		}
	}
}
