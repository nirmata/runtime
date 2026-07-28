package lsmmgr

import (
	"context"
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
		return h.l.RuntimePolicyEvent(result("rp1", compiler.ModeEnforce, webSel,
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
	if got := openEnf.observedSet(); !slices.Equal(got, []uint64{11, 12}) {
		t.Fatalf("open observed cgids = %v, want [11 12]", got)
	}

	// 3. a second policy monitors the db pod: it must observe without programming
	step("create rp2 in monitor mode", func() error {
		return h.l.RuntimePolicyEvent(result("rp2", compiler.ModeMonitor, dbSel, pair(nil, []string{"*"}), nil), events.EventTypeCreate)
	})
	rp2Enf := h.enf("rp2", open)
	if rp2Enf.denyAll || len(rp2Enf.denySet()) != 0 {
		t.Errorf("rp2 (monitor) programmed maps: denyAll=%v deny=%v", rp2Enf.denyAll, rp2Enf.denySet())
	}
	if got := rp2Enf.observedSet(); !slices.Equal(got, []uint64{21}) {
		t.Errorf("rp2 observed cgids = %v, want [21]", got)
	}

	// 4. the observed paths of both policies are collected in one poll
	rp2Enf.seed(21, map[string]uint32{"/etc/shadow": 2})
	openEnf.seed(11, map[string]uint32{"/etc/hosts": 1})
	evs, err := h.l.CollectObservations(context.Background())
	if err != nil {
		t.Fatalf("CollectObservations: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("collected %d events, want 2 (one per policy): %+v", len(evs), evs)
	}

	// 5. rp1's selector moves to the db pod: podWeb detaches, podDb attaches
	step("retarget rp1 to db", func() error {
		return h.l.RuntimePolicyEvent(result("rp1", compiler.ModeEnforce, dbSel,
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

	// 6. podWeb is relabelled into rp1's new selector (#58): it must be picked up
	step("relabel podWeb to db", func() error {
		return h.l.PodEvent(testPod("podWeb", map[string]string{"app": "db"}), cgs(11, 12), events.EventTypeUpdate)
	})
	if got := openEnf.cgidSet(); !slices.Equal(got, []uint64{11, 12, 21}) {
		t.Fatalf("open cgids after relabel = %v, want [11 12 21]", got)
	}
	if got := attachedPolicyUIDs(h.l.pods["podWeb"]); !slices.Equal(got, []string{"rp1", "rp2"}) {
		t.Fatalf("podWeb attachedLsms after relabel = %v, want [rp1 rp2]", got)
	}

	// 7. rp1 drops exec enforcement and changes its open target set
	step("rp1 drops exec", func() error {
		return h.l.RuntimePolicyEvent(result("rp1", compiler.ModeEnforce, dbSel,
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

	// 8. the db pod's containers churn
	step("podDb cgid churn", func() error {
		return h.l.PodEvent(testPod("podDb", map[string]string{"app": "db"}), cgs(22, 23), events.EventTypeUpdate)
	})
	for name, f := range map[string]*fakeEnforcer{"rp1": openEnf, "rp2": rp2Enf} {
		if got := f.cgidSet(); !slices.Equal(got, []uint64{11, 12, 22, 23}) {
			t.Fatalf("%s cgids after churn = %v, want [11 12 22 23]", name, got)
		}
	}

	// 9. both pods go away
	step("delete podDb", func() error {
		return h.l.PodEvent(testPod("podDb", nil), nil, events.EventTypeDelete)
	})
	step("delete podWeb", func() error {
		return h.l.PodEvent(testPod("podWeb", nil), nil, events.EventTypeDelete)
	})
	for name, f := range map[string]*fakeEnforcer{"rp1": openEnf, "rp2": rp2Enf} {
		if got := f.cgidSet(); len(got) != 0 {
			t.Fatalf("%s cgids after pod delete = %v, want empty", name, got)
		}
		if got := f.observedSet(); len(got) != 0 {
			t.Fatalf("%s observed cgids after pod delete = %v, want empty", name, got)
		}
	}
	for _, uid := range []string{"rp1", "rp2"} {
		if got := attachedPodUIDs(h.l.lsmAttachments[uid]); len(got) != 0 {
			t.Fatalf("%s attached pods = %v, want empty", uid, got)
		}
	}

	// 10. and finally both policies are deleted
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
	modeFor := func(i int) string {
		// half the policies observe, half enforce
		if i%4 < 2 {
			return compiler.ModeEnforce
		}
		return compiler.ModeMonitor
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
			rp := result(rpUID(i), modeFor(i), selFor(selForPolicy(i)), pair(nil, []string{"/etc/shadow"}), nil)
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
			rp := result(rpUID(i), modeFor(i), selFor(selForPolicy(i)), pair(nil, []string{"/etc/shadow", "/etc/passwd"}), nil)
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
		want := []string{"/etc/passwd", "/etc/shadow"}
		if compiler.IsObserveMode(modeFor(i)) {
			want = nil
		}
		if got := h.enf(rpUID(i), open).denySet(); !slices.Equal(got, want) {
			t.Errorf("%s deny set = %v, want %v", rpUID(i), got, want)
		}
	}

	// phase 3: observations are collected while pod events keep arriving
	for i := range numPolicies {
		h.enf(rpUID(i), open).seed(uint64(200+i), map[string]uint32{"/etc/shadow": 1})
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := h.l.CollectObservations(context.Background()); err != nil {
			errCh <- err
		}
	}()
	for i := range numPods {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.l.PodEvent(testPod(podUID(i), labelFor(i)), cgs(uint64(300+i)), events.EventTypeUpdate); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	drainErrs(t, errCh)
	assertInvariant(t, h.l)

	// phase 4: half the pods are deleted while half the policies are deleted
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
		f := h.enf(rpUID(i), open)
		if got := f.cgidSet(); !slices.Equal(got, wantCgids) {
			t.Errorf("%s enforcer cgids = %v, want %v", rpUID(i), got, wantCgids)
		}
		// observation is on for every attached cgid, in both modes
		if got := f.observedSet(); !slices.Equal(got, wantCgids) {
			t.Errorf("%s observed cgids = %v, want %v", rpUID(i), got, wantCgids)
		}
	}
}
