package lsmmgr

import (
	"fmt"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

const (
	open = lsm.PROG_TYPE_LSM_OPEN
	exec = lsm.PROG_TYPE_LSM_EXEC
)

// fixedTime is the clock every harness runs on: never sleep, never read the wall
// clock in a unit test.
var fixedTime = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

// fakeEnforcer records every call the manager makes on it and also maintains the
// effective state those calls would produce in the bpf maps (cgid set, allow/deny
// path sets, default deny, observed cgids). tests assert on both: the exact
// arguments of the diff operations, and the resulting state.
type fakeEnforcer struct {
	mu     sync.Mutex
	target string

	addTargets  []compiler.AllowDenyPair
	delTargets  []compiler.AllowDenyPair
	addCgids    [][]uint64
	delCgids    [][]uint64
	enableObs   [][]uint64
	disableObs  [][]uint64
	readCalls   [][]uint64
	defaultDeny []bool
	attachCount int
	closeCount  int

	// effective state
	allow      map[string]struct{}
	deny       map[string]struct{}
	cgids      map[uint64]struct{}
	observing  map[uint64]struct{}
	denyAll    bool
	closed     bool
	usedClosed []string // methods called after Close, must always be empty

	// pending are the kernel-side counts ReadEvents will hand back (and reset).
	pending map[uint64]map[lsm.PathEventKey]uint32

	errs map[string]error
}

func newFakeEnforcer(target string, errs map[string]error) *fakeEnforcer {
	if errs == nil {
		errs = map[string]error{}
	}
	return &fakeEnforcer{
		target:    target,
		allow:     map[string]struct{}{},
		deny:      map[string]struct{}{},
		cgids:     map[uint64]struct{}{},
		observing: map[uint64]struct{}{},
		pending:   map[uint64]map[lsm.PathEventKey]uint32{},
		errs:      errs,
	}
}

func (f *fakeEnforcer) note(method string) error {
	if f.closed {
		f.usedClosed = append(f.usedClosed, method)
	}
	return f.errs[method]
}

func (f *fakeEnforcer) Attach() (link.Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attachCount++
	return nil, f.note("Attach")
}

func (f *fakeEnforcer) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := f.note("Close")
	f.closeCount++
	f.closed = true
	return err
}

func (f *fakeEnforcer) AddCgids(cgids []uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCgids = append(f.addCgids, slices.Clone(cgids))
	for _, c := range cgids {
		f.cgids[c] = struct{}{}
	}
	return f.note("AddCgids")
}

func (f *fakeEnforcer) DeleteCgids(cgids []uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delCgids = append(f.delCgids, slices.Clone(cgids))
	for _, c := range cgids {
		delete(f.cgids, c)
	}
	return f.note("DeleteCgids")
}

func (f *fakeEnforcer) AddTargets(paths *compiler.AllowDenyPair) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addTargets = append(f.addTargets, clonePair(paths))
	for _, p := range paths.Allow {
		f.allow[p] = struct{}{}
	}
	for _, p := range paths.Deny {
		f.deny[p] = struct{}{}
	}
	return f.note("AddTargets")
}

func (f *fakeEnforcer) DeleteTargets(paths *compiler.AllowDenyPair) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delTargets = append(f.delTargets, clonePair(paths))
	for _, p := range paths.Allow {
		delete(f.allow, p)
	}
	for _, p := range paths.Deny {
		delete(f.deny, p)
	}
	return f.note("DeleteTargets")
}

func (f *fakeEnforcer) SetDefaultDeny(val bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.defaultDeny = append(f.defaultDeny, val)
	f.denyAll = val
	return f.note("SetDefaultDeny")
}

func (f *fakeEnforcer) EnableObservation(cgids []uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableObs = append(f.enableObs, slices.Clone(cgids))
	for _, c := range cgids {
		f.observing[c] = struct{}{}
	}
	return f.note("EnableObservation")
}

func (f *fakeEnforcer) DisableObservation(cgids []uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disableObs = append(f.disableObs, slices.Clone(cgids))
	for _, c := range cgids {
		delete(f.observing, c)
		delete(f.pending, c)
	}
	return f.note("DisableObservation")
}

// ReadEvents drains the seeded counts for the cgids it is asked about, mirroring
// the real read-and-reset semantics.
func (f *fakeEnforcer) ReadEvents(cgids []uint64) (map[uint64]map[lsm.PathEventKey]uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readCalls = append(f.readCalls, slices.Clone(cgids))
	out := map[uint64]map[lsm.PathEventKey]uint32{}
	for _, c := range cgids {
		counts, ok := f.pending[c]
		if !ok || len(counts) == 0 {
			continue
		}
		out[c] = counts
		delete(f.pending, c)
	}
	return out, f.note("ReadEvents")
}

// seed puts kernel-side allow-verdict counts in place for the next ReadEvents
// call. seedVerdict is the general form.
func (f *fakeEnforcer) seed(cgid uint64, counts map[string]uint32) {
	for p, c := range counts {
		f.seedVerdict(cgid, lsm.PathEventKey{Path: p, Verdict: runtimeevent.VerdictAllow}, c)
	}
}

// seedVerdict puts one kernel-side (path, verdict) count in place for the next
// ReadEvents call.
func (f *fakeEnforcer) seedVerdict(cgid uint64, key lsm.PathEventKey, count uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending[cgid] == nil {
		f.pending[cgid] = map[lsm.PathEventKey]uint32{}
	}
	f.pending[cgid][key] = count
}

// reset clears the recorded call log but keeps the effective state, so a test can
// isolate the calls made by a single event.
func (f *fakeEnforcer) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addTargets = nil
	f.delTargets = nil
	f.addCgids = nil
	f.delCgids = nil
	f.enableObs = nil
	f.disableObs = nil
	f.readCalls = nil
	f.defaultDeny = nil
}

func (f *fakeEnforcer) cgidSet() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sortedU64(f.cgids)
}

func (f *fakeEnforcer) observedSet() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sortedU64(f.observing)
}

func (f *fakeEnforcer) denySet() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sortedKeys(f.deny)
}

func (f *fakeEnforcer) allowSet() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sortedKeys(f.allow)
}

func sortedU64(m map[uint64]struct{}) []uint64 {
	out := make([]uint64, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clonePair(p *compiler.AllowDenyPair) compiler.AllowDenyPair {
	if p == nil {
		return compiler.AllowDenyPair{}
	}
	return compiler.AllowDenyPair{Allow: slices.Clone(p.Allow), Deny: slices.Clone(p.Deny)}
}

// fakeStatus records the policy conditions the manager reports.
type fakeStatus struct {
	mu         sync.Mutex
	conditions map[string][]metav1.Condition
	violations map[string][]string
}

func newFakeStatus() *fakeStatus {
	return &fakeStatus{
		conditions: map[string][]metav1.Condition{},
		violations: map[string][]string{},
	}
}

func (s *fakeStatus) RecordViolation(policyUID, podUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.violations[policyUID] = append(s.violations[policyUID], podUID)
}

func (s *fakeStatus) RecordCondition(policyUID string, cond metav1.Condition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conditions[policyUID] = append(s.conditions[policyUID], cond)
}

func (s *fakeStatus) conditionTypes(policyUID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.conditions[policyUID]))
	for _, c := range s.conditions[policyUID] {
		out = append(out, c.Type)
	}
	return out
}

// harness wires an LsmManager to fake enforcers and keeps a record of every
// enforcer that got created.
type harness struct {
	t      *testing.T
	l      *LsmManager
	status *fakeStatus

	mu        sync.Mutex
	created   []*fakeEnforcer
	createErr map[string]error
	methodErr map[string]map[string]error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		t:         t,
		status:    newFakeStatus(),
		createErr: map[string]error{},
		methodErr: map[string]map[string]error{},
	}
	factory := func(_ *logr.Logger, target string) (lsmEnforcer, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if err := h.createErr[target]; err != nil {
			return nil, err
		}
		errs := map[string]error{}
		for m, e := range h.methodErr[target] {
			errs[m] = e
		}
		f := newFakeEnforcer(target, errs)
		h.created = append(h.created, f)
		return f, nil
	}
	h.l = NewLsmManager(logr.Discard(), h.status,
		withEnforcerFactory(factory),
		WithClock(func() time.Time { return fixedTime }),
	)
	return h
}

// failCreate makes enforcer construction fail for a target.
func (h *harness) failCreate(target string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.createErr[target] = err
}

// failMethod makes a method fail on every enforcer created for a target afterwards.
func (h *harness) failMethod(target, method string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.methodErr[target] == nil {
		h.methodErr[target] = map[string]error{}
	}
	h.methodErr[target][method] = err
}

func (h *harness) createdCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.created)
}

func (h *harness) createdFor(target string) []*fakeEnforcer {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*fakeEnforcer
	for _, f := range h.created {
		if f.target == target {
			out = append(out, f)
		}
	}
	return out
}

// enf returns the enforcer currently attached for a policy/prog type.
func (h *harness) enf(rpUID, progType string) *fakeEnforcer {
	h.t.Helper()
	la, ok := h.l.lsmAttachments[rpUID]
	if !ok {
		h.t.Fatalf("no lsm attachment for policy %q", rpUID)
	}
	prog, ok := la.progs[progType]
	if !ok {
		h.t.Fatalf("no prog state for policy %q progType %q (have %v)", rpUID, progType, progTypes(la))
	}
	f, ok := prog.enf.(*fakeEnforcer)
	if !ok {
		h.t.Fatalf("enforcer for %q/%q is not a fake", rpUID, progType)
	}
	return f
}

func (h *harness) resetAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, f := range h.created {
		f.reset()
	}
}

func progTypes(la *lsmAttachment) []string {
	out := make([]string, 0, len(la.progs))
	for k := range la.progs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assertInvariant checks the bidirectional bookkeeping between attachedPods and
// attachedLsms: every reference in one direction must have its counterpart, and
// every referenced object must still be the live one held in the manager maps.
func assertInvariant(t *testing.T, l *LsmManager) {
	t.Helper()
	for rpUID, la := range l.lsmAttachments {
		for podUID, pod := range la.attachedPods {
			live, ok := l.pods[podUID]
			if !ok {
				t.Errorf("dangling reference: policy %q attached to pod %q which is not in l.pods", rpUID, podUID)
				continue
			}
			if live != pod {
				t.Errorf("stale pointer: policy %q holds a different podRepresentation for pod %q than l.pods", rpUID, podUID)
			}
			if pod.attachedLsms[rpUID] != la {
				t.Errorf("missing reverse pointer: pod %q does not point back at policy %q", podUID, rpUID)
			}
		}
	}
	for podUID, pod := range l.pods {
		for rpUID, la := range pod.attachedLsms {
			live, ok := l.lsmAttachments[rpUID]
			if !ok {
				t.Errorf("dangling reference: pod %q points at policy %q which is not in l.lsmAttachments", podUID, rpUID)
				continue
			}
			if live != la {
				t.Errorf("stale pointer: pod %q holds a different lsmAttachment for policy %q", podUID, rpUID)
			}
			if la.attachedPods[podUID] != pod {
				t.Errorf("missing forward pointer: policy %q does not point back at pod %q", rpUID, podUID)
			}
		}
	}
}

// ---- builders ----

func pair(allow, deny []string) *compiler.AllowDenyPair {
	return &compiler.AllowDenyPair{Allow: allow, Deny: deny}
}

func selFor(kv map[string]string) labels.Selector {
	sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: kv})
	if err != nil {
		panic(err)
	}
	return sel
}

func result(uid, mode string, sel labels.Selector, open, exec *compiler.AllowDenyPair) *compiler.EvaluationResult {
	return &compiler.EvaluationResult{
		UID:      uid,
		Name:     uid,
		Mode:     mode,
		Selector: sel,
		Open:     open,
		Exec:     exec,
	}
}

func testPod(uid string, lbls map[string]string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   uid,
			UID:    types.UID(uid),
			Labels: lbls,
		},
	}
}

func cgs(ids ...uint64) []*containers.ContainerCgroupInfo {
	out := make([]*containers.ContainerCgroupInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, &containers.ContainerCgroupInfo{ID: id, Path: fmt.Sprintf("/sys/fs/cgroup/%d", id)})
	}
	return out
}

// ---- assertions ----

func samePair(got compiler.AllowDenyPair, wantAllow, wantDeny []string) bool {
	return slices.Equal(got.Allow, wantAllow) && slices.Equal(got.Deny, wantDeny)
}

func assertPairCalls(t *testing.T, what string, got []compiler.AllowDenyPair, want []compiler.AllowDenyPair) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d calls %v, want %d calls %v", what, len(got), got, len(want), want)
	}
	for i := range got {
		if !samePair(got[i], want[i].Allow, want[i].Deny) {
			t.Errorf("%s call %d: got %+v, want %+v", what, i, got[i], want[i])
		}
	}
}

// assertCgidCalls compares recorded cgid calls ignoring the order of the calls
// themselves (the manager iterates maps) but not the contents of each call.
func assertCgidCalls(t *testing.T, what string, got [][]uint64, want [][]uint64) {
	t.Helper()
	norm := func(in [][]uint64) []string {
		out := make([]string, 0, len(in))
		for _, c := range in {
			s := slices.Clone(c)
			slices.Sort(s)
			out = append(out, fmt.Sprint(s))
		}
		sort.Strings(out)
		return out
	}
	g, w := norm(got), norm(want)
	if !slices.Equal(g, w) {
		t.Errorf("%s: got %v, want %v", what, g, w)
	}
}

func attachedPodUIDs(la *lsmAttachment) []string {
	out := make([]string, 0, len(la.attachedPods))
	for k := range la.attachedPods {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func attachedPolicyUIDs(pr *podRepresentation) []string {
	out := make([]string, 0, len(pr.attachedLsms))
	for k := range pr.attachedLsms {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
