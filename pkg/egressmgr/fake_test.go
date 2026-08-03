package egressmgr

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

// the fixed clock every test manager runs on, so conditions and events can be
// compared without stripping timestamps.
var testTime = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

// a value-copy snapshot of an *compiler.AllowDenyPair taken at call time. The
// manager mutates the pairs it owns, so recording the pointer would let later
// mutations rewrite history.
type ipPair struct {
	Allow []string
	Deny  []string
}

func snapshotPair(p *compiler.AllowDenyPair) ipPair {
	if p == nil {
		return ipPair{}
	}
	return ipPair{Allow: slices.Clone(p.Allow), Deny: slices.Clone(p.Deny)}
}

func pair(allow, deny []string) ipPair {
	return ipPair{Allow: allow, Deny: deny}
}

type flagToggle struct {
	idx uint8
	val bool
}

// fakeFilter records every call the manager makes and models the state the bpf
// maps would end up in: the ip maps behave as sets and the flags map holds the
// default-deny and observe bits. Target parsing goes through the real
// egressfilter.ParseTargets, so unsupported targets are rejected here as the
// kernel-side filter rejects them.
type fakeFilter struct {
	adds     []ipPair
	deletes  []ipPair
	toggles  []flagToggle
	attaches []string
	reads    int

	allow       map[string]struct{}
	deny        map[string]struct{}
	allowHosts  map[string]struct{}
	denyHosts   map[string]struct{}
	defaultDeny bool
	observe     bool

	attachErr error
	addErr    error
	readErr   error
	ipEvents  map[egressfilter.IPEventKey]uint32
}

func newFakeFilter() *fakeFilter {
	return &fakeFilter{
		allow:      make(map[string]struct{}),
		deny:       make(map[string]struct{}),
		allowHosts: make(map[string]struct{}),
		denyHosts:  make(map[string]struct{}),
	}
}

func (f *fakeFilter) AddIps(p *compiler.AllowDenyPair) ([]egressfilter.RejectedTarget, error) {
	f.adds = append(f.adds, snapshotPair(p))
	if p == nil {
		return nil, nil
	}
	allowAddrs, allowHosts, _, allowRejected := egressfilter.ParseTargets(p.Allow)
	denyAddrs, denyHosts, _, denyRejected := egressfilter.ParseTargets(p.Deny)
	for _, a := range allowAddrs {
		f.allow[a.String()] = struct{}{}
	}
	for _, a := range denyAddrs {
		f.deny[a.String()] = struct{}{}
	}
	for _, h := range allowHosts {
		f.allowHosts[h] = struct{}{}
	}
	for _, h := range denyHosts {
		f.denyHosts[h] = struct{}{}
	}
	return append(allowRejected, denyRejected...), f.addErr
}

func (f *fakeFilter) DeleteIps(p *compiler.AllowDenyPair) ([]egressfilter.RejectedTarget, error) {
	f.deletes = append(f.deletes, snapshotPair(p))
	if p == nil {
		return nil, nil
	}
	allowAddrs, allowHosts, _, allowRejected := egressfilter.ParseTargets(p.Allow)
	denyAddrs, denyHosts, _, denyRejected := egressfilter.ParseTargets(p.Deny)
	for _, a := range allowAddrs {
		delete(f.allow, a.String())
	}
	for _, a := range denyAddrs {
		delete(f.deny, a.String())
	}
	for _, h := range allowHosts {
		delete(f.allowHosts, h)
	}
	for _, h := range denyHosts {
		delete(f.denyHosts, h)
	}
	return append(allowRejected, denyRejected...), nil
}

func (f *fakeFilter) SetFlagIdx(idx uint8, val bool) {
	f.toggles = append(f.toggles, flagToggle{idx: idx, val: val})
	switch idx {
	case egressfilter.DEFAULT_DENY:
		f.defaultDeny = val
	case egressfilter.OBSERVE:
		f.observe = val
	}
}

func (f *fakeFilter) Attach(cgPath string) ([]link.Link, error) {
	f.attaches = append(f.attaches, cgPath)
	if f.attachErr != nil {
		return nil, f.attachErr
	}
	// link.Link cannot be implemented outside package link, and the manager only
	// uses the returned values as opaque map values
	return []link.Link{}, nil
}

// models the destructive read of the counter map: the events are handed over once
// and the map is reset, so the next call reports a delta.
func (f *fakeFilter) ReadIPEvents() (map[egressfilter.IPEventKey]uint32, error) {
	f.reads++
	out := f.ipEvents
	f.ipEvents = nil
	return out, f.readErr
}

func (f *fakeFilter) reset() {
	f.adds = nil
	f.deletes = nil
	f.toggles = nil
	f.attaches = nil
}

func (f *fakeFilter) liveAllow() []string      { return sortedKeys(f.allow) }
func (f *fakeFilter) liveDeny() []string       { return sortedKeys(f.deny) }
func (f *fakeFilter) liveAllowHosts() []string { return sortedKeys(f.allowHosts) }
func (f *fakeFilter) liveDenyHosts() []string  { return sortedKeys(f.denyHosts) }

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// fakeFactory stands in for egressfilter.New.
type fakeFactory struct {
	created   []*fakeFilter
	newErr    error
	attachErr error
}

func (ff *fakeFactory) new(*logr.Logger) (egressFilter, error) {
	if ff.newErr != nil {
		return nil, ff.newErr
	}
	f := newFakeFilter()
	f.attachErr = ff.attachErr
	ff.created = append(ff.created, f)
	return f, nil
}

// records what the manager reports back onto policy status. mutex guarded because
// the pod and policy informers call the manager from different goroutines.
type fakeStatus struct {
	mu         sync.Mutex
	conditions map[string][]metav1.Condition
	names      map[string][]string
	violations []string
}

func newFakeStatus() *fakeStatus {
	return &fakeStatus{
		conditions: make(map[string][]metav1.Condition),
		names:      make(map[string][]string),
	}
}

func (s *fakeStatus) RecordViolation(policyUID string, podUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.violations = append(s.violations, policyUID+"/"+podUID)
}

func (s *fakeStatus) RecordCondition(policyUID, policyName string, cond metav1.Condition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conditions[policyUID] = append(s.conditions[policyUID], cond)
	s.names[policyUID] = append(s.names[policyUID], policyName)
}

// recordedNames returns the names supplied alongside a policy's conditions.
func (s *fakeStatus) recordedNames(policyUID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.names[policyUID])
}

func (s *fakeStatus) all(policyUID string) []metav1.Condition {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.conditions[policyUID])
}

// latest returns the last condition of the given type recorded for a policy.
func (s *fakeStatus) latest(policyUID, condType string) (metav1.Condition, bool) {
	conds := s.all(policyUID)
	for i := len(conds) - 1; i >= 0; i-- {
		if conds[i].Type == condType {
			return conds[i], true
		}
	}
	return metav1.Condition{}, false
}

func newTestManager() (*EgressManager, *fakeFactory, *fakeStatus) {
	ff := &fakeFactory{}
	status := newFakeStatus()
	e := NewEgressManager(logr.Discard(), status)
	e.newFilter = ff.new
	e.clock = func() time.Time { return testTime }
	return e, ff, status
}

func makePod(uid string, lbls map[string]string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   uid,
			UID:    types.UID(uid),
			Labels: lbls,
		},
	}
}

func cgInfos(paths ...string) []*containers.ContainerCgroupInfo {
	out := make([]*containers.ContainerCgroupInfo, 0, len(paths))
	for i, p := range paths {
		out = append(out, &containers.ContainerCgroupInfo{ID: uint64(i + 1), Path: p})
	}
	return out
}

// addPod drives a create pod event and returns the fake filter bound to it.
func addPod(t *testing.T, e *EgressManager, uid string, lbls map[string]string, paths ...string) *fakeFilter {
	t.Helper()
	if err := e.PodEvent(makePod(uid, lbls), cgInfos(paths...), events.EventTypeCreate); err != nil {
		t.Fatalf("podCreated(%s): unexpected error: %v", uid, err)
	}
	return filterOf(t, e, uid)
}

// relabelPod drives an update pod event carrying a new label set, keeping the
// pod's cgroups as they are.
func relabelPod(t *testing.T, e *EgressManager, uid string, lbls map[string]string, paths ...string) {
	t.Helper()
	if err := e.PodEvent(makePod(uid, lbls), cgInfos(paths...), events.EventTypeUpdate); err != nil {
		t.Fatalf("podUpdated(%s): unexpected error: %v", uid, err)
	}
}

func filterOf(t *testing.T, e *EgressManager, uid string) *fakeFilter {
	t.Helper()
	pa, ok := e.pods[uid]
	if !ok {
		t.Fatalf("pod %s not tracked by the manager", uid)
	}
	f, ok := pa.filter.(*fakeFilter)
	if !ok {
		t.Fatalf("pod %s filter is %T, want *fakeFilter", uid, pa.filter)
	}
	return f
}

func rp(uid, mode string, sel map[string]string, allow, deny []string) *compiler.EvaluationResult {
	return &compiler.EvaluationResult{
		UID:      uid,
		Name:     uid,
		Mode:     mode,
		Selector: labels.SelectorFromSet(labels.Set(sel)),
		IPs:      &compiler.AllowDenyPair{Allow: allow, Deny: deny},
	}
}

// the controller emits delete events that carry only the uid (nil IPs, nil
// selector), so the delete path has to work off the stored attachment alone.
func deleteEvent(uid string) *compiler.EvaluationResult {
	return &compiler.EvaluationResult{UID: uid}
}

func wantPairs(t *testing.T, kind string, got, want []ipPair) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d calls %v, want %d calls %v", kind, len(got), got, len(want), want)
	}
	for i := range want {
		if !slices.Equal(got[i].Allow, want[i].Allow) || !slices.Equal(got[i].Deny, want[i].Deny) {
			t.Errorf("%s call %d: got allow=%v deny=%v, want allow=%v deny=%v",
				kind, i, got[i].Allow, got[i].Deny, want[i].Allow, want[i].Deny)
		}
	}
}

func wantLiveIps(t *testing.T, f *fakeFilter, allow, deny []string) {
	t.Helper()
	if !slices.Equal(f.liveAllow(), allow) {
		t.Errorf("live allow ips: got %v, want %v", f.liveAllow(), allow)
	}
	if !slices.Equal(f.liveDeny(), deny) {
		t.Errorf("live deny ips: got %v, want %v", f.liveDeny(), deny)
	}
}

func wantLiveHosts(t *testing.T, f *fakeFilter, allow, deny []string) {
	t.Helper()
	if !slices.Equal(f.liveAllowHosts(), allow) {
		t.Errorf("live allow hosts: got %v, want %v", f.liveAllowHosts(), allow)
	}
	if !slices.Equal(f.liveDenyHosts(), deny) {
		t.Errorf("live deny hosts: got %v, want %v", f.liveDenyHosts(), deny)
	}
}

func wantDefaultDeny(t *testing.T, f *fakeFilter, want bool) {
	t.Helper()
	if f.defaultDeny != want {
		t.Errorf("default deny flag: got %v, want %v (toggles: %v)", f.defaultDeny, want, f.toggles)
	}
}

func wantObserveFlag(t *testing.T, f *fakeFilter, want bool) {
	t.Helper()
	if f.observe != want {
		t.Errorf("observe flag: got %v, want %v (toggles: %v)", f.observe, want, f.toggles)
	}
}

func wantDefaultDenyOwners(t *testing.T, e *EgressManager, podUid string, want ...string) {
	t.Helper()
	wantSetEquals(t, "defaultDeny owners", podUid, keysOf(e.pods[podUid].defaultDeny), want)
}

func wantAttachedRps(t *testing.T, e *EgressManager, podUid string, want ...string) {
	t.Helper()
	wantSetEquals(t, "attachedFilters", podUid, keysOf(e.pods[podUid].attachedFilters), want)
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func wantSetEquals(t *testing.T, kind, podUid string, got, want []string) {
	t.Helper()
	slices.Sort(got)
	slices.Sort(want)
	if len(want) == 0 {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Errorf("pod %s %s: got %v, want %v", podUid, kind, got, want)
	}
}

func cgPathsOf(t *testing.T, e *EgressManager, podUid string) []string {
	t.Helper()
	out := make([]string, 0)
	for cg := range e.pods[podUid].cgs {
		out = append(out, cg.Path)
	}
	slices.Sort(out)
	return out
}
