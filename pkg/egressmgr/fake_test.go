package egressmgr

import (
	"slices"
	"testing"

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

// ipPair is a value-copy snapshot of an *compiler.AllowDenyPair taken at call
// time. The manager mutates the pairs it owns, so recording the pointer would
// let later mutations rewrite history.
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

// fakeFilter records every call the manager makes and also models the state the
// real BPF maps would end up in: the banned-ip map behaves as a set (adds and
// deletes are idempotent), and the flags map holds the default-deny bit. Tests
// assert both the call arguments and the resulting state, so an IP that is added
// and never removed shows up as a leak.
type fakeFilter struct {
	adds     []ipPair
	deletes  []ipPair
	toggles  []flagToggle
	attaches []string

	allow       map[string]struct{}
	deny        map[string]struct{}
	defaultDeny bool

	attachErr error
}

func newFakeFilter() *fakeFilter {
	return &fakeFilter{
		allow: make(map[string]struct{}),
		deny:  make(map[string]struct{}),
	}
}

func (f *fakeFilter) AddIps(p *compiler.AllowDenyPair) {
	f.adds = append(f.adds, snapshotPair(p))
	if p == nil {
		return
	}
	for _, ip := range p.Allow {
		if !programmable(ip) {
			continue
		}
		f.allow[ip] = struct{}{}
	}
	for _, ip := range p.Deny {
		if !programmable(ip) {
			continue
		}
		f.deny[ip] = struct{}{}
	}
}

// the real filter runs every entry through normalizeIP and skips whatever isn't
// a v4 address, so the "*" wildcard never reaches a map: its meaning is carried
// entirely by the DEFAULT_DENY flag. Model that, otherwise the live ip sets
// would report wildcard bookkeeping as leaked map entries.
func programmable(ip string) bool { return ip != "*" }

func (f *fakeFilter) DeleteIps(p *compiler.AllowDenyPair) {
	f.deletes = append(f.deletes, snapshotPair(p))
	if p == nil {
		return
	}
	for _, ip := range p.Allow {
		delete(f.allow, ip)
	}
	for _, ip := range p.Deny {
		delete(f.deny, ip)
	}
}

func (f *fakeFilter) SetFlagIdx(idx uint8, val bool) {
	f.toggles = append(f.toggles, flagToggle{idx: idx, val: val})
	if idx == egressfilter.DEFAULT_DENY {
		f.defaultDeny = val
	}
}

func (f *fakeFilter) Attach(cgPath string) (link.Link, error) {
	f.attaches = append(f.attaches, cgPath)
	if f.attachErr != nil {
		return nil, f.attachErr
	}
	// link.Link cannot be implemented outside package link (unexported isLink
	// method), and the manager only uses the returned value as an opaque map
	// value, so nil is enough.
	return nil, nil
}

func (f *fakeFilter) reset() {
	f.adds = nil
	f.deletes = nil
	f.toggles = nil
	f.attaches = nil
}

func (f *fakeFilter) liveAllow() []string { return sortedKeys(f.allow) }
func (f *fakeFilter) liveDeny() []string  { return sortedKeys(f.deny) }

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

func newTestManager() (*EgressManager, *fakeFactory) {
	e := NewEgressManager(logr.Discard())
	ff := &fakeFactory{}
	e.newFilter = ff.new
	return e, ff
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

func wantDefaultDeny(t *testing.T, f *fakeFilter, want bool) {
	t.Helper()
	if f.defaultDeny != want {
		t.Errorf("default deny flag: got %v, want %v (toggles: %v)", f.defaultDeny, want, f.toggles)
	}
}

func wantDefaultDenyOwners(t *testing.T, e *EgressManager, podUid string, want ...string) {
	t.Helper()
	got := make([]string, 0, len(e.pods[podUid].defaultDeny))
	for uid := range e.pods[podUid].defaultDeny {
		got = append(got, uid)
	}
	slices.Sort(got)
	slices.Sort(want)
	if len(want) == 0 {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Errorf("pod %s defaultDeny owners: got %v, want %v", podUid, got, want)
	}
}

func wantAttachedRps(t *testing.T, e *EgressManager, podUid string, want ...string) {
	t.Helper()
	got := make([]string, 0)
	for uid := range e.pods[podUid].attachedFilters {
		got = append(got, uid)
	}
	slices.Sort(got)
	slices.Sort(want)
	if len(want) == 0 {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Errorf("pod %s attachedFilters: got %v, want %v", podUid, got, want)
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
