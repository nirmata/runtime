package dnsmgr

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// fakeTracer records the gate contents and every attach, so a test can assert
// on the kernel-visible outcome rather than on internal bookkeeping.
type fakeTracer struct {
	gate      map[uint64]struct{}
	attached  map[string]*bool // cgroup path -> closed flag
	attachErr error
	attaches  int
}

func newFakeTracer() *fakeTracer {
	return &fakeTracer{gate: map[uint64]struct{}{}, attached: map[string]*bool{}}
}

func (f *fakeTracer) Attach(path string) (link.Link, error) {
	if f.attachErr != nil {
		return nil, f.attachErr
	}
	f.attaches++
	closed := false
	f.attached[path] = &closed
	return &closeOnlyLink{closed: &closed}, nil
}

func (f *fakeTracer) AddCgids(ids []uint64) error {
	for _, id := range ids {
		f.gate[id] = struct{}{}
	}
	return nil
}

func (f *fakeTracer) DeleteCgids(ids []uint64) error {
	for _, id := range ids {
		delete(f.gate, id)
	}
	return nil
}

func (f *fakeTracer) gateIDs() []uint64 {
	out := make([]uint64, 0, len(f.gate))
	for id := range f.gate {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func (f *fakeTracer) openLinks() int {
	n := 0
	for _, closed := range f.attached {
		if !*closed {
			n++
		}
	}
	return n
}

// closeOnlyLink is a link.Link whose only meaningful method is Close.
type closeOnlyLink struct {
	link.Link
	closed *bool
}

func (l *closeOnlyLink) Close() error {
	*l.closed = true
	return nil
}

func newManager(t *testing.T) (*Manager, *fakeTracer) {
	t.Helper()
	ft := newFakeTracer()
	return New(logr.Discard(), ft), ft
}

func dnsPolicy(t *testing.T, uid string, matchLabels map[string]string) *compiler.EvaluationResult {
	t.Helper()
	sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: matchLabels})
	if err != nil {
		t.Fatalf("building selector: %v", err)
	}
	return &compiler.EvaluationResult{
		UID: uid, Name: uid, Selector: sel, Mode: compiler.ModeMonitor,
		DNS: &compiler.AllowDenyPair{Allow: []string{"api.anthropic.com"}},
	}
}

func pod(uid string, lbls map[string]string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Labels: lbls}}
}

func cgs(n int) []*containers.ContainerCgroupInfo {
	out := make([]*containers.ContainerCgroupInfo, 0, n)
	for i := range n {
		out = append(out, &containers.ContainerCgroupInfo{
			ID:   uint64(100 + i),
			Path: fmt.Sprintf("/sys/fs/cgroup/pod/c%d", i),
			Name: fmt.Sprintf("c%d", i),
		})
	}
	return out
}

func TestPodIsNotObservedWithoutADNSPolicy(t *testing.T) {
	m, ft := newManager(t)

	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(2), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}

	if got := ft.attaches; got != 0 {
		t.Errorf("attaches = %d, want 0: a pod no dns policy selects must not be observed", got)
	}
	if got := ft.gateIDs(); len(got) != 0 {
		t.Errorf("gate = %v, want empty", got)
	}
}

func TestPolicyWithoutDNSBehaviorNeverSelects(t *testing.T) {
	m, ft := newManager(t)

	sel, _ := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{})
	networkOnly := &compiler.EvaluationResult{UID: "rp1", Name: "rp1", Selector: sel, Mode: compiler.ModeMonitor}
	if err := m.RuntimePolicyEvent(networkOnly, events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	if err := m.PodEvent(pod("p1", nil), cgs(1), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}

	if got := ft.attaches; got != 0 {
		t.Errorf("attaches = %d, want 0: only a dns behavior selects for dns observation", got)
	}
}

func TestPolicyThenPodAdmitsEveryContainerCgroup(t *testing.T) {
	m, ft := newManager(t)

	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(3), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}

	if got, want := ft.attaches, 3; got != want {
		t.Errorf("attaches = %d, want %d", got, want)
	}
	if got, want := ft.gateIDs(), []uint64{100, 101, 102}; !slices.Equal(got, want) {
		t.Errorf("gate = %v, want %v", got, want)
	}
}

// A pod that already exists when the policy arrives must be picked up: the
// policy informer and the pod informer race, and either order has to work.
func TestPodThenPolicyIsPickedUp(t *testing.T) {
	m, ft := newManager(t)

	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(2), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}
	if got := ft.attaches; got != 0 {
		t.Fatalf("attaches = %d before any policy, want 0", got)
	}

	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}

	if got, want := ft.attaches, 2; got != want {
		t.Errorf("attaches = %d, want %d", got, want)
	}
	if got, want := ft.gateIDs(), []uint64{100, 101}; !slices.Equal(got, want) {
		t.Errorf("gate = %v, want %v", got, want)
	}
}

func TestRelabelledPodStopsBeingObserved(t *testing.T) {
	m, ft := newManager(t)

	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(2), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}
	if got := len(ft.gateIDs()); got != 2 {
		t.Fatalf("gate size = %d before relabel, want 2", got)
	}

	// The label the policy selected on is gone.
	if err := m.PodEvent(pod("p1", map[string]string{"app": "other"}), cgs(2), events.EventTypeUpdate); err != nil {
		t.Fatalf("PodEvent update: %v", err)
	}

	if got := ft.gateIDs(); len(got) != 0 {
		t.Errorf("gate = %v after relabel, want empty", got)
	}
	if got := ft.openLinks(); got != 0 {
		t.Errorf("openLinks = %d after relabel, want 0", got)
	}
}

func TestRelabelledPodStartsBeingObserved(t *testing.T) {
	m, ft := newManager(t)

	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "other"}), cgs(1), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}
	if got := ft.attaches; got != 0 {
		t.Fatalf("attaches = %d, want 0", got)
	}

	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(1), events.EventTypeUpdate); err != nil {
		t.Fatalf("PodEvent update: %v", err)
	}

	if got, want := ft.gateIDs(), []uint64{100}; !slices.Equal(got, want) {
		t.Errorf("gate = %v, want %v", got, want)
	}
}

// Losing the last `dns` behavior on update must revoke observation. The policy
// object still exists and still selects the pod, so only the behavior set can
// tell the manager to stop.
func TestPolicyLosingItsDNSBehaviorRevokesObservation(t *testing.T) {
	m, ft := newManager(t)

	rp := dnsPolicy(t, "rp1", map[string]string{"app": "agent"})
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(2), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}
	if got := len(ft.gateIDs()); got != 2 {
		t.Fatalf("gate size = %d, want 2", got)
	}

	rp.DNS = nil
	if err := m.RuntimePolicyEvent(rp, events.EventTypeUpdate); err != nil {
		t.Fatalf("RuntimePolicyEvent update: %v", err)
	}

	if got := ft.gateIDs(); len(got) != 0 {
		t.Errorf("gate = %v, want empty", got)
	}
	if got := ft.openLinks(); got != 0 {
		t.Errorf("openLinks = %d, want 0", got)
	}
}

func TestObservationSurvivesAnOverlappingSecondPolicy(t *testing.T) {
	m, ft := newManager(t)

	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent rp1: %v", err)
	}
	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp2", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent rp2: %v", err)
	}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(1), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}

	// Deleting one leaves the other selecting the pod.
	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeDelete); err != nil {
		t.Fatalf("RuntimePolicyEvent delete: %v", err)
	}

	if got, want := ft.gateIDs(), []uint64{100}; !slices.Equal(got, want) {
		t.Errorf("gate = %v, want %v: a second selecting policy still needs the observation", got, want)
	}
	if got := ft.openLinks(); got != 1 {
		t.Errorf("openLinks = %d, want 1", got)
	}
}

// A restarted container gets a new cgroup id, so an already-observed pod still
// has to admit it. Missing this leaves the pod attached to a dead cgroup and
// silently blind to the live one.
func TestRestartedContainerIsAttachedAndAdmitted(t *testing.T) {
	m, ft := newManager(t)

	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(1), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}

	restarted := []*containers.ContainerCgroupInfo{{ID: 999, Path: "/sys/fs/cgroup/pod/c0-restarted", Name: "c0"}}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), restarted, events.EventTypeUpdate); err != nil {
		t.Fatalf("PodEvent update: %v", err)
	}

	if got, want := ft.gateIDs(), []uint64{100, 999}; !slices.Equal(got, want) {
		t.Errorf("gate = %v, want %v", got, want)
	}
	if got, want := ft.attaches, 2; got != want {
		t.Errorf("attaches = %d, want %d", got, want)
	}
}

// Re-delivering the same pod must not attach the same cgroup twice: pod updates
// are frequent and each duplicate link would run the program again per packet.
func TestRepeatedPodUpdateDoesNotReattach(t *testing.T) {
	m, ft := newManager(t)

	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	for range 4 {
		if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(2), events.EventTypeUpdate); err != nil {
			t.Fatalf("PodEvent: %v", err)
		}
	}

	if got, want := ft.attaches, 2; got != want {
		t.Errorf("attaches = %d, want %d", got, want)
	}
}

func TestPodDeletedRevokesAndDetaches(t *testing.T) {
	m, ft := newManager(t)

	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(2), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}
	if err := m.PodDeleted("p1"); err != nil {
		t.Fatalf("PodDeleted: %v", err)
	}

	if got := ft.gateIDs(); len(got) != 0 {
		t.Errorf("gate = %v, want empty", got)
	}
	if got := ft.openLinks(); got != 0 {
		t.Errorf("openLinks = %d, want 0", got)
	}
	if _, ok := m.pods["p1"]; ok {
		t.Error("pod state retained after delete")
	}
}

func TestPodDeletedForUnknownPodIsNotAnError(t *testing.T) {
	m, _ := newManager(t)
	if err := m.PodDeleted("never-seen"); err != nil {
		t.Errorf("PodDeleted(unknown) = %v, want nil", err)
	}
}

// A cgroup that failed to attach must not end up in the gate: it would read as
// observed while producing nothing.
func TestFailedAttachDoesNotAdmitTheCgroup(t *testing.T) {
	m, ft := newManager(t)
	ft.attachErr = errors.New("attach refused")

	if err := m.RuntimePolicyEvent(dnsPolicy(t, "rp1", map[string]string{"app": "agent"}), events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(2), events.EventTypeCreate)
	if err == nil {
		t.Fatal("PodEvent returned nil, want the attach error surfaced")
	}

	if got := ft.gateIDs(); len(got) != 0 {
		t.Errorf("gate = %v, want empty", got)
	}
}

func TestNilEvaluationResultIsAnError(t *testing.T) {
	m, _ := newManager(t)
	if err := m.RuntimePolicyEvent(nil, events.EventTypeCreate); err == nil {
		t.Error("RuntimePolicyEvent(nil) = nil, want an error")
	}
}

func TestNilTracerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("New(nil tracer) did not panic")
		}
	}()
	New(logr.Discard(), nil)
}

// A policy in no mode reports nothing, so observing the pods it selects would be
// cost with no output.
func TestPolicyWithNoModeDoesNotObserve(t *testing.T) {
	m, ft := newManager(t)

	rp := dnsPolicy(t, "rp1", map[string]string{"app": "agent"})
	rp.Mode = ""
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(1), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}

	if got := ft.attaches; got != 0 {
		t.Errorf("attaches = %d, want 0", got)
	}
}

// A dns behavior in enforce mode is refused before it reaches the manager, so an
// enforce-mode policy must not gate pods in here either.
func TestEnforceModePolicyDoesNotObserve(t *testing.T) {
	m, ft := newManager(t)

	rp := dnsPolicy(t, "rp1", map[string]string{"app": "agent"})
	rp.Mode = compiler.ModeEnforce
	if err := m.RuntimePolicyEvent(rp, events.EventTypeCreate); err != nil {
		t.Fatalf("RuntimePolicyEvent: %v", err)
	}
	if err := m.PodEvent(pod("p1", map[string]string{"app": "agent"}), cgs(1), events.EventTypeCreate); err != nil {
		t.Fatalf("PodEvent: %v", err)
	}

	if got := ft.gateIDs(); len(got) != 0 {
		t.Errorf("gate = %v, want empty", got)
	}
}
