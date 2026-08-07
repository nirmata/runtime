package dnsmgr

import (
	"errors"
	"sync"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// tracer is the kernel side of DNS observation, satisfied by
// pkg/bpf/dnsquery.Observer.
type tracer interface {
	Attach(cgroupPath string) (link.Link, error)
	AddCgids(cgids []uint64) error
	DeleteCgids(cgids []uint64) error
}

// Manager decides which pods the DNS program observes.
//
// A pod is observed exactly while some policy with a `dns` behavior selects it.
// That is both an efficiency and a privacy boundary: an unselected pod's
// queries never enter the ring buffer, so they cannot be dropped, decoded, or
// reported, and no node-wide firehose exists to fall behind.
//
// Attachment and admission are separate steps because they fail differently. A
// link is per container cgroup and its absence means no packets are seen at
// all; a cgroup id in the gate is what lets an attached program emit. Both are
// reconciled from the same selection decision.
type Manager struct {
	logger logr.Logger
	tracer tracer

	// The pod and policy informers run in parallel; every field below is
	// guarded.
	mu   sync.Mutex
	pods map[string]*podState
	rps  map[string]*compiler.EvaluationResult
}

type podState struct {
	labels map[string]string
	// cgInfos is the latest container set from the pod watcher, retained even
	// while the pod is unobserved: the policy informer delivers no container
	// information, so a policy that starts selecting an existing pod has
	// nothing else to attach to.
	cgInfos []*containers.ContainerCgroupInfo
	cgs     map[containers.ContainerCgroupInfo]link.Link
	// observed records whether this pod is currently gated in.
	observed bool
}

func New(logger logr.Logger, t tracer) *Manager {
	if t == nil {
		panic("dnsmgr: nil tracer")
	}
	return &Manager{
		logger: logger,
		tracer: t,
		pods:   make(map[string]*podState),
		rps:    make(map[string]*compiler.EvaluationResult),
	}
}

var (
	_ events.PodEventHandler           = (*Manager)(nil)
	_ events.RuntimePolicyEventHandler = (*Manager)(nil)
)

func (m *Manager) PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ps, ok := m.pods[string(pod.UID)]
	if !ok {
		ps = &podState{cgs: make(map[containers.ContainerCgroupInfo]link.Link)}
		m.pods[string(pod.UID)] = ps
	}
	// Labels are refreshed on every update: a relabelled pod must start or stop
	// being observed, and a stale label set would decide otherwise.
	ps.labels = pod.Labels
	ps.cgInfos = cgInfos

	return m.reconcilePod(string(pod.UID), ps)
}

func (m *Manager) PodDeleted(uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ps, ok := m.pods[uid]
	if !ok {
		return nil
	}
	delete(m.pods, uid)
	return m.detach(uid, ps)
}

func (m *Manager) RuntimePolicyEvent(rp *compiler.EvaluationResult, eventType string) error {
	if rp == nil {
		return errors.New("dnsmgr: nil evaluation result")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Only a monitor-mode policy with `dns` entries selects pods for
	// observation: enforce is refused at compile time, and a mode the
	// detection engine does nothing in must not start observation either.
	if eventType == events.EventTypeDelete || !rp.DNS.HasEntries() || rp.Mode != compiler.ModeMonitor {
		delete(m.rps, rp.UID)
	} else {
		m.rps[rp.UID] = rp
	}

	var errs []error
	for uid, ps := range m.pods {
		if err := m.reconcilePod(uid, ps); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// reconcilePod brings one pod's attachment and gate admission in line with the
// current policy set.
func (m *Manager) reconcilePod(uid string, ps *podState) error {
	want := m.selectedLocked(ps.labels)

	switch {
	case want:
		// attach is idempotent, so this also covers a restarted container
		// appearing under a new cgroup while the pod stays observed.
		if err := m.attach(uid, ps); err != nil {
			return err
		}
		if !ps.observed {
			ps.observed = true
			m.logger.V(2).Info("observing dns queries", "podUid", uid, "cgroups", len(ps.cgs))
		}
	case ps.observed:
		if err := m.detach(uid, ps); err != nil {
			return err
		}
		ps.observed = false
		m.logger.V(2).Info("no longer observing dns queries", "podUid", uid)
	}
	return nil
}

// attach links every not-yet-linked cgroup and admits its id to the gate. A
// cgroup that is already linked is left alone so repeated updates are cheap.
func (m *Manager) attach(uid string, ps *podState) error {
	var (
		errs  []error
		cgids []uint64
	)
	for _, cg := range ps.cgInfos {
		if _, ok := ps.cgs[*cg]; ok {
			continue
		}
		l, err := m.tracer.Attach(cg.Path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ps.cgs[*cg] = l
		cgids = append(cgids, cg.ID)
	}
	// Admit after attaching. The reverse order would let a cgroup that failed
	// to attach sit in the gate, which reads as "observed" while producing
	// nothing.
	if len(cgids) > 0 {
		if err := m.tracer.AddCgids(cgids); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		m.logger.Error(errors.Join(errs...), "attaching dns observation failed", "podUid", uid)
	}
	return errors.Join(errs...)
}

// detach revokes the gate first, then closes the links: an id left admitted
// after its link is gone is harmless, but a link left open after revocation
// would keep running the program for nothing.
func (m *Manager) detach(uid string, ps *podState) error {
	cgids := make([]uint64, 0, len(ps.cgs))
	for cg := range ps.cgs {
		cgids = append(cgids, cg.ID)
	}

	var errs []error
	if len(cgids) > 0 {
		if err := m.tracer.DeleteCgids(cgids); err != nil {
			errs = append(errs, err)
		}
	}
	for cg, l := range ps.cgs {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
		delete(ps.cgs, cg)
	}
	if len(errs) > 0 {
		m.logger.Error(errors.Join(errs...), "detaching dns observation failed", "podUid", uid)
	}
	return errors.Join(errs...)
}

func (m *Manager) selectedLocked(podLabels map[string]string) bool {
	for _, rp := range m.rps {
		if rp.Selector.Matches(labels.Set(podLabels)) {
			return true
		}
	}
	return false
}
