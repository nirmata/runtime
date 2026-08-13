package attribution

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nirmata/runtime/pkg/containers"
	"github.com/nirmata/runtime/pkg/events"
	"github.com/nirmata/runtime/pkg/metrics"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
)

// the container-level part of an attribution record.
type entry struct {
	podUID      string
	container   string
	containerID string
}

// the pod-level part of an attribution record. id.Labels is replaced rather than
// mutated on every pod update, so a reader holding a returned PodIdentity cannot
// observe a torn map.
type podEntry struct {
	id      runtimeevent.PodIdentity
	cgroups map[uint64]struct{}
}

// Index resolves cgroup IDs, pod UIDs and PIDs to a runtimeevent.PodIdentity.
type Index struct {
	mu       sync.RWMutex
	byCgroup map[uint64]entry
	byPodUID map[string]podEntry

	procRoot string
	metrics  *metrics.Metrics
	log      logr.Logger

	// defaults to containers.ResolveCgroupByPID; a seam so the PID path can run
	// without a real cgroup mount
	resolveByPID func(procRoot string, pid uint32) (*containers.ContainerCgroupInfo, error)
}

// Option configures an Index.
type Option func(*Index)

// WithProcRoot overrides the procfs root used by LookupPID (default "/proc").
func WithProcRoot(root string) Option {
	return func(ix *Index) {
		if root != "" {
			ix.procRoot = root
		}
	}
}

// WithMetrics wires the Prometheus collectors; without it Annotate still drops
// unattributable events, it just does not count them.
func WithMetrics(m *metrics.Metrics) Option {
	return func(ix *Index) { ix.metrics = m }
}

// NewIndex returns an empty index.
func NewIndex(log logr.Logger, opts ...Option) *Index {
	ix := &Index{
		byCgroup:     map[uint64]entry{},
		byPodUID:     map[string]podEntry{},
		procRoot:     containers.DefaultProcRoot,
		log:          log,
		resolveByPID: containers.ResolveCgroupByPID,
	}
	for _, opt := range opts {
		opt(ix)
	}
	return ix
}

// PodEvent implements events.PodEventHandler. Create and update are idempotent
// upserts: labels, owner and the cgroup set are recomputed from scratch and
// cgroups the pod has stopped owning are evicted.
func (ix *Index) PodEvent(pod corev1.Pod, _ map[string]string, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error {
	switch podEventType {
	case events.EventTypeCreate, events.EventTypeUpdate:
		ix.upsert(&pod, cgInfos)
		return nil
	default:
		return fmt.Errorf("attribution: invalid pod event type %q", podEventType)
	}
}

// PodDeleted implements events.PodEventHandler.
func (ix *Index) PodDeleted(uid string) error {
	ix.evict(uid)
	return nil
}

func (ix *Index) upsert(pod *corev1.Pod, cgInfos []*containers.ContainerCgroupInfo) {
	uid := string(pod.UID)
	if uid == "" {
		ix.log.V(2).Info("skipping pod with empty UID", "namespace", pod.Namespace, "pod", pod.Name)
		return
	}

	ownerKind, ownerName := deriveOwner(pod)
	id := runtimeevent.PodIdentity{
		UID:            uid,
		Namespace:      pod.Namespace,
		Name:           pod.Name,
		Labels:         copyLabels(pod.Labels),
		OwnerKind:      ownerKind,
		OwnerName:      ownerName,
		NodeName:       pod.Spec.NodeName,
		ServiceAccount: pod.Spec.ServiceAccountName,
	}

	containerIDs := containerIDsByName(pod)
	cgroups := make(map[uint64]struct{}, len(cgInfos))
	newEntries := make(map[uint64]entry, len(cgInfos))
	for _, cg := range cgInfos {
		if cg == nil || cg.ID == 0 {
			continue
		}
		cgroups[cg.ID] = struct{}{}
		newEntries[cg.ID] = entry{
			podUID:      uid,
			container:   cg.Name,
			containerID: containerIDs[cg.Name],
		}
	}

	ix.mu.Lock()
	defer ix.mu.Unlock()

	// evict the cgroups of restarted containers
	for cgID := range ix.byPodUID[uid].cgroups {
		if _, still := cgroups[cgID]; !still {
			delete(ix.byCgroup, cgID)
		}
	}
	for cgID, e := range newEntries {
		ix.byCgroup[cgID] = e
	}
	ix.byPodUID[uid] = podEntry{id: id, cgroups: cgroups}

	ix.log.V(2).Info("indexed pod", "namespace", pod.Namespace, "pod", pod.Name,
		"podUid", uid, "cgroups", len(cgroups))
}

func (ix *Index) evict(uid string) {
	if uid == "" {
		return
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	for cgID := range ix.byPodUID[uid].cgroups {
		delete(ix.byCgroup, cgID)
	}
	delete(ix.byPodUID, uid)
	ix.log.V(2).Info("evicted pod from attribution index", "podUid", uid)
}

// Lookup resolves a cgroup inode to the owning pod and container.
func (ix *Index) Lookup(cgroupID uint64) (runtimeevent.PodIdentity, bool) {
	if cgroupID == 0 {
		return runtimeevent.PodIdentity{}, false
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	e, ok := ix.byCgroup[cgroupID]
	if !ok {
		return runtimeevent.PodIdentity{}, false
	}
	pe, ok := ix.byPodUID[e.podUID]
	if !ok {
		return runtimeevent.PodIdentity{}, false
	}
	id := pe.id
	id.Container = e.container
	id.ContainerID = e.containerID
	return id, true
}

// LookupPodUID resolves a pod UID to its identity. The container fields are
// empty, since a pod UID does not identify a container. The returned Labels map
// is shared with the index and must not be mutated.
func (ix *Index) LookupPodUID(uid string) (runtimeevent.PodIdentity, bool) {
	if uid == "" {
		return runtimeevent.PodIdentity{}, false
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	pe, ok := ix.byPodUID[uid]
	if !ok {
		return runtimeevent.PodIdentity{}, false
	}
	return pe.id, true
}

// LookupPID resolves a PID to its pod. It first asks pkg/containers to stat the
// cgroup named by <procRoot>/<pid>/cgroup, which yields the inode the bpf
// programs key on. When that is unavailable (no cgroup mount visible, stat
// denied, cgroup namespaced) it falls back to the pod UID embedded in the cgroup
// path, which every kubelet cgroup driver writes.
func (ix *Index) LookupPID(pid uint32) (runtimeevent.PodIdentity, bool) {
	if pid == 0 {
		return runtimeevent.PodIdentity{}, false
	}

	if cg, err := ix.resolveByPID(ix.procRoot, pid); err == nil && cg != nil {
		if id, ok := ix.Lookup(cg.ID); ok {
			return id, true
		}
		if uid := podUIDFromCgroupPath(cg.Path); uid != "" {
			if id, ok := ix.LookupPodUID(uid); ok {
				return id, true
			}
		}
	} else if err != nil {
		ix.log.V(4).Info("resolving cgroup by pid failed, falling back to path",
			"pid", pid, "reason", err.Error())
	}

	rel, err := ix.readProcCgroup(pid)
	if err != nil {
		ix.log.V(4).Info("reading proc cgroup failed", "pid", pid, "reason", err.Error())
		return runtimeevent.PodIdentity{}, false
	}
	uid := podUIDFromCgroupPath(rel)
	if uid == "" {
		return runtimeevent.PodIdentity{}, false
	}
	return ix.LookupPodUID(uid)
}

// readProcCgroup returns the cgroup path recorded for pid. The unified (v2) entry
// wins; the first v1 controller entry is the fallback.
func (ix *Index) readProcCgroup(pid uint32) (string, error) {
	file := filepath.Join(ix.procRoot, fmt.Sprint(pid), "cgroup")
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", file, err)
	}
	var v1 string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// <hierarchy-id>:<controller-list>:<cgroup-path>
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[2] == "" {
			continue
		}
		if fields[0] == "0" && fields[1] == "" {
			return fields[2], nil
		}
		if v1 == "" {
			v1 = fields[2]
		}
	}
	if v1 == "" {
		return "", fmt.Errorf("no cgroup path in %s", file)
	}
	return v1, nil
}

// Put seeds the index directly with a pod-level identity. Exported for tests and
// fixture loaders; production code goes through PodEvent.
func (ix *Index) Put(cgroupID uint64, id runtimeevent.PodIdentity) {
	if id.UID == "" {
		return
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()

	pe, ok := ix.byPodUID[id.UID]
	if !ok {
		pe = podEntry{cgroups: map[uint64]struct{}{}}
	}
	podLevel := id
	podLevel.Container = ""
	podLevel.ContainerID = ""
	pe.id = podLevel
	if cgroupID != 0 {
		pe.cgroups[cgroupID] = struct{}{}
		ix.byCgroup[cgroupID] = entry{
			podUID:      id.UID,
			container:   id.Container,
			containerID: id.ContainerID,
		}
	}
	ix.byPodUID[id.UID] = pe
}

// Len reports how many pods and cgroups the index holds.
func (ix *Index) Len() (pods int, cgroups int) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return len(ix.byPodUID), len(ix.byCgroup)
}

func copyLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// create a map of container names in a pod to container ids
func containerIDsByName(pod *corev1.Pod) map[string]string {
	out := make(map[string]string, len(pod.Status.ContainerStatuses))
	for i := range pod.Status.ContainerStatuses {
		cs := &pod.Status.ContainerStatuses[i]
		out[cs.Name] = cs.ContainerID
	}
	return out
}

// podUIDFromCgroupPath extracts a pod UID from a kubelet cgroup path. Both
// drivers embed it:
//
//	systemd:  .../kubepods-besteffort-pod<uid with _ for ->.slice/cri-containerd-<id>.scope
//	cgroupfs: .../kubepods/besteffort/pod<uid>/<id>
//
// It returns "" when no segment looks like a pod UID.
func podUIDFromCgroupPath(path string) string {
	for _, seg := range strings.Split(path, "/") {
		idx := strings.LastIndex(seg, "pod")
		if idx < 0 {
			continue
		}
		candidate := seg[idx+len("pod"):]
		candidate = strings.TrimSuffix(candidate, ".slice")
		candidate = strings.TrimSuffix(candidate, ".scope")
		// systemd escapes the dashes of a UID as underscores
		candidate = strings.ReplaceAll(candidate, "_", "-")
		if isPodUID(candidate) {
			return candidate
		}
	}
	return ""
}

// isPodUID accepts the canonical 36-character RFC 4122 form kubelet uses.
func isPodUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
