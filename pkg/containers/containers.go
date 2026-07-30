// Package containers resolves the cgroup identity (path + inode) of a pod's
// containers. The cgroup inode is the key both BPF engines use to attribute
// kernel events back to a workload, so nothing in this package may panic on a
// pod object, a mountinfo line, or a procfs file.
package containers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// DefaultProcRoot is the procfs root used by the exported helpers that do not
// take one explicitly. Tests always pass their own fake tree.
const DefaultProcRoot = "/proc"

// mountInfoPath is the file describing this process' mount table.
const mountInfoPath = "/proc/self/mountinfo"

var log = ctrl.Log.WithName("containers")

var (
	cgroupOnce  sync.Once
	cgroupMount *cgroupInfo
	cgroupErr   error
)

type cgroupInfo struct {
	mountPoint string
	version    int
}

// ContainerCgroupInfo is the resolved cgroup identity of a single container.
// It is used as a map key by the managers, so every field must stay comparable.
type ContainerCgroupInfo struct {
	ID   uint64
	Path string
	Name string // container name, needed by attribution
}

// detectedCgroup returns the host cgroup mount, detecting it at most once.
// Detection is lazy on purpose: doing it in init() turned an unreadable or
// cgroup-less mount table into a start-up panic.
func detectedCgroup() (*cgroupInfo, error) {
	cgroupOnce.Do(func() {
		cgroupMount, cgroupErr = detectCgroup()
	})
	return cgroupMount, cgroupErr
}

// ResolveCgInfos resolves the cgroup identity of every running container of
// pod. It never panics and never lets a single unresolvable container discard
// its healthy siblings: containers whose ID is missing (not started yet) or
// whose cgroup path cannot be found are skipped, and the infos that could be
// resolved are returned together with a joined error describing the rest, so
// callers may retry later.
func ResolveCgInfos(pod *corev1.Pod) ([]*ContainerCgroupInfo, error) {
	cgInfos := []*ContainerCgroupInfo{}
	if pod == nil {
		return cgInfos, nil
	}

	var errs []error
	for i := range pod.Status.ContainerStatuses {
		cs := &pod.Status.ContainerStatuses[i]
		cgInfo, err := cgroupInfoFromContainer(pod, cs)
		if err != nil {
			// V(2): expected for containers that are still being created.
			log.V(2).Info("skipping container with unresolvable cgroup",
				"pod", pod.Name, "namespace", pod.Namespace, "container", cs.Name, "reason", err.Error())
			errs = append(errs, err)
			continue
		}
		cgInfos = append(cgInfos, cgInfo)
	}

	return cgInfos, errors.Join(errs...)
}

func ExtractCgPaths(cgInfos []*ContainerCgroupInfo) []string {
	ret := []string{}
	for _, cgInfo := range cgInfos {
		if cgInfo == nil {
			continue
		}
		ret = append(ret, cgInfo.Path)
	}
	return ret
}

func ExtractCgids(cgInfos []*ContainerCgroupInfo) []uint64 {
	ret := []uint64{}
	for _, cgInfo := range cgInfos {
		if cgInfo == nil {
			continue
		}
		ret = append(ret, cgInfo.ID)
	}
	return ret
}

func cgroupInfoFromContainer(pod *corev1.Pod, cs *corev1.ContainerStatus) (*ContainerCgroupInfo, error) {
	cg, err := detectedCgroup()
	if err != nil {
		return nil, fmt.Errorf("resolving cgroup mount for container %s: %w", cs.Name, err)
	}

	runtime, containerID, err := parseContainerID(cs.ContainerID)
	if err != nil {
		return nil, fmt.Errorf("resolving cgroup for container %s: %w", cs.Name, err)
	}
	qos := strings.ToLower(string(pod.Status.QOSClass))

	paths := buildCandidatePaths(cg.mountPoint, runtime, string(pod.UID), containerID, qos)
	for _, path := range paths {
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err == nil {
			return &ContainerCgroupInfo{ID: stat.Ino, Path: path, Name: cs.Name}, nil
		}
	}

	return nil, fmt.Errorf("cgroup path not found for container %s (id %s, runtime %s, %d candidates tried)",
		cs.Name, containerID, runtime, len(paths))
}

// parseContainerID splits a CRI container reference ("<runtime>://<id>") into
// runtime and id. Not-yet-started containers report an empty reference, so a
// malformed value is an error, never an index panic.
func parseContainerID(raw string) (runtime, id string, err error) {
	parts := strings.SplitN(raw, "://", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("container id %q is not yet resolvable", raw)
	}
	return strings.ToLower(parts[0]), parts[1], nil
}

// systemdLeaves returns the scope directory names a given runtime uses under
// the systemd cgroup driver. An unknown or empty runtime yields all of them.
func systemdLeaves(runtime, containerID string) []string {
	switch runtime {
	case "containerd":
		return []string{"cri-containerd-" + containerID + ".scope"}
	case "cri-o", "crio":
		return []string{"crio-" + containerID + ".scope"}
	case "docker":
		return []string{"docker-" + containerID + ".scope"}
	default:
		return []string{
			"cri-containerd-" + containerID + ".scope",
			"crio-" + containerID + ".scope",
			"docker-" + containerID + ".scope",
		}
	}
}

// cgroupfsLeaves returns the leaf path (relative to the pod directory) a given
// runtime uses under the cgroupfs cgroup driver.
func cgroupfsLeaves(runtime, containerID string) []string {
	switch runtime {
	case "containerd", "cri-o", "crio":
		return []string{containerID}
	case "docker":
		return []string{"docker/" + containerID}
	default:
		return []string{containerID, "docker/" + containerID}
	}
}

// buildCandidatePaths enumerates, most-likely-first, the cgroup directories a
// container may live in. runtime is the scheme of the CRI container id ("" for
// unknown); podUID is the RAW pod UID — systemd escaping happens internally,
// because the cgroupfs driver does NOT escape it; qos is the lowercased QoS
// class, "" treated as guaranteed (the only layout without a QoS level).
func buildCandidatePaths(root, runtime, podUID, containerID, qos string) []string {
	// systemd escapes '-' in unit names, so the kubelet replaces it with '_'.
	escapedUID := strings.ReplaceAll(podUID, "-", "_")
	noQoS := qos == "" || qos == "guaranteed"

	var paths []string
	seen := map[string]bool{}
	add := func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}

	// systemd cgroup driver: <root>/<prefix>.slice/<prefix>-<qos>.slice/<prefix>-<qos>-pod<uid>.slice/<scope>
	systemdRoots := []struct{ root, prefix string }{
		{root, "kubepods"}, // default
		{root + "/kubelet.slice", "kubelet-kubepods"}, // systemd managed kubelet
	}
	for _, leaf := range systemdLeaves(runtime, containerID) {
		for _, r := range systemdRoots {
			if noQoS {
				// some kubelet versions skip the qos slice for guaranteed pods
				add(fmt.Sprintf("%s/%s.slice/%s-pod%s.slice/%s", r.root, r.prefix, r.prefix, escapedUID, leaf))
			}
			if qos != "" {
				// others include it (and it is mandatory for burstable/besteffort)
				add(fmt.Sprintf("%s/%s.slice/%s-%s.slice/%s-%s-pod%s.slice/%s",
					r.root, r.prefix, r.prefix, qos, r.prefix, qos, escapedUID, leaf))
			}
		}
	}

	// cgroupfs cgroup driver: <base>/kubepods/<qos>/pod<uid>/<leaf>, pod UID not
	// escaped. The net_cls base is the cgroup v1 fallback.
	cgroupfsBases := []string{root, root + "/net_cls"}
	for _, leaf := range cgroupfsLeaves(runtime, containerID) {
		for _, base := range cgroupfsBases {
			if noQoS {
				add(fmt.Sprintf("%s/kubepods/pod%s/%s", base, podUID, leaf))
			}
			if qos != "" {
				add(fmt.Sprintf("%s/kubepods/%s/pod%s/%s", base, qos, podUID, leaf))
			}
		}
	}

	return paths
}

// ResolveCgroupByPID is the authoritative fallback: it asks the kernel which
// cgroup a pid belongs to instead of guessing a layout. The daemon runs with
// hostPID and mounts /, so this works for every runtime, cgroup driver and
// cgroup version. procRoot is parameterized for tests.
func ResolveCgroupByPID(procRoot string, pid uint32) (*ContainerCgroupInfo, error) {
	cg, err := detectedCgroup()
	if err != nil {
		return nil, fmt.Errorf("resolving cgroup mount for pid %d: %w", pid, err)
	}
	return resolveCgroupByPID(procRoot, pid, cg)
}

func resolveCgroupByPID(procRoot string, pid uint32, cg *cgroupInfo) (*ContainerCgroupInfo, error) {
	if cg == nil {
		return nil, fmt.Errorf("resolving cgroup for pid %d: no cgroup mount", pid)
	}
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}

	file := filepath.Join(procRoot, fmt.Sprint(pid), "cgroup")
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}

	rel, err := parseProcCgroup(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", file, err)
	}

	path := filepath.Join(cg.mountPoint, rel)
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return nil, fmt.Errorf("stat cgroup %s for pid %d: %w", path, pid, err)
	}

	return &ContainerCgroupInfo{ID: stat.Ino, Path: path, Name: filepath.Base(path)}, nil
}

// parseProcCgroup extracts the cgroup path from /proc/<pid>/cgroup content.
// The unified (v2) entry - hierarchy id 0 with no controllers - wins; the first
// v1 controller entry is the fallback. Malformed lines are skipped, never
// indexed blindly.
func parseProcCgroup(data []byte) (string, error) {
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
	if v1 != "" {
		return v1, nil
	}
	return "", fmt.Errorf("no cgroup entry found")
}

func detectCgroup() (*cgroupInfo, error) {
	data, err := os.ReadFile(mountInfoPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", mountInfoPath, err)
	}
	return parseMountInfo(data)
}

// parseMountInfo finds the cgroup mount to use in mountinfo formatted content.
// It is pure so it can be table tested without a procfs. Two passes: a unified
// cgroup2 hierarchy always wins over a cgroup v1 controller mount, which may
// appear earlier in mountinfo order on hybrid hosts. Short or malformed
// lines are skipped rather than indexed.
func parseMountInfo(data []byte) (*cgroupInfo, error) {
	lines := strings.Split(string(data), "\n")
	for _, want := range []string{"cgroup2", "cgroup"} {
		for _, line := range lines {
			fields := strings.Fields(line)
			// the mount point is at index 4 in /proc/self/mountinfo and the
			// fields before it are fixed, but short lines (including the
			// trailing empty one) must not panic
			if len(fields) < 5 {
				continue
			}
			mountPoint := fields[4]

			// fields 0..5 are fixed, so the hyphen separator can only appear at
			// index 6 or later; the filesystem type follows it
			for i := 6; i < len(fields); i++ {
				if fields[i] != "-" {
					continue
				}
				if i+1 < len(fields) && fields[i+1] == want {
					version := 1
					if want == "cgroup2" {
						version = 2
					}
					return &cgroupInfo{mountPoint: mountPoint, version: version}, nil
				}
				break
			}
		}
	}

	return nil, fmt.Errorf("no cgroup mount found")
}
