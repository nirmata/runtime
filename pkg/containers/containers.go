package containers

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"

	corev1 "k8s.io/api/core/v1"
)

var (
	cgroupOnce  sync.Once
	cgroupMount *cgroupInfo
	cgroupErr   error
)

type cgroupInfo struct {
	mountPoint string
	version    int
}

type ContainerCgroupInfo struct {
	ID   uint64
	Path string
}

func init() {
	cgroupOnce.Do(func() {
		cgroupMount, cgroupErr = detectCgroup()
	})
}

type ContainerCgstore struct{}

func ResolveCgInfos(pod *corev1.Pod) ([]*ContainerCgroupInfo, error) {
	cgInfos := []*ContainerCgroupInfo{}
	for _, c := range pod.Status.ContainerStatuses {
		// todo: this may not work if the container itself is not running
		// even if the pod is. we should stash this container and attempt to resolve
		// its cgid later
		cgInfo, err := cgroupInfoFromContainer(pod, &c)
		if err != nil {
			return nil, err
		}
		cgInfos = append(cgInfos, cgInfo)
	}
	return cgInfos, nil
}

func ExtractCgPaths(cgInfos []*ContainerCgroupInfo) []string {
	ret := []string{}
	for _, cgInfo := range cgInfos {
		ret = append(ret, cgInfo.Path)
	}
	return ret
}

func ExtractCgids(cgInfos []*ContainerCgroupInfo) []uint64 {
	ret := []uint64{}
	for _, cgInfo := range cgInfos {
		ret = append(ret, cgInfo.ID)
	}
	return ret
}

func cgroupInfoFromContainer(pod *corev1.Pod, cs *corev1.ContainerStatus) (*ContainerCgroupInfo, error) {
	cg, err := cgroupMount, cgroupErr
	if err != nil {
		return nil, err
	}

	containerID, err := parseContainerID(cs.ContainerID)
	if err != nil {
		return nil, err
	}
	podUID := strings.ReplaceAll(string(pod.UID), "-", "_")
	qos := strings.ToLower(string(pod.Status.QOSClass))

	paths := buildCandidatePaths(cg.mountPoint, podUID, containerID, qos)
	for _, path := range paths {
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err == nil {
			return &ContainerCgroupInfo{ID: stat.Ino, Path: path}, nil
		}
	}

	return nil, fmt.Errorf("cgroup path not found for container %s", containerID)
}

// parseContainerID strips the runtime scheme from a CRI container id
// (e.g. "containerd://<id>"). Containers that have not started yet report an
// empty id, which previously panicked on the split result.
func parseContainerID(raw string) (string, error) {
	parts := strings.SplitN(raw, "://", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("invalid container id %q", raw)
	}
	return parts[1], nil
}

func buildCandidatePaths(root, podUID, containerID, qos string) []string {
	type template struct{ root, prefix string }

	// todo: handle file structure differences if the cgroup was found to be v1
	// and we need testing on more edge cases
	roots := []template{
		{root, "kubepods"}, // default cgroupv2
		{root + "/kubelet.slice", "kubelet-kubepods"}, // systemd managed kubelet
	}

	var paths []string
	for _, r := range roots {
		if qos == "guaranteed" {
			paths = append(paths,
				// some kubelet versions skip the qos slice for guaranteed
				fmt.Sprintf("%s/%s.slice/%s-pod%s.slice/cri-containerd-%s.scope",
					r.root, r.prefix, r.prefix, podUID, containerID),
				// others include it
				fmt.Sprintf("%s/%s.slice/%s-guaranteed.slice/%s-guaranteed-pod%s.slice/cri-containerd-%s.scope",
					r.root, r.prefix, r.prefix, r.prefix, podUID, containerID),
			)
		} else {
			paths = append(paths,
				// /root/prefix.slice/prefix-qos.slice/prefix-qos-podID.slice
				fmt.Sprintf("%s/%s.slice/%s-%s.slice/%s-%s-pod%s.slice/cri-containerd-%s.scope",
					r.root, r.prefix, r.prefix, qos, r.prefix, qos, podUID, containerID),
			)
		}
	}
	return paths
}

func detectCgroup() (*cgroupInfo, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return parseMountInfo(f)
}

// parseMountInfo scans mountinfo formatted content and returns the first cgroup
// or cgroup2 mount it finds. It is pure so that it can be tested without a
// procfs.
func parseMountInfo(r io.Reader) (*cgroupInfo, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// the mount point is at the 4th index in /proc/self/mountinfo and
		// the fields before it are fixed. its reliable for us to expect the
		// mount point to be there, but malformed/short lines must not panic
		if len(fields) < 5 {
			continue
		}
		mountPoint := fields[4]

		// scan fields until we get the hyphen separator which after it we will
		// find the filesystem type
		for i, f := range fields {
			if f != "-" || i+1 >= len(fields) {
				continue
			}
			// check if the file system type is cgroup or cgroupv2
			switch fields[i+1] {
			case "cgroup2":
				return &cgroupInfo{mountPoint: mountPoint, version: 2}, nil
			case "cgroup":
				return &cgroupInfo{mountPoint: mountPoint, version: 1}, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("no cgroup mount found")
}
