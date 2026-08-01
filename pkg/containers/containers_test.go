package containers

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// setCgroupMount points the package level cgroup detection result at a test
// controlled root so resolution can be exercised off Linux and without procfs.
func setCgroupMount(t *testing.T, root string, version int) {
	t.Helper()
	// consume the sync.Once so lazy detection never overwrites the fake
	cgroupOnce.Do(func() {})
	prevMount, prevErr := cgroupMount, cgroupErr
	cgroupMount, cgroupErr = &cgroupInfo{mountPoint: root, version: version}, nil
	t.Cleanup(func() {
		cgroupMount, cgroupErr = prevMount, prevErr
	})
}

func TestParseMountInfo(t *testing.T) {
	// trimmed but otherwise verbatim sample of a real cgroup v2 only host
	cgroupV2Host := `21 26 0:20 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
22 26 0:5 / /proc rw,nosuid,nodev,noexec,relatime shared:15 - proc proc rw
28 21 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate
30 21 0:28 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:11 - pstore pstore rw
`
	// pure cgroup v1 hierarchy: the tmpfs parent is not a cgroup fs, the
	// controller mounts below it are
	cgroupV1Host := `25 20 0:22 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755
26 25 0:23 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:10 - cgroup cgroup rw,xattr,name=systemd
27 25 0:26 / /sys/fs/cgroup/net_cls rw,nosuid,nodev,noexec,relatime shared:12 - cgroup cgroup rw,net_cls
`
	// hybrid host: v1 controller mounts appear BEFORE the unified hierarchy.
	// A single forward scan concluded version 1 here.
	hybridHost := `26 25 0:23 / /sys/fs/cgroup/systemd rw,relatime shared:10 - cgroup cgroup rw,xattr,name=systemd
27 25 0:26 / /sys/fs/cgroup/memory rw,relatime shared:12 - cgroup cgroup rw,memory
31 25 0:30 / /sys/fs/cgroup/unified rw,relatime shared:14 - cgroup2 cgroup2 rw,nsdelegate
`

	tests := []struct {
		name        string
		input       string
		wantMount   string
		wantVersion int
		wantErr     bool
	}{
		{
			name:        "cgroup2 mount",
			input:       cgroupV2Host,
			wantMount:   "/sys/fs/cgroup",
			wantVersion: 2,
		},
		{
			name:        "cgroup v1 controller mount",
			input:       cgroupV1Host,
			wantMount:   "/sys/fs/cgroup/systemd",
			wantVersion: 1,
		},
		{
			name:        "hybrid host prefers cgroup2 over an earlier v1 mount",
			input:       hybridHost,
			wantMount:   "/sys/fs/cgroup/unified",
			wantVersion: 2,
		},
		{
			name:    "no cgroup mount",
			input:   "22 26 0:5 / /proc rw,relatime shared:15 - proc proc rw\n",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "only newlines",
			input:   "\n\n\n",
			wantErr: true,
		},
		{
			// every one of these used to panic on fields[4]
			name:    "short lines are skipped and do not panic",
			input:   "a\na b\na b c\na b c d\n\n",
			wantErr: true,
		},
		{
			name:        "short lines before a valid cgroup2 line",
			input:       "\nbroken\n1 2 3\n28 21 0:26 / /sys/fs/cgroup rw shared:9 - cgroup2 cgroup2 rw\n",
			wantMount:   "/sys/fs/cgroup",
			wantVersion: 2,
		},
		{
			name:    "trailing hyphen with no fs type does not panic",
			input:   "28 21 0:26 / /sys/fs/cgroup rw opts shared:9 -\n",
			wantErr: true,
		},
		{
			name:        "no optional fields before the separator",
			input:       "28 21 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
			wantMount:   "/sys/fs/cgroup",
			wantVersion: 2,
		},
		{
			name:        "line with no trailing newline",
			input:       "28 21 0:26 / /sys/fs/cgroup rw shared:9 - cgroup2 cgroup2 rw",
			wantMount:   "/sys/fs/cgroup",
			wantVersion: 2,
		},
		{
			name: "first cgroup2 mount wins among several",
			input: "28 21 0:26 / /first rw shared:9 - cgroup2 cgroup2 rw\n" +
				"29 21 0:27 / /second rw shared:9 - cgroup2 cgroup2 rw\n",
			wantMount:   "/first",
			wantVersion: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMountInfo([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := &cgroupInfo{mountPoint: tt.wantMount, version: tt.wantVersion}
			if diff := cmp.Diff(want, got, cmp.AllowUnexported(cgroupInfo{})); diff != "" {
				t.Errorf("parseMountInfo() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildCandidatePaths(t *testing.T) {
	const (
		root = "/sys/fs/cgroup"
		uid  = "aaaa-bbbb"
		cid  = "deadbeef"
	)

	tests := []struct {
		name    string
		runtime string
		qos     string
		want    []string
	}{
		{
			name:    "containerd systemd and cgroupfs burstable",
			runtime: "containerd",
			qos:     "burstable",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubepods/burstable/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/burstable/podaaaa-bbbb/deadbeef",
			},
		},
		{
			name:    "containerd besteffort",
			runtime: "containerd",
			qos:     "besteffort",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubepods/besteffort/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/besteffort/podaaaa-bbbb/deadbeef",
			},
		},
		{
			name:    "containerd guaranteed emits both qos-less and qos layouts",
			runtime: "containerd",
			qos:     "guaranteed",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubepods.slice/kubepods-guaranteed.slice/kubepods-guaranteed-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-guaranteed.slice/kubelet-kubepods-guaranteed-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubepods/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/kubepods/guaranteed/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/guaranteed/podaaaa-bbbb/deadbeef",
			},
		},
		{
			name:    "crio scope leaf",
			runtime: "cri-o",
			qos:     "burstable",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podaaaa_bbbb.slice/crio-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-podaaaa_bbbb.slice/crio-deadbeef.scope",
				"/sys/fs/cgroup/kubepods/burstable/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/burstable/podaaaa-bbbb/deadbeef",
			},
		},
		{
			name:    "crio alias without hyphen",
			runtime: "crio",
			qos:     "besteffort",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podaaaa_bbbb.slice/crio-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-podaaaa_bbbb.slice/crio-deadbeef.scope",
				"/sys/fs/cgroup/kubepods/besteffort/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/besteffort/podaaaa-bbbb/deadbeef",
			},
		},
		{
			name:    "docker scope and nested cgroupfs leaf",
			runtime: "docker",
			qos:     "burstable",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podaaaa_bbbb.slice/docker-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-podaaaa_bbbb.slice/docker-deadbeef.scope",
				"/sys/fs/cgroup/kubepods/burstable/podaaaa-bbbb/docker/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/burstable/podaaaa-bbbb/docker/deadbeef",
			},
		},
		{
			name:    "unknown runtime tries every leaf",
			runtime: "",
			qos:     "burstable",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podaaaa_bbbb.slice/crio-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-podaaaa_bbbb.slice/crio-deadbeef.scope",
				"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podaaaa_bbbb.slice/docker-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-podaaaa_bbbb.slice/docker-deadbeef.scope",
				"/sys/fs/cgroup/kubepods/burstable/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/burstable/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/kubepods/burstable/podaaaa-bbbb/docker/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/burstable/podaaaa-bbbb/docker/deadbeef",
			},
		},
		{
			// an unknown QOSClass must not produce "kubepods-.slice" garbage
			name:    "empty qos falls back to the qos-less layouts only",
			runtime: "containerd",
			qos:     "",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubepods/podaaaa-bbbb/deadbeef",
				"/sys/fs/cgroup/net_cls/kubepods/podaaaa-bbbb/deadbeef",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCandidatePaths(root, tt.runtime, uid, cid, tt.qos)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildCandidatePaths() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildCandidatePathsHasNoDuplicates(t *testing.T) {
	for _, qos := range []string{"", "guaranteed", "burstable", "besteffort"} {
		for _, rt := range []string{"", "containerd", "cri-o", "crio", "docker", "bogus"} {
			seen := map[string]bool{}
			for _, p := range buildCandidatePaths("/sys/fs/cgroup", rt, "a-b", "cid", qos) {
				if seen[p] {
					t.Errorf("duplicate candidate %q for runtime=%q qos=%q", p, rt, qos)
				}
				seen[p] = true
			}
		}
	}
}

func TestParseContainerID(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantRuntime string
		wantID      string
		wantErr     bool
	}{
		{name: "containerd", in: "containerd://abc123", wantRuntime: "containerd", wantID: "abc123"},
		{name: "docker", in: "docker://abc123", wantRuntime: "docker", wantID: "abc123"},
		{name: "crio", in: "cri-o://abc123", wantRuntime: "cri-o", wantID: "abc123"},
		{name: "uppercase runtime is normalized", in: "CONTAINERD://abc123", wantRuntime: "containerd", wantID: "abc123"},
		{name: "id containing separator", in: "containerd://a://b", wantRuntime: "containerd", wantID: "a://b"},
		// every case below used to panic with index out of range on SplitN(...)[1]
		{name: "empty", in: "", wantErr: true},
		{name: "no scheme separator", in: "abc123", wantErr: true},
		{name: "scheme only", in: "containerd://", wantErr: true},
		{name: "no runtime", in: "://abc123", wantErr: true},
		{name: "partial separator", in: "containerd:/abc", wantErr: true},
		{name: "separator only", in: "://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime, id, err := parseContainerID(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got (%q, %q)", tt.in, runtime, id)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if runtime != tt.wantRuntime || id != tt.wantID {
				t.Errorf("parseContainerID(%q) = (%q, %q), want (%q, %q)",
					tt.in, runtime, id, tt.wantRuntime, tt.wantID)
			}
		})
	}
}

// TestResolveCgInfosDoesNotPanicOnUnstartedContainers pins that a pod with an
// unstarted container must not crash the daemon.
func TestResolveCgInfosDoesNotPanicOnUnstartedContainers(t *testing.T) {
	setCgroupMount(t, t.TempDir(), 2)

	tests := []struct {
		name        string
		containerID string
	}{
		{name: "empty container id", containerID: ""},
		{name: "no scheme separator", containerID: "abc123"},
		{name: "scheme only", containerID: "containerd://"},
		{name: "partial separator", containerID: "containerd:/abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", UID: "1-2-3"},
				Status: corev1.PodStatus{
					QOSClass:          corev1.PodQOSBurstable,
					ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ContainerID: tt.containerID}},
				},
			}
			got, err := ResolveCgInfos(pod)
			if err == nil {
				t.Errorf("expected a joined error describing the skipped container, got nil")
			}
			if len(got) != 0 {
				t.Errorf("expected no resolved infos, got %+v", got)
			}
		})
	}
}

// TestResolveCgInfosPartialSuccess pins that one waiting container must not
// discard the cgroup info of its running siblings.
func TestResolveCgInfosPartialSuccess(t *testing.T) {
	root := t.TempDir()
	setCgroupMount(t, root, 2)

	running := filepath.Join(root, "kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod1_2_3.slice", "cri-containerd-aaa.scope")
	if err := os.MkdirAll(running, 0o755); err != nil {
		t.Fatal(err)
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", UID: "1-2-3"},
		Status: corev1.PodStatus{
			QOSClass: corev1.PodQOSBurstable,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "pending"}, // never started
				{Name: "running", ContainerID: "containerd://aaa"},      // resolvable
				{Name: "gone", ContainerID: "containerd://nonexistent"}, // id set, no cgroup dir
			},
		},
	}

	cgInfos, err := ResolveCgInfos(pod)
	if err == nil {
		t.Errorf("expected a joined error for the two unresolvable containers, got nil")
	}
	if diff := cmp.Diff([]string{running}, ExtractCgPaths(cgInfos)); diff != "" {
		t.Errorf("resolved paths mismatch (-want +got):\n%s", diff)
	}
	if len(cgInfos) != 1 || cgInfos[0].Name != "running" {
		t.Fatalf("expected exactly the running container, got %+v", cgInfos)
	}
	if cgInfos[0].ID == 0 {
		t.Errorf("expected a non zero cgroup inode, got %d", cgInfos[0].ID)
	}
}

func TestResolveCgInfosResolvesEveryRuntimeLayout(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		qos         corev1.PodQOSClass
		relPath     string
	}{
		{
			name:        "containerd systemd",
			containerID: "containerd://aaa",
			qos:         corev1.PodQOSBurstable,
			relPath:     "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1_2_3.slice/cri-containerd-aaa.scope",
		},
		{
			name:        "crio systemd",
			containerID: "cri-o://bbb",
			qos:         corev1.PodQOSBestEffort,
			relPath:     "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1_2_3.slice/crio-bbb.scope",
		},
		{
			name:        "docker systemd",
			containerID: "docker://ccc",
			qos:         corev1.PodQOSGuaranteed,
			relPath:     "kubepods.slice/kubepods-pod1_2_3.slice/docker-ccc.scope",
		},
		{
			name:        "containerd cgroupfs driver keeps hyphens in the pod uid",
			containerID: "containerd://ddd",
			qos:         corev1.PodQOSBurstable,
			relPath:     "kubepods/burstable/pod1-2-3/ddd",
		},
		{
			name:        "docker cgroupfs driver nests under docker",
			containerID: "docker://eee",
			qos:         corev1.PodQOSBurstable,
			relPath:     "kubepods/burstable/pod1-2-3/docker/eee",
		},
		{
			name:        "cgroup v1 net_cls fallback",
			containerID: "cri-o://fff",
			qos:         corev1.PodQOSBurstable,
			relPath:     "net_cls/kubepods/burstable/pod1-2-3/fff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			setCgroupMount(t, root, 2)
			wantPath := filepath.Join(root, tt.relPath)
			if err := os.MkdirAll(wantPath, 0o755); err != nil {
				t.Fatal(err)
			}

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", UID: "1-2-3"},
				Status: corev1.PodStatus{
					QOSClass:          tt.qos,
					ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ContainerID: tt.containerID}},
				},
			}

			cgInfos, err := ResolveCgInfos(pod)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cgInfos) != 1 {
				t.Fatalf("expected one cgroup info, got %+v", cgInfos)
			}
			var stat syscall.Stat_t
			if err := syscall.Stat(wantPath, &stat); err != nil {
				t.Fatal(err)
			}
			want := &ContainerCgroupInfo{ID: stat.Ino, Path: wantPath, Name: "app"}
			if diff := cmp.Diff(want, cgInfos[0]); diff != "" {
				t.Errorf("ResolveCgInfos() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolveCgInfosNilAndEmptyPod(t *testing.T) {
	// nothing to resolve means no error and no host access
	got, err := ResolveCgInfos(nil)
	if err != nil || len(got) != 0 {
		t.Errorf("ResolveCgInfos(nil) = (%+v, %v), want (empty, nil)", got, err)
	}
	got, err = ResolveCgInfos(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "1-2-3"}})
	if err != nil || len(got) != 0 {
		t.Errorf("ResolveCgInfos(pod without statuses) = (%+v, %v), want (empty, nil)", got, err)
	}
}

func TestCgroupPodUIDPrefersStaticPodConfigHash(t *testing.T) {
	mirrorUID := "730e610d-5d39-4125-b7f9-420afead9035"
	configHash := "129636dd4b80c88d09e934b98c18d4f4"

	tests := []struct {
		name string
		pod  *corev1.Pod
		want string
	}{{
		name: "static pod uses the config hash the kubelet named the cgroup with",
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			UID:         types.UID(mirrorUID),
			Annotations: map[string]string{configHashAnnotation: configHash},
		}},
		want: configHash,
	}, {
		name: "ordinary pod uses its own uid",
		pod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID(mirrorUID)}},
		want: mirrorUID,
	}, {
		name: "empty annotation is not a hash",
		pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			UID:         types.UID(mirrorUID),
			Annotations: map[string]string{configHashAnnotation: ""},
		}},
		want: mirrorUID,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cgroupPodUID(tt.pod); got != tt.want {
				t.Errorf("cgroupPodUID() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The kubelet does not escape the config hash, and it contains no '-' to
// escape, so the static pod slice name must carry it verbatim.
func TestBuildCandidatePathsAcceptsConfigHashVerbatim(t *testing.T) {
	configHash := "129636dd4b80c88d09e934b98c18d4f4"
	want := "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/" +
		"kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod" + configHash +
		".slice/cri-containerd-abc.scope"

	paths := buildCandidatePaths("/sys/fs/cgroup", "containerd", configHash, "abc", "burstable")
	if !slices.Contains(paths, want) {
		t.Errorf("buildCandidatePaths() did not offer %q; got %v", want, paths)
	}
}

func TestExtractHelpers(t *testing.T) {
	if got := ExtractCgPaths(nil); len(got) != 0 {
		t.Errorf("ExtractCgPaths(nil) = %v, want empty", got)
	}
	if got := ExtractCgids(nil); len(got) != 0 {
		t.Errorf("ExtractCgids(nil) = %v, want empty", got)
	}
	// a nil entry must be skipped rather than dereferenced
	in := []*ContainerCgroupInfo{nil, {ID: 7, Path: "/a", Name: "app"}}
	if diff := cmp.Diff([]string{"/a"}, ExtractCgPaths(in)); diff != "" {
		t.Errorf("ExtractCgPaths() mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]uint64{7}, ExtractCgids(in)); diff != "" {
		t.Errorf("ExtractCgids() mismatch (-want +got):\n%s", diff)
	}
}

func TestParseProcCgroup(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "unified v2 entry",
			input: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1_2_3.slice/cri-containerd-aaa.scope\n",
			want:  "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1_2_3.slice/cri-containerd-aaa.scope",
		},
		{
			name: "hybrid prefers the unified entry over v1 controllers",
			input: "12:pids:/kubepods/burstable/pod1-2-3/aaa\n" +
				"3:net_cls,net_prio:/kubepods/burstable/pod1-2-3/aaa\n" +
				"0::/kubepods.slice/cri-containerd-aaa.scope\n",
			want: "/kubepods.slice/cri-containerd-aaa.scope",
		},
		{
			name:  "v1 only falls back to the first controller entry",
			input: "12:pids:/kubepods/burstable/pod1-2-3/aaa\n3:net_cls:/other\n",
			want:  "/kubepods/burstable/pod1-2-3/aaa",
		},
		{name: "empty", input: "", wantErr: true},
		{name: "only newlines", input: "\n\n", wantErr: true},
		{name: "missing path field", input: "0::\n", wantErr: true},
		{name: "not enough colons", input: "0:\n", wantErr: true},
		{name: "garbage", input: "not a cgroup line\n", wantErr: true},
		{
			name:  "garbage before a valid entry",
			input: "garbage\n0:\n0::/good\n",
			want:  "/good",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseProcCgroup([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseProcCgroup() = %q, want %q", got, tt.want)
			}
		})
	}
}

// writeFakeProc builds <procRoot>/<pid>/cgroup trees for the pids given.
func writeFakeProc(t *testing.T, contents map[uint32]string) string {
	t.Helper()
	procRoot := t.TempDir()
	for pid, body := range contents {
		dir := filepath.Join(procRoot, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return procRoot
}

func TestResolveCgroupByPID(t *testing.T) {
	cgRoot := t.TempDir()
	setCgroupMount(t, cgRoot, 2)

	const rel = "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1_2_3.slice/cri-containerd-aaa.scope"
	resolved := filepath.Join(cgRoot, rel)
	if err := os.MkdirAll(resolved, 0o755); err != nil {
		t.Fatal(err)
	}

	procRoot := writeFakeProc(t, map[uint32]string{
		1234: "0::/" + rel + "\n",
		// v1 only: same relative path, reached through the fallback branch
		1235: "12:pids:/" + rel + "\n",
		// points at a directory that does not exist under the cgroup mount
		1236: "0::/kubepods.slice/missing.scope\n",
		1237: "garbage\n",
	})

	tests := []struct {
		name     string
		procRoot string
		pid      uint32
		wantPath string
		wantErr  bool
	}{
		{name: "unified entry", procRoot: procRoot, pid: 1234, wantPath: resolved},
		{name: "v1 fallback entry", procRoot: procRoot, pid: 1235, wantPath: resolved},
		{name: "cgroup dir missing", procRoot: procRoot, pid: 1236, wantErr: true},
		{name: "unparsable cgroup file", procRoot: procRoot, pid: 1237, wantErr: true},
		{name: "no such pid", procRoot: procRoot, pid: 9999, wantErr: true},
		{name: "no such proc root", procRoot: filepath.Join(procRoot, "nope"), pid: 1234, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveCgroupByPID(tt.procRoot, tt.pid)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var stat syscall.Stat_t
			if err := syscall.Stat(tt.wantPath, &stat); err != nil {
				t.Fatal(err)
			}
			want := &ContainerCgroupInfo{
				ID:   stat.Ino,
				Path: tt.wantPath,
				Name: filepath.Base(tt.wantPath),
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("ResolveCgroupByPID() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolveCgroupByPIDWithoutCgroupMount(t *testing.T) {
	procRoot := writeFakeProc(t, map[uint32]string{1: "0::/x\n"})
	if _, err := resolveCgroupByPID(procRoot, 1, nil); err == nil {
		t.Fatal("expected an error when no cgroup mount was detected")
	}
}
