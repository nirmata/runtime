package containers

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseMountInfo(t *testing.T) {
	// a trimmed but otherwise verbatim sample of a real cgroup v2 only host
	cgroupV2Host := `21 26 0:20 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
22 26 0:5 / /proc rw,nosuid,nodev,noexec,relatime shared:15 - proc proc rw
28 21 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
30 21 0:28 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:11 - pstore pstore rw
`
	// cgroup v1 hierarchy: the first cgroup fs found is the tmpfs-backed
	// /sys/fs/cgroup/systemd controller
	cgroupV1Host := `25 20 0:22 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755
26 25 0:23 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:10 - cgroup cgroup rw,xattr,name=systemd
27 25 0:26 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:12 - cgroup cgroup rw,memory
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
			name:        "cgroup v1 mount",
			input:       cgroupV1Host,
			wantMount:   "/sys/fs/cgroup/systemd",
			wantVersion: 1,
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
			name:    "short lines are skipped and do not panic",
			input:   "a\na b\na b c\na b c d\n\n",
			wantErr: true,
		},
		{
			name: "short lines before a valid cgroup2 line",
			// the leading garbage used to panic on fields[4]
			input:       "\nbroken\n1 2 3\n28 21 0:26 / /sys/fs/cgroup rw shared:9 - cgroup2 cgroup2 rw\n",
			wantMount:   "/sys/fs/cgroup",
			wantVersion: 2,
		},
		{
			name: "trailing hyphen with no fs type does not panic",
			// separator is the last field: the inner loop must not read past it
			input:   "28 21 0:26 / /sys/fs/cgroup rw shared:9 -\n",
			wantErr: true,
		},
		{
			name:        "line with no trailing newline",
			input:       "28 21 0:26 / /sys/fs/cgroup rw shared:9 - cgroup2 cgroup2 rw",
			wantMount:   "/sys/fs/cgroup",
			wantVersion: 2,
		},
		{
			name: "first cgroup mount wins",
			input: "28 21 0:26 / /first rw shared:9 - cgroup2 cgroup2 rw\n" +
				"29 21 0:27 / /second rw shared:9 - cgroup2 cgroup2 rw\n",
			wantMount:   "/first",
			wantVersion: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMountInfo(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.mountPoint != tt.wantMount {
				t.Errorf("mountPoint = %q, want %q", got.mountPoint, tt.wantMount)
			}
			if got.version != tt.wantVersion {
				t.Errorf("version = %d, want %d", got.version, tt.wantVersion)
			}
		})
	}
}

func TestBuildCandidatePaths(t *testing.T) {
	const (
		root = "/sys/fs/cgroup"
		uid  = "aaaa_bbbb"
		cid  = "deadbeef"
	)

	tests := []struct {
		name string
		qos  string
		want []string
	}{
		{
			name: "guaranteed emits both qos-less and qos slices for both roots",
			qos:  "guaranteed",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubepods.slice/kubepods-guaranteed.slice/kubepods-guaranteed-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-guaranteed.slice/kubelet-kubepods-guaranteed-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
			},
		},
		{
			name: "burstable",
			qos:  "burstable",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
			},
		},
		{
			name: "besteffort",
			qos:  "besteffort",
			want: []string{
				"/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
				"/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-podaaaa_bbbb.slice/cri-containerd-deadbeef.scope",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCandidatePaths(root, uid, cid, tt.qos)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("buildCandidatePaths()\n got: %#v\nwant: %#v", got, tt.want)
			}
		})
	}
}

func TestParseContainerID(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "containerd", in: "containerd://abc123", want: "abc123"},
		{name: "docker", in: "docker://abc123", want: "abc123"},
		{name: "id containing separator", in: "containerd://a://b", want: "a://b"},
		// this input used to panic with index out of range on SplitN(...)[1]
		{name: "empty", in: "", wantErr: true},
		{name: "no scheme separator", in: "abc123", wantErr: true},
		{name: "scheme only", in: "containerd://", wantErr: true},
		{name: "partial separator", in: "containerd:/abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseContainerID(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseContainerID(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// setCgroupMount points the package level cgroup detection result at a test
// controlled root so the resolution path can be exercised off Linux.
func setCgroupMount(t *testing.T, root string) {
	t.Helper()
	prevMount, prevErr := cgroupMount, cgroupErr
	cgroupMount, cgroupErr = &cgroupInfo{mountPoint: root, version: 2}, nil
	t.Cleanup(func() {
		cgroupMount, cgroupErr = prevMount, prevErr
	})
}

func TestCgroupInfoFromContainerEmptyContainerID(t *testing.T) {
	setCgroupMount(t, t.TempDir())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "1-2-3"},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSBurstable},
	}
	// container not started yet: the id is empty
	cs := &corev1.ContainerStatus{Name: "app"}

	got, err := cgroupInfoFromContainer(pod, cs)
	if err == nil {
		t.Fatalf("expected an error for an empty container id, got %+v", got)
	}
	if got != nil {
		t.Errorf("expected nil cgroup info, got %+v", got)
	}
}

func TestCgroupInfoFromContainerResolvesExistingPath(t *testing.T) {
	root := t.TempDir()
	setCgroupMount(t, root)

	// the pod uid has its hyphens replaced with underscores in the cgroup path
	want := filepath.Join(root,
		"kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-pod1_2_3.slice",
		"cri-containerd-abc123.scope",
	)
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatal(err)
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "1-2-3"},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSBurstable},
	}
	cs := &corev1.ContainerStatus{Name: "app", ContainerID: "containerd://abc123"}

	got, err := cgroupInfoFromContainer(pod, cs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Path != want {
		t.Errorf("Path = %q, want %q", got.Path, want)
	}

	var stat syscall.Stat_t
	if err := syscall.Stat(want, &stat); err != nil {
		t.Fatal(err)
	}
	if got.ID != stat.Ino {
		t.Errorf("ID = %d, want inode %d", got.ID, stat.Ino)
	}
}

func TestCgroupInfoFromContainerNoMatchingPath(t *testing.T) {
	setCgroupMount(t, t.TempDir())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "1-2-3"},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSGuaranteed},
	}
	cs := &corev1.ContainerStatus{Name: "app", ContainerID: "containerd://abc123"}

	if _, err := cgroupInfoFromContainer(pod, cs); err == nil {
		t.Fatal("expected an error when no candidate path exists")
	}
}

func TestResolveCgInfos(t *testing.T) {
	root := t.TempDir()
	setCgroupMount(t, root)

	first := filepath.Join(root, "kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod1_2_3.slice", "cri-containerd-aaa.scope")
	second := filepath.Join(root, "kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod1_2_3.slice", "cri-containerd-bbb.scope")
	for _, p := range []string{first, second} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "1-2-3"},
		Status: corev1.PodStatus{
			QOSClass: corev1.PodQOSBurstable,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "a", ContainerID: "containerd://aaa"},
				{Name: "b", ContainerID: "containerd://bbb"},
			},
		},
	}

	cgInfos, err := ResolveCgInfos(pod)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{first, second}; !reflect.DeepEqual(ExtractCgPaths(cgInfos), want) {
		t.Errorf("ExtractCgPaths() = %v, want %v", ExtractCgPaths(cgInfos), want)
	}
	cgids := ExtractCgids(cgInfos)
	if len(cgids) != 2 || cgids[0] == 0 || cgids[1] == 0 {
		t.Errorf("ExtractCgids() = %v, want two non zero inodes", cgids)
	}
}

func TestResolveCgInfosNoContainerStatuses(t *testing.T) {
	// no container statuses means nothing is resolved and the host is never
	// consulted
	cgInfos, err := ResolveCgInfos(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "1-2-3"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cgInfos) != 0 {
		t.Errorf("expected no cgroup infos, got %+v", cgInfos)
	}
}

func TestResolveCgInfosPropagatesError(t *testing.T) {
	setCgroupMount(t, t.TempDir())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "1-2-3"},
		Status: corev1.PodStatus{
			QOSClass:          corev1.PodQOSBurstable,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "a"}},
		},
	}
	if _, err := ResolveCgInfos(pod); err == nil {
		t.Fatal("expected the container resolution error to propagate")
	}
}

func TestExtractHelpersOnEmptyInput(t *testing.T) {
	if got := ExtractCgPaths(nil); len(got) != 0 {
		t.Errorf("ExtractCgPaths(nil) = %v, want empty", got)
	}
	if got := ExtractCgids(nil); len(got) != 0 {
		t.Errorf("ExtractCgids(nil) = %v, want empty", got)
	}
}
