package attribution

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testPodUID     = "3f8e1a2b-4c5d-6e7f-8091-a2b3c4d5e6f7"
	testPodUIDEsc  = "3f8e1a2b_4c5d_6e7f_8091_a2b3c4d5e6f7"
	testSystemdCg  = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + testPodUIDEsc + ".slice/cri-containerd-cafe.scope"
	testCgroupfsCg = "/kubepods/besteffort/pod" + testPodUID + "/cafebabe"
)

func testIndex(t *testing.T, opts ...Option) *Index {
	t.Helper()
	return NewIndex(logr.Discard(), opts...)
}

// testPod builds a pod owned by a ReplicaSet of deployment "agent", with one
// running container whose cgroup the caller supplies.
func testPod(labels map[string]string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "agent-7d9f4b6c8-abcde",
			Namespace: "team-a",
			UID:       testPodUID,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "agent-7d9f4b6c8"},
			},
		},
		Spec: corev1.PodSpec{
			NodeName:           "node-1",
			ServiceAccountName: "agent-sa",
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "containerd://cafe"},
			},
		},
	}
}

func appCgroup() []*containers.ContainerCgroupInfo {
	return []*containers.ContainerCgroupInfo{
		{ID: 4242, Path: testSystemdCg, Name: "app"},
	}
}

func TestPodEventLifecycle(t *testing.T) {
	ix := testIndex(t)
	pod := testPod(map[string]string{"app": "agent", "pod-template-hash": "7d9f4b6c8"})

	if err := ix.PodEvent(pod, appCgroup(), events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}

	want := runtimeevent.PodIdentity{
		UID:            testPodUID,
		Namespace:      "team-a",
		Name:           "agent-7d9f4b6c8-abcde",
		Labels:         map[string]string{"app": "agent", "pod-template-hash": "7d9f4b6c8"},
		Container:      "app",
		ContainerID:    "containerd://cafe",
		OwnerKind:      "Deployment",
		OwnerName:      "agent",
		NodeName:       "node-1",
		ServiceAccount: "agent-sa",
	}
	got, ok := ix.Lookup(4242)
	if !ok {
		t.Fatalf("Lookup(4242) after create: not found")
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Lookup after create (-want +got):\n%s", diff)
	}

	// Update: the container restarted into a new cgroup; the old one must go.
	updated := testPod(map[string]string{"app": "agent", "pod-template-hash": "7d9f4b6c8"})
	newCg := []*containers.ContainerCgroupInfo{{ID: 5353, Path: testSystemdCg, Name: "app"}}
	if err := ix.PodEvent(updated, newCg, events.EventTypeUpdate); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, ok := ix.Lookup(4242); ok {
		t.Errorf("Lookup(4242) after update: stale cgroup still indexed")
	}
	if _, ok := ix.Lookup(5353); !ok {
		t.Errorf("Lookup(5353) after update: new cgroup not indexed")
	}
	if pods, cgroups := ix.Len(); pods != 1 || cgroups != 1 {
		t.Errorf("Len() after update = (%d, %d), want (1, 1)", pods, cgroups)
	}

	if err := ix.PodEvent(updated, newCg, events.EventTypeDelete); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := ix.Lookup(5353); ok {
		t.Errorf("Lookup(5353) after delete: still indexed")
	}
	if _, ok := ix.LookupPodUID(testPodUID); ok {
		t.Errorf("LookupPodUID after delete: still indexed")
	}
	if pods, cgroups := ix.Len(); pods != 0 || cgroups != 0 {
		t.Errorf("Len() after delete = (%d, %d), want (0, 0)", pods, cgroups)
	}
}

func TestPodEventUpdateRefreshesLabels(t *testing.T) {
	ix := testIndex(t)
	pod := testPod(map[string]string{"app": "agent", "tier": "old"})
	if err := ix.PodEvent(pod, appCgroup(), events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}

	relabelled := testPod(map[string]string{"app": "agent", "ai-agent": "true"})
	if err := ix.PodEvent(relabelled, appCgroup(), events.EventTypeUpdate); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, ok := ix.LookupPodUID(testPodUID)
	if !ok {
		t.Fatalf("LookupPodUID: not found")
	}
	want := map[string]string{"app": "agent", "ai-agent": "true"}
	if diff := cmp.Diff(want, got.Labels); diff != "" {
		t.Errorf("labels after update (-want +got):\n%s", diff)
	}
}

func TestPodEventCopiesLabelsFromCaller(t *testing.T) {
	ix := testIndex(t)
	labels := map[string]string{"app": "agent"}
	pod := testPod(labels)
	if err := ix.PodEvent(pod, appCgroup(), events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	// The informer's cache object must never be able to mutate the index.
	labels["app"] = "mutated"

	got, _ := ix.LookupPodUID(testPodUID)
	if got.Labels["app"] != "agent" {
		t.Errorf("labels[app] = %q, want %q: index must not share the caller's map", got.Labels["app"], "agent")
	}
}

func TestPodEventIndexesPodWithoutCgroups(t *testing.T) {
	// The egress poll source only knows pod UIDs, so a pod whose containers
	// have no resolvable cgroup yet must still be attributable by UID.
	ix := testIndex(t)
	if err := ix.PodEvent(testPod(nil), nil, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, ok := ix.LookupPodUID(testPodUID); !ok {
		t.Errorf("LookupPodUID: not found for pod with no cgroups")
	}
	if pods, cgroups := ix.Len(); pods != 1 || cgroups != 0 {
		t.Errorf("Len() = (%d, %d), want (1, 0)", pods, cgroups)
	}
}

func TestPodEventSkipsInvalidEntries(t *testing.T) {
	ix := testIndex(t)
	cgInfos := []*containers.ContainerCgroupInfo{
		nil,
		{ID: 0, Name: "notstarted"},
		{ID: 77, Name: "app"},
	}
	if err := ix.PodEvent(testPod(nil), cgInfos, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, ok := ix.Lookup(0); ok {
		t.Errorf("Lookup(0) succeeded, want miss")
	}
	if _, ok := ix.Lookup(77); !ok {
		t.Errorf("Lookup(77): not found")
	}
}

func TestPodEventRejectsUnknownType(t *testing.T) {
	ix := testIndex(t)
	if err := ix.PodEvent(testPod(nil), nil, "resync"); err == nil {
		t.Errorf("PodEvent with bogus type: got nil error, want error")
	}
}

func TestPodEventSkipsPodWithoutUID(t *testing.T) {
	ix := testIndex(t)
	pod := testPod(nil)
	pod.UID = ""
	if err := ix.PodEvent(pod, appCgroup(), events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	if pods, cgroups := ix.Len(); pods != 0 || cgroups != 0 {
		t.Errorf("Len() = (%d, %d), want (0, 0)", pods, cgroups)
	}
}

func TestRuntimePolicyEventIsNoOp(t *testing.T) {
	ix := testIndex(t)
	if err := ix.RuntimePolicyEvent(nil, events.EventTypeCreate); err != nil {
		t.Errorf("RuntimePolicyEvent: %v", err)
	}
	if pods, cgroups := ix.Len(); pods != 0 || cgroups != 0 {
		t.Errorf("Len() = (%d, %d), want (0, 0)", pods, cgroups)
	}
}

func TestLookupMisses(t *testing.T) {
	ix := testIndex(t)
	if _, ok := ix.Lookup(0); ok {
		t.Errorf("Lookup(0): want miss")
	}
	if _, ok := ix.Lookup(9999); ok {
		t.Errorf("Lookup(9999): want miss")
	}
	if _, ok := ix.LookupPodUID(""); ok {
		t.Errorf("LookupPodUID(\"\"): want miss")
	}
	if _, ok := ix.LookupPodUID("nope"); ok {
		t.Errorf("LookupPodUID(nope): want miss")
	}
	if _, ok := ix.LookupPID(0); ok {
		t.Errorf("LookupPID(0): want miss")
	}
}

func TestPutSeedsIndex(t *testing.T) {
	ix := testIndex(t)
	id := runtimeevent.PodIdentity{
		UID:         testPodUID,
		Namespace:   "team-a",
		Name:        "agent",
		Container:   "app",
		ContainerID: "containerd://cafe",
	}
	ix.Put(4242, id)

	byCgroup, ok := ix.Lookup(4242)
	if !ok {
		t.Fatalf("Lookup(4242) after Put: not found")
	}
	if diff := cmp.Diff(id, byCgroup); diff != "" {
		t.Errorf("Lookup after Put (-want +got):\n%s", diff)
	}

	// The pod-level record carries no container identity.
	byUID, ok := ix.LookupPodUID(testPodUID)
	if !ok {
		t.Fatalf("LookupPodUID after Put: not found")
	}
	if byUID.Container != "" || byUID.ContainerID != "" {
		t.Errorf("LookupPodUID container fields = (%q, %q), want empty", byUID.Container, byUID.ContainerID)
	}

	// Put is also how fixture loaders register a pod with no cgroup at all.
	ix.Put(0, runtimeevent.PodIdentity{UID: "other-uid"})
	if _, ok := ix.LookupPodUID("other-uid"); !ok {
		t.Errorf("LookupPodUID(other-uid) after Put(0): not found")
	}
	ix.Put(1, runtimeevent.PodIdentity{})
	if pods, _ := ix.Len(); pods != 2 {
		t.Errorf("pods = %d, want 2 (Put with empty UID must be ignored)", pods)
	}
}

// writeProcCgroup builds a fake procfs tree containing <pid>/cgroup.
func writeProcCgroup(t *testing.T, pid uint32, content string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return root
}

func TestLookupPIDResolvesViaCgroupID(t *testing.T) {
	// Primary path: pkg/containers stats the cgroup and yields its inode.
	ix := testIndex(t, WithProcRoot(writeProcCgroup(t, 4242, "0::"+testSystemdCg+"\n")))
	ix.resolveByPID = func(procRoot string, pid uint32) (*containers.ContainerCgroupInfo, error) {
		if pid != 4242 {
			return nil, fmt.Errorf("unexpected pid %d", pid)
		}
		return &containers.ContainerCgroupInfo{ID: 99, Path: testSystemdCg, Name: "app"}, nil
	}
	if err := ix.PodEvent(testPod(nil), []*containers.ContainerCgroupInfo{
		{ID: 99, Path: testSystemdCg, Name: "app"},
	}, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, ok := ix.LookupPID(4242)
	if !ok {
		t.Fatalf("LookupPID(4242): not found")
	}
	if got.UID != testPodUID || got.Container != "app" {
		t.Errorf("LookupPID = (%q, %q), want (%q, %q)", got.UID, got.Container, testPodUID, "app")
	}
}

func TestLookupPIDFallsBackToCgroupPath(t *testing.T) {
	// Fallback path: no cgroup mount / stat failure, so the pod UID is read
	// out of <procRoot>/<pid>/cgroup. resolveByPID is left at its default,
	// which cannot succeed against a fake tree on any platform.
	tests := []struct {
		name    string
		content string
		wantOK  bool
	}{{
		name:    "cgroup v2 systemd driver",
		content: "0::" + testSystemdCg + "\n",
		wantOK:  true,
	}, {
		name:    "cgroup v2 cgroupfs driver",
		content: "0::" + testCgroupfsCg + "\n",
		wantOK:  true,
	}, {
		name:    "cgroup v1 controller entry",
		content: "11:devices:" + testSystemdCg + "\n5:memory:" + testSystemdCg + "\n",
		wantOK:  true,
	}, {
		name:    "hybrid prefers the unified entry",
		content: "5:memory:/kubepods/besteffort/podffffffff-ffff-ffff-ffff-ffffffffffff/x\n0::" + testSystemdCg + "\n",
		wantOK:  true,
	}, {
		name:    "malformed lines skipped",
		content: "\ngarbage\n:\n0::\n0::" + testSystemdCg + "\n",
		wantOK:  true,
	}, {
		name:    "host process outside kubepods",
		content: "0::/system.slice/sshd.service\n",
		wantOK:  false,
	}, {
		name:    "unknown pod",
		content: "0::/kubepods.slice/kubepods-pod00000000_0000_0000_0000_000000000000.slice/x.scope\n",
		wantOK:  false,
	}, {
		name:    "empty file",
		content: "",
		wantOK:  false,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ix := testIndex(t, WithProcRoot(writeProcCgroup(t, 4242, tc.content)))
			if err := ix.PodEvent(testPod(nil), appCgroup(), events.EventTypeCreate); err != nil {
				t.Fatalf("create: %v", err)
			}
			got, ok := ix.LookupPID(4242)
			if ok != tc.wantOK {
				t.Fatalf("LookupPID ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got.UID != testPodUID {
				t.Errorf("UID = %q, want %q", got.UID, testPodUID)
			}
		})
	}
}

func TestLookupPIDMissingProcEntry(t *testing.T) {
	ix := testIndex(t, WithProcRoot(t.TempDir()))
	if _, ok := ix.LookupPID(4242); ok {
		t.Errorf("LookupPID with no procfs entry: want miss")
	}
}

func TestPodUIDFromCgroupPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"systemd escaped", testSystemdCg, testPodUID},
		{"cgroupfs", testCgroupfsCg, testPodUID},
		{"burstable systemd", "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + testPodUIDEsc + ".slice", testPodUID},
		{"guaranteed cgroupfs", "/kubepods/pod" + testPodUID, testPodUID},
		{"pod uid only segment", "pod" + testPodUID, testPodUID},
		{"host path", "/system.slice/containerd.service", ""},
		{"short uid rejected", "/kubepods/podabc/x", ""},
		{"non hex rejected", "/kubepods/podzzzzzzzz-4c5d-6e7f-8091-a2b3c4d5e6f7", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := podUIDFromCgroupPath(tc.path); got != tc.want {
				t.Errorf("podUIDFromCgroupPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestIndexIsSafeForConcurrentUse(t *testing.T) {
	ix := testIndex(t)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				pod := testPod(map[string]string{"i": fmt.Sprint(i)})
				pod.UID = "3f8e1a2b-4c5d-6e7f-8091-a2b3c4d5e6f7"
				cg := []*containers.ContainerCgroupInfo{{ID: uint64(i%16 + 1), Name: "app"}}
				_ = ix.PodEvent(pod, cg, events.EventTypeUpdate)
				ev := &runtimeevent.Event{Kind: runtimeevent.KindNet, CgroupID: uint64(i%16 + 1)}
				ix.Annotate(ev)
				ix.Len()
				if w%3 == 0 {
					_ = ix.PodEvent(pod, cg, events.EventTypeDelete)
				}
			}
		}(w)
	}
	wg.Wait()
}
