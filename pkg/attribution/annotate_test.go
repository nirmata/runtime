package attribution

import (
	"testing"

	"github.com/nirmata/runtime/pkg/containers"
	"github.com/nirmata/runtime/pkg/events"
	"github.com/nirmata/runtime/pkg/metrics"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAnnotateStageName(t *testing.T) {
	if got := testIndex(t).Name(); got != "attribution" {
		t.Errorf("Name() = %q, want %q", got, "attribution")
	}
}

func TestAnnotateFillsPod(t *testing.T) {
	tests := []struct {
		name  string
		event runtimeevent.Event
		// wantContainer is empty when the match is only pod-level.
		wantContainer string
	}{{
		name: "by pod uid hint",
		event: runtimeevent.Event{
			Kind: runtimeevent.KindNet,
			Pod:  runtimeevent.PodIdentity{UID: testPodUID},
		},
	}, {
		name:          "by cgroup id",
		event:         runtimeevent.Event{Kind: runtimeevent.KindOpen, CgroupID: 4242},
		wantContainer: "app",
	}, {
		name:  "by pid",
		event: runtimeevent.Event{Kind: runtimeevent.KindExec, PID: 4242},
	}, {
		name: "pod uid hint wins over a stale cgroup id",
		event: runtimeevent.Event{
			Kind:     runtimeevent.KindNet,
			CgroupID: 9999,
			Pod:      runtimeevent.PodIdentity{UID: testPodUID},
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := metrics.New(prometheus.NewRegistry())
			ix := testIndex(t,
				WithProcRoot(writeProcCgroup(t, 4242, "0::"+testSystemdCg+"\n")),
				WithMetrics(m))
			if err := ix.PodEvent(testPod(map[string]string{"app": "agent"}), nil, appCgroup(), events.EventTypeCreate); err != nil {
				t.Fatalf("create: %v", err)
			}

			ev := tc.event
			if !ix.Annotate(&ev) {
				t.Fatalf("Annotate() = false, want true")
			}
			want := runtimeevent.PodIdentity{
				UID:            testPodUID,
				Namespace:      "team-a",
				Name:           "agent-7d9f4b6c8-abcde",
				Labels:         map[string]string{"app": "agent"},
				Container:      tc.wantContainer,
				OwnerKind:      "ReplicaSet",
				OwnerName:      "agent-7d9f4b6c8",
				NodeName:       "node-1",
				ServiceAccount: "agent-sa",
			}
			if tc.wantContainer != "" {
				want.ContainerID = "containerd://cafe"
			}
			if diff := cmp.Diff(want, ev.Pod); diff != "" {
				t.Errorf("ev.Pod (-want +got):\n%s", diff)
			}
			if got := testutil.ToFloat64(m.AttributionMisses); got != 0 {
				t.Errorf("AttributionMisses = %v, want 0", got)
			}
		})
	}
}

func TestAnnotateKeepsSourceContainerHint(t *testing.T) {
	ix := testIndex(t)
	if err := ix.PodEvent(testPod(nil), nil, nil, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	ev := runtimeevent.Event{
		Kind: runtimeevent.KindNet,
		Pod:  runtimeevent.PodIdentity{UID: testPodUID, Container: "sidecar", ContainerID: "containerd://beef"},
	}
	if !ix.Annotate(&ev) {
		t.Fatalf("Annotate() = false, want true")
	}
	if ev.Pod.Container != "sidecar" || ev.Pod.ContainerID != "containerd://beef" {
		t.Errorf("container hint = (%q, %q), want it preserved", ev.Pod.Container, ev.Pod.ContainerID)
	}
	if ev.Pod.Namespace != "team-a" {
		t.Errorf("Namespace = %q, want team-a", ev.Pod.Namespace)
	}
}

func TestAnnotateDropsUnattributedAndCounts(t *testing.T) {
	tests := []struct {
		name  string
		event *runtimeevent.Event
	}{
		{"nil event", nil},
		{"no identity at all", &runtimeevent.Event{Kind: runtimeevent.KindNet}},
		{"unknown cgroup", &runtimeevent.Event{Kind: runtimeevent.KindNet, CgroupID: 9999}},
		{"unknown pod uid", &runtimeevent.Event{Kind: runtimeevent.KindNet, Pod: runtimeevent.PodIdentity{UID: "ghost"}}},
		{"host pid", &runtimeevent.Event{Kind: runtimeevent.KindExec, PID: 1}},
		{"deleted pod", &runtimeevent.Event{Kind: runtimeevent.KindOpen, CgroupID: 4242}},
	}

	m := metrics.New(prometheus.NewRegistry())
	ix := testIndex(t, WithProcRoot(writeProcCgroup(t, 1, "0::/init.scope\n")), WithMetrics(m))
	// Index then delete the pod, so cgroup 4242 is genuinely gone.
	if err := ix.PodEvent(testPod(nil), nil, appCgroup(), events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ix.PodDeleted(string(testPod(nil).UID)); err != nil {
		t.Fatalf("delete: %v", err)
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if ix.Annotate(tc.event) {
				t.Fatalf("Annotate() = true, want false (dropped)")
			}
			if tc.event != nil && tc.event.Pod.UID != "" && tc.event.Pod.Namespace != "" {
				t.Errorf("dropped event was partially annotated: %+v", tc.event.Pod)
			}
			if got, want := testutil.ToFloat64(m.AttributionMisses), float64(i+1); got != want {
				t.Errorf("AttributionMisses = %v, want %v", got, want)
			}
		})
	}
}

func TestAnnotateWithoutMetricsDoesNotPanic(t *testing.T) {
	ix := testIndex(t)
	if ix.Annotate(&runtimeevent.Event{Kind: runtimeevent.KindNet, CgroupID: 7}) {
		t.Errorf("Annotate() = true, want false")
	}
}

func TestProcessDelegatesToAnnotate(t *testing.T) {
	ix := testIndex(t)
	if err := ix.PodEvent(testPod(nil), nil, []*containers.ContainerCgroupInfo{
		{ID: 4242, Name: "app"},
	}, events.EventTypeCreate); err != nil {
		t.Fatalf("create: %v", err)
	}
	ev := runtimeevent.Event{Kind: runtimeevent.KindNet, CgroupID: 4242}
	if !ix.Process(&ev) {
		t.Fatalf("Process() = false, want true")
	}
	if ev.Pod.UID != testPodUID {
		t.Errorf("ev.Pod.UID = %q, want %q", ev.Pod.UID, testPodUID)
	}
}
