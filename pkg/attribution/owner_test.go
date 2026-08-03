package attribution

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDeriveOwner(t *testing.T) {
	tests := []struct {
		name     string
		owners   []metav1.OwnerReference
		labels   map[string]string
		wantKind string
		wantName string
	}{{
		name:     "deployment via replicaset",
		owners:   []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "agent-7d9f4b6c8"}},
		labels:   map[string]string{"pod-template-hash": "7d9f4b6c8"},
		wantKind: "Deployment",
		wantName: "agent",
	}, {
		name:     "deployment name containing dashes",
		owners:   []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "my-ai-agent-59ff8c6d4d"}},
		labels:   map[string]string{"pod-template-hash": "59ff8c6d4d"},
		wantKind: "Deployment",
		wantName: "my-ai-agent",
	}, {
		name:     "replicaset without pod-template-hash stays a replicaset",
		owners:   []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "hand-made-rs"}},
		wantKind: "ReplicaSet",
		wantName: "hand-made-rs",
	}, {
		name:     "replicaset whose name does not end in the hash stays a replicaset",
		owners:   []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "agent-deadbeef"}},
		labels:   map[string]string{"pod-template-hash": "7d9f4b6c8"},
		wantKind: "ReplicaSet",
		wantName: "agent-deadbeef",
	}, {
		name:     "replicaset named exactly the hash is not trimmed away",
		owners:   []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "-7d9f4b6c8"}},
		labels:   map[string]string{"pod-template-hash": "7d9f4b6c8"},
		wantKind: "ReplicaSet",
		wantName: "-7d9f4b6c8",
	}, {
		name:     "statefulset reported directly",
		owners:   []metav1.OwnerReference{{Kind: "StatefulSet", Name: "vector"}},
		wantKind: "StatefulSet",
		wantName: "vector",
	}, {
		name:     "daemonset reported directly",
		owners:   []metav1.OwnerReference{{Kind: "DaemonSet", Name: "node-exporter"}},
		wantKind: "DaemonSet",
		wantName: "node-exporter",
	}, {
		name:     "job reported directly",
		owners:   []metav1.OwnerReference{{Kind: "Job", Name: "backfill-1"}},
		wantKind: "Job",
		wantName: "backfill-1",
	}, {
		name:     "first owner reference wins",
		owners:   []metav1.OwnerReference{{Kind: "StatefulSet", Name: "first"}, {Kind: "ReplicaSet", Name: "second"}},
		wantKind: "StatefulSet",
		wantName: "first",
	}, {
		name:   "bare pod has no owner",
		owners: nil,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name:            "p",
				Labels:          tc.labels,
				OwnerReferences: tc.owners,
			}}
			kind, name := deriveOwner(pod)
			if kind != tc.wantKind || name != tc.wantName {
				t.Errorf("deriveOwner() = (%q, %q), want (%q, %q)", kind, name, tc.wantKind, tc.wantName)
			}
		})
	}
}

func TestDeriveOwnerNilPod(t *testing.T) {
	if kind, name := deriveOwner(nil); kind != "" || name != "" {
		t.Errorf("deriveOwner(nil) = (%q, %q), want empty", kind, name)
	}
}
