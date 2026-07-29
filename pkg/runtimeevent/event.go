// Package runtimeevent defines the normalized, attributed runtime event
// plane shared by every producer (the managers' poll sources) and every
// consumer (attribution, monitor sinks, reporters).
//
// The package is deliberately dependency-light and side-effect free: it holds
// the event schema and the source/sink seam interfaces.
package runtimeevent

import (
	"net/netip"
	"time"
)

// Kind discriminates which facts pointer on an Event is populated.
type Kind string

const (
	KindNet  Kind = "net"
	KindExec Kind = "exec"
	KindOpen Kind = "open"
)

// KernelVerdict is the enforcement verdict a BPF program recorded for an
// observation. The values mirror the VERDICT_ALLOW / VERDICT_DENY defines in
// the C programs (pkg/bpf/egressfilter/_cprog/maps.h and
// pkg/bpf/lsm/_cprog/maps.h); keep them in sync.
type KernelVerdict uint32

const (
	VerdictAllow KernelVerdict = 0
	VerdictDeny  KernelVerdict = 1
)

// Event is one normalized, attributed runtime observation.
// Exactly one facts pointer matching Kind is non-nil.
type Event struct {
	Kind     Kind      `json:"kind"`
	Time     time.Time `json:"time"`
	CgroupID uint64    `json:"cgroupID,omitempty"`
	PID      uint32    `json:"pid,omitempty"`
	Comm     string    `json:"comm,omitempty"`
	// Count > 1 for poll-sourced events that aggregate N kernel occurrences.
	//
	// Invariant: the kernel verdict is part of the observation counter key,
	// so every occurrence a Count aggregates shares the same KernelDenied
	// value. One address or path can therefore yield two events per poll —
	// one per verdict — but never a mixed count.
	Count uint32 `json:"count,omitempty"`

	// KernelDenied is the kernel's ACTUAL enforcement verdict for the
	// occurrences this event aggregates. Written only by the BPF poll
	// sources, from the verdict dimension of the observation maps. In pure
	// monitor mode nothing is programmed to block, so it is false there; it
	// becomes true when an enforce-mode policy's maps denied the operation.
	KernelDenied bool `json:"kernelDenied,omitempty"`

	// WouldDeny is monitor mode's counterfactual: an enforcing form of a
	// matched monitor-mode policy would have blocked this. Written only by
	// pkg/monitor, on its per-policy copy of the event. Independent of
	// KernelDenied.
	WouldDeny bool `json:"wouldDeny,omitempty"`

	Net  *NetFacts  `json:"net,omitempty"`
	Exec *ExecFacts `json:"exec,omitempty"`
	Open *OpenFacts `json:"open,omitempty"`

	// Pod is filled by pkg/attribution. Sources may pre-fill Pod.UID as a
	// hint when they know the pod but not the cgroup (egress poll source).
	Pod PodIdentity `json:"pod,omitempty"`
}

// PodIdentity is the workload attribution attached to an Event.
type PodIdentity struct {
	UID            string            `json:"uid,omitempty"`
	Namespace      string            `json:"namespace,omitempty"`
	Name           string            `json:"name,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Container      string            `json:"container,omitempty"`
	ContainerID    string            `json:"containerID,omitempty"`
	OwnerKind      string            `json:"ownerKind,omitempty"`
	OwnerName      string            `json:"ownerName,omitempty"`
	NodeName       string            `json:"nodeName,omitempty"`
	ServiceAccount string            `json:"serviceAccount,omitempty"`
}

// NetFacts describes an egress connection attempt.
type NetFacts struct {
	DestIP netip.Addr `json:"destIP"`
}

// ExecFacts describes a process execution.
type ExecFacts struct {
	Filename string `json:"filename"`
}

// OpenFacts describes a file open.
type OpenFacts struct {
	Path string `json:"path"`
}
