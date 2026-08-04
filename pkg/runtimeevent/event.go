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
	KindDNS  Kind = "dns"
	KindExec Kind = "exec"
	KindOpen Kind = "open"
)

// KernelDecision mirrors the DECISION_ALLOW / DECISION_DENY defines in the C
// programs; keep the values in sync.
type KernelDecision uint32

const (
	DecisionAllow KernelDecision = 0
	DecisionDeny  KernelDecision = 1
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
	// The decision is part of the counter key, so a Count never mixes allowed
	// and denied occurrences.
	Count uint32 `json:"count,omitempty"`

	// KernelDenied marks events actually denied at the kernel level.
	KernelDenied bool `json:"kernelDenied,omitempty"`

	// WouldDeny marks events that would have been blocked but whose policy is
	// in monitor mode. Written by pkg/monitor.
	WouldDeny bool `json:"wouldDeny,omitempty"`

	Net  *NetFacts  `json:"net,omitempty"`
	DNS  *DNSFacts  `json:"dns,omitempty"`
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
	// Domain is the DNS name DestIP was resolved from, empty when the kernel
	// never saw the address in a snooped answer.
	Domain string `json:"domain,omitempty"`
}

// DNSFacts describes an observed DNS question. The name is what the workload
// asked to resolve, which is not proof that it connected: an answer can be
// cached or shared, and a workload dialling a bare address asks nothing.
type DNSFacts struct {
	QName string `json:"qname"`
}

// ExecFacts describes a process execution.
type ExecFacts struct {
	Filename string `json:"filename"`
}

// OpenFacts describes a file open.
type OpenFacts struct {
	Path string `json:"path"`
}
