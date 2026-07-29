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

// Event is one normalized, attributed runtime observation.
// Exactly one facts pointer matching Kind is non-nil.
type Event struct {
	Kind     Kind      `json:"kind"`
	Time     time.Time `json:"time"`
	CgroupID uint64    `json:"cgroupID,omitempty"`
	PID      uint32    `json:"pid,omitempty"`
	Comm     string    `json:"comm,omitempty"`
	// Count > 1 for poll-sourced events that aggregate N kernel occurrences.
	Count uint32 `json:"count,omitempty"`
	// Denied is true when the enforcement layer blocked (or, in monitor
	// mode, would have blocked) this occurrence. Set by pkg/monitor, not
	// by sources.
	Denied bool `json:"denied,omitempty"`

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
