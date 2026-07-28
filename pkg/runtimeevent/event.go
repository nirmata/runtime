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
	KindTLS  Kind = "tls"
	KindHTTP Kind = "http"
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
	TLS  *TLSFacts  `json:"tls,omitempty"`
	HTTP *HTTPFacts `json:"http,omitempty"`
	Exec *ExecFacts `json:"exec,omitempty"`
	Open *OpenFacts `json:"open,omitempty"`

	// Pod is filled by pkg/attribution. Sources may pre-fill Pod.UID as a
	// hint when they know the pod but not the cgroup (egress poll source).
	Pod PodIdentity `json:"pod,omitempty"`

	// AI is filled by the classifier stage (pkg/detect/ai); the type lives
	// in ai.go. Nil means "not AI traffic, or not classified yet".
	AI *AIFacts `json:"ai,omitempty"`
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
	DestIP   netip.Addr `json:"destIP"`
	DestPort uint16     `json:"destPort,omitempty"`
	Protocol string     `json:"protocol,omitempty"` // "tcp"|"udp"|""

	// Governed is nil when no AIControls endpoint set is known, which is not
	// the same as knowing the flow bypasses the proxy. Set by pkg/aicontrols.
	Governed *bool `json:"governed,omitempty"`
}

// DNSFacts describes an observed DNS question.
type DNSFacts struct {
	QName string `json:"qname"`
	QType uint16 `json:"qtype,omitempty"`
}

// TLSFacts describes a TLS ClientHello.
type TLSFacts struct {
	SNI  string   `json:"sni,omitempty"`
	ALPN []string `json:"alpn,omitempty"`
	JA4  string   `json:"ja4,omitempty"`
}

// ExecFacts describes a process execution.
type ExecFacts struct {
	Filename string   `json:"filename"`
	Argv     []string `json:"argv,omitempty"` // bounded: max 8 args, 128B each (decoder-enforced)
	PPID     uint32   `json:"ppid,omitempty"`
}

// OpenFacts describes a file open.
type OpenFacts struct {
	Path string `json:"path"`
}
