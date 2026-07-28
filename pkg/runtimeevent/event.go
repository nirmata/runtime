// Package runtimeevent defines the normalized, attributed runtime event
// plane shared by every producer (BPF sources, poll sources, fixtures) and
// every consumer (attribution, detection, monitor sinks, reporters).
//
// The package is deliberately dependency-light and side-effect free: it holds
// the event schema, the source/sink seam interfaces, and the first redaction
// chokepoint (HTTPFacts). Redaction is not configurable; see redact.go.
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
	DNS  *DNSFacts  `json:"dns,omitempty"`
	TLS  *TLSFacts  `json:"tls,omitempty"`
	HTTP *HTTPFacts `json:"http,omitempty"`
	Exec *ExecFacts `json:"exec,omitempty"`
	Open *OpenFacts `json:"open,omitempty"`

	// Pod is filled by pkg/attribution. Sources may pre-fill Pod.UID as a
	// hint when they know the pod but not the cgroup (egress poll source).
	Pod PodIdentity `json:"pod,omitempty"`

	// AI is filled by the classifier; the type lives in ai.go, added by PR B.
	// AI *AIFacts `json:"ai,omitempty"`
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

	// Governed: nil = unknown; set by pkg/aicontrols (PR B).
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
