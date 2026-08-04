package compiler

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// StarTarget is the sentinel a policy uses to mean "everything", i.e. a
// default-deny (in a deny list) or an allow-all (in an allow list). It applies
// to every behavior kind: network targets as well as open/exec paths. It is
// never programmed into a kernel map; consumers translate it into their own
// default-deny flag.
const StarTarget = "*"

// Sentinel errors returned by ParseNetworkValue. They are deliberately terse:
// callers that surface them to operators (admission's field errors, the egress
// filter's rejected-target conditions) wrap or map them into their own
// remedy-bearing vocabulary.
var (
	// ErrEmptyNetworkValue reports a value that is empty after trimming.
	ErrEmptyNetworkValue = errors.New("empty network target")
	// ErrIPv6NetworkValue reports an IPv6 literal or CIDR (IPv4-mapped IPv6
	// forms are unmapped and accepted, not reported).
	ErrIPv6NetworkValue = errors.New("IPv6 addresses and CIDRs are not supported")
	// ErrWildcardNetworkValue reports a wildcard such as "*.example.com",
	// distinct from the bare "*" sentinel.
	ErrWildcardNetworkValue = errors.New(`wildcards are not supported: list each address or fully qualified hostname, or use "*" to match everything`)
	// ErrNotAnIPNetworkValue reports anything else: URLs, truncated
	// addresses, and strings that are not a usable hostname either (a single
	// label, an over-long or malformed label, a numeric last label).
	ErrNotAnIPNetworkValue = errors.New(`not an IPv4 address, IPv4 CIDR, hostname or "*"`)
	// ErrServiceFormNetworkValue reports a name in the cluster DNS domain that
	// is not a Service name: a pod record, a headless Service's per-pod record,
	// or a short form. Such a name is rejected instead of falling through to
	// Host, because resolving it from the pod's DNS answers is not what an
	// operator naming a cluster address asked for. Callers prefix the specific
	// diagnosis; see serviceFormError.
	ErrServiceFormNetworkValue = errors.New(`a cluster Service must be named "<service>.<namespace>.svc.<cluster-domain>"`)
	// ErrServiceDomainNetworkValue reports a Service-shaped name whose suffix is
	// some other cluster's DNS domain.
	ErrServiceDomainNetworkValue = errors.New("this Service name is not in the cluster's DNS domain")
	// ErrServiceLabelNetworkValue reports a canonical Service name whose service
	// or namespace label is malformed.
	ErrServiceLabelNetworkValue = errors.New(`invalid cluster Service name: the service label must start with a letter and the namespace label with a letter or digit, both continuing with alphanumerics or "-" and at most 63 characters`)
)

const (
	maxHostnameLen = 253
	maxLabelLen    = 63
)

// NetworkValue is the parsed form of one network target string. Exactly one
// of the fields is meaningful: Star for the "*" sentinel, Addr for a single
// address, Prefix for a CIDR, Host for an external hostname, Service for a
// cluster Service DNS name.
type NetworkValue struct {
	// Star is true when the value is the StarTarget sentinel.
	Star bool
	// Addr is set for a single-address value. It is already Unmap()ed, so an
	// IPv4-mapped IPv6 literal comes back as its IPv4 form.
	Addr netip.Addr
	// Prefix is set for a CIDR value of ANY width, already unmapped and
	// Masked. Width is deliberately not checked here: ParseNetworkValue
	// defines what a value IS, and each consumer applies its own width
	// policy (see egressfilter.ParseTargets, the single narrowing point).
	Prefix netip.Prefix
	// Host is set for a hostname value, lowercased and without the root dot,
	// so "API.Example.COM." and "api.example.com" are the same value.
	Host string
	// Service is set for a cluster Service DNS name. It is parsed rather than
	// left in Host because the two resolve by different mechanisms: a Service
	// is looked up in the API server, any other name is learned from the pod's
	// own DNS answers.
	Service *ClusterService
}

// ClusterService is the Service named by a cluster DNS value.
type ClusterService struct {
	Name      string
	Namespace string
}

// ClusterDomain is the cluster's DNS domain, the suffix that makes a value a
// Service name rather than an external one. It is a cluster-wide constant that
// every consumer of the grammar has to agree on, so it is set once from the
// daemon's flag before any policy is compiled, never per call.
var ClusterDomain = "cluster.local"

// ParseNetworkValue parses one policy-authored network target string. This is
// the ONE definition of the egress target value grammar: admission validation
// (validateNetworkBehavior), program-time expansion (egressfilter.ParseTargets)
// and monitor-mode matching (monitor.newNetMatcher) all consume it, so they
// cannot disagree about what a value is.
//
// The value is first trimmed of surrounding whitespace, quotes and brackets
// (CEL list rendering and hand-written YAML both leak those). Then:
//
//   - StarTarget ("*") yields Star
//   - an IPv4 literal (or IPv4-mapped IPv6 literal) yields Addr, unmapped
//   - an IPv4 CIDR (or IPv4-mapped IPv6 CIDR) of any width yields Prefix,
//     unmapped and masked
//   - "<service>.<namespace>.svc.<ClusterDomain>" yields Service
//   - any other multi-label DNS name yields Host, lowercased and stripped of
//     its root dot
//   - everything else is an error: ErrEmptyNetworkValue,
//     ErrIPv6NetworkValue, ErrWildcardNetworkValue,
//     ErrServiceFormNetworkValue, ErrServiceDomainNetworkValue,
//     ErrServiceLabelNetworkValue, or ErrNotAnIPNetworkValue
func ParseNetworkValue(raw string) (NetworkValue, error) {
	cleaned := cleanValue(raw)

	switch {
	case cleaned == "":
		return NetworkValue{}, ErrEmptyNetworkValue

	case cleaned == StarTarget:
		return NetworkValue{Star: true}, nil

	case strings.Contains(cleaned, "*"):
		return NetworkValue{}, ErrWildcardNetworkValue

	case strings.Contains(cleaned, "/"):
		prefix, err := netip.ParsePrefix(cleaned)
		if err != nil {
			return NetworkValue{}, ErrNotAnIPNetworkValue
		}
		// Unmap first so ::ffff:10.0.0.0/120 is not mistaken for IPv6.
		prefix = unmapPrefix(prefix)
		if !prefix.Addr().Is4() {
			return NetworkValue{}, ErrIPv6NetworkValue
		}
		return NetworkValue{Prefix: prefix.Masked()}, nil

	default:
		if addr, err := netip.ParseAddr(cleaned); err == nil {
			addr = addr.Unmap()
			if !addr.Is4() {
				return NetworkValue{}, ErrIPv6NetworkValue
			}
			return NetworkValue{Addr: addr}, nil
		}
		name := normalizeName(cleaned)
		if svc, isServiceName, err := parseClusterService(name); isServiceName {
			if err != nil {
				return NetworkValue{}, err
			}
			return NetworkValue{Service: svc}, nil
		}
		host, err := parseHostname(name)
		if err != nil {
			return NetworkValue{}, err
		}
		return NetworkValue{Host: host}, nil
	}
}

// parseClusterService reports whether name is meant as a cluster DNS name at
// all, separately from whether it is a usable one, so that a name aimed at the
// cluster is never quietly downgraded to an external host.
func parseClusterService(name string) (*ClusterService, bool, error) {
	suffix := "." + ClusterDomain
	labels := strings.Split(name, ".")
	inClusterDomain := strings.HasSuffix(name, suffix)
	svcPositioned := len(labels) > 3 && labels[2] == "svc"

	if !inClusterDomain {
		if !svcPositioned {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf(`%w: name a cluster Service as "<service>.<namespace>.svc.%s"`, ErrServiceDomainNetworkValue, ClusterDomain)
	}

	head := strings.Split(strings.TrimSuffix(name, suffix), ".")
	switch {
	case len(head) == 3 && head[2] == "pod":
		return nil, true, serviceFormError("a pod DNS record, not a Service")
	case len(head) == 4 && head[3] == "svc":
		return nil, true, serviceFormError("a headless Service's per-pod DNS record, not a Service")
	case len(head) != 3 || head[2] != "svc":
		return nil, true, serviceFormError("an incomplete cluster Service DNS name")
	}
	// A Service name is an RFC 1035 label, a namespace an RFC 1123 one: a
	// Service cannot start with a digit, a namespace can.
	if len(name) > maxHostnameLen || !validServiceLabel(head[0]) || !validLabel(head[1]) {
		return nil, true, ErrServiceLabelNetworkValue
	}
	return &ClusterService{Name: head[0], Namespace: head[1]}, true, nil
}

func serviceFormError(diagnosis string) error {
	return fmt.Errorf("%s: %w (cluster-domain is %q)", diagnosis, ErrServiceFormNetworkValue, ClusterDomain)
}

// cleanValue strips the surrounding whitespace, quotes and brackets that CEL
// list rendering and hand-written YAML leak into a value.
func cleanValue(raw string) string {
	return strings.Trim(raw, " \t\r\n\"'[]")
}

func normalizeName(cleaned string) string {
	return strings.ToLower(strings.TrimSuffix(cleaned, "."))
}

func parseHostname(host string) (string, error) {
	if !validHostname(host) {
		return "", ErrNotAnIPNetworkValue
	}
	return host, nil
}

// host is already normalized: normalizing again here would strip a second root
// dot and turn "example.com.." into a valid name. This is the one definition of
// what a hostname is for every value grammar in this package, so a name the
// network grammar accepts and one a dns behavior accepts cannot drift.
func validHostname(host string) bool {
	if host == "" || len(host) > maxHostnameLen {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !validLabel(label) {
			return false
		}
	}
	// A numeric last label means a truncated or over-long address ("10.0.0",
	// "1.2.3.4.5"), which must stay an error rather than becoming a name.
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

func validServiceLabel(label string) bool {
	return validLabel(label) && label[0] >= 'a' && label[0] <= 'z'
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > maxLabelLen {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// unmapPrefix converts an IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/N, N >= 96)
// into its IPv4 form. Anything else is returned unchanged, so a prefix wider
// than the v4-mapped range stays IPv6 and is rejected as such.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	addr := p.Addr()
	if !addr.Is4In6() {
		return p
	}
	bits := p.Bits() - 96
	if bits < 0 {
		return p
	}
	return netip.PrefixFrom(addr.Unmap(), bits)
}
