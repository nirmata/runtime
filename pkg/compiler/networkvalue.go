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
	// names neither a Service nor one of its endpoints: a pod A record, or an
	// incomplete name. Such a name is rejected instead of falling through to
	// Host, because resolving it from the pod's DNS answers is not what an
	// operator naming a cluster address asked for. Callers prefix the specific
	// diagnosis; see serviceFormError.
	ErrServiceFormNetworkValue = errors.New(`a cluster Service must be named "<service>.<namespace>.svc.<cluster-domain>", or one of its endpoints "<hostname>.<service>.<namespace>.svc.<cluster-domain>"`)
	// ErrServiceShortFormNetworkValue reports a cluster name with no domain,
	// such as "redis.default.svc". A pod's resolver expands it through the
	// search domains, so the question is the full name and the authored value
	// would match nothing.
	ErrServiceShortFormNetworkValue = errors.New("this cluster name is missing its DNS domain")
	// ErrServiceLabelNetworkValue reports a cluster name whose labels are
	// malformed.
	ErrServiceLabelNetworkValue = errors.New(`invalid cluster Service name: the service label must start with a letter and the namespace and hostname labels with a letter or digit, all continuing with alphanumerics or "-" and at most 63 characters`)
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

// ClusterService is the Service named by a cluster DNS value. Hostname is set
// only for a per-endpoint record, and names one endpoint of that Service rather
// than the Service as a whole.
type ClusterService struct {
	Name      string
	Namespace string
	Hostname  string
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
//   - "<hostname>.<service>.<namespace>.svc.<ClusterDomain>" yields Service
//     with Hostname set, naming one endpoint of it
//   - any other multi-label DNS name yields Host, lowercased and stripped of
//     its root dot
//   - everything else is an error: ErrEmptyNetworkValue,
//     ErrIPv6NetworkValue, ErrWildcardNetworkValue,
//     ErrServiceFormNetworkValue, ErrServiceShortFormNetworkValue,
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
//
// "Aimed at the cluster" is decided by the configured cluster domain, not by a
// label named "svc" anywhere in the name: an external destination is free to be
// called api.prod.svc.example.com, and reserving that shape made a legitimate
// name unusable. The cost is that a name carrying some OTHER cluster's domain
// cannot be told from an external one and is accepted as external.
func parseClusterService(name string) (*ClusterService, bool, error) {
	suffix := "." + ClusterDomain
	if !strings.HasSuffix(name, suffix) {
		if labels := strings.Split(name, "."); len(labels) > 1 && labels[len(labels)-1] == "svc" {
			return nil, true, fmt.Errorf(`%w: name it in full, as "<service>.<namespace>.svc.%s"`,
				ErrServiceShortFormNetworkValue, ClusterDomain)
		}
		return nil, false, nil
	}

	head := strings.Split(strings.TrimSuffix(name, suffix), ".")
	if len(name) > maxHostnameLen {
		return nil, true, ErrServiceLabelNetworkValue
	}
	// A Service name is an RFC 1035 label, a namespace and an endpoint hostname
	// are RFC 1123 ones: a Service cannot start with a digit, those can.
	switch {
	case len(head) == 4 && head[3] == "svc":
		if !validLabel(head[0]) || !validServiceLabel(head[1]) || !validLabel(head[2]) {
			return nil, true, ErrServiceLabelNetworkValue
		}
		return &ClusterService{Hostname: head[0], Name: head[1], Namespace: head[2]}, true, nil
	case len(head) == 3 && head[2] == "svc":
		if !validServiceLabel(head[0]) || !validLabel(head[1]) {
			return nil, true, ErrServiceLabelNetworkValue
		}
		return &ClusterService{Name: head[0], Namespace: head[1]}, true, nil
	case len(head) == 3 && head[2] == "pod":
		return nil, true, serviceFormError("a pod DNS record, whose name already carries the address it resolves to")
	}
	return nil, true, serviceFormError("an incomplete cluster DNS name")
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
