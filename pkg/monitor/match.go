package monitor

import (
	"net/netip"
	"strings"

	"github.com/nirmata/runtime/pkg/compiler"
)

// decision is the outcome of evaluating one behavior against one observation.
type decision struct {
	// violation is true when the policy would have blocked the observation.
	violation bool
	// defaultDeny records why: an explicit deny entry matched, or the
	// behavior default-denies and nothing allowed the value. It only feeds
	// the finding message.
	defaultDeny bool
}

// netMatcher is the compiled form of one side (allow or deny) of a network
// behavior's values.
//
// Values are compiled once, when the policy is tracked, so HandleEvent does no
// parsing on the event path. CIDR values are kept as prefixes and matched by
// containment: egressfilter expands them into individual map keys at program
// time, so a policy denying 10.0.0.0/24 must produce a finding for 10.0.0.7
// rather than silently observing nothing.
type netMatcher struct {
	star     bool
	addrs    map[netip.Addr]struct{}
	prefixes []netip.Prefix
	hosts    map[string]struct{}
}

func newNetMatcher(values []string) netMatcher {
	m := netMatcher{}
	for _, raw := range values {
		v, err := compiler.ParseNetworkValue(raw)
		if err != nil {
			// nothing to match on; admission rejects these, but a value
			// reaching here must never panic or match everything
			continue
		}
		switch {
		case v.Star:
			m.star = true
		case v.Prefix.IsValid():
			m.prefixes = append(m.prefixes, v.Prefix)
		case v.Host != "":
			if m.hosts == nil {
				m.hosts = make(map[string]struct{}, len(values))
			}
			m.hosts[v.Host] = struct{}{}
		default:
			if m.addrs == nil {
				m.addrs = make(map[netip.Addr]struct{}, len(values))
			}
			m.addrs[v.Addr] = struct{}{}
		}
	}
	return m
}

// matches reports whether the observation is covered by an explicit value.
// domain is the name the kernel attributed the address to, empty when it
// attributed none; both sides of the comparison come out of
// compiler.ParseNetworkValue, so the host compare is exact. The "*" sentinel is
// deliberately NOT a match here: it is the default-deny marker, handled
// separately by netBehavior.eval.
func (m netMatcher) matches(addr netip.Addr, domain string) bool {
	if domain != "" {
		if _, ok := m.hosts[domain]; ok {
			return true
		}
	}
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if _, ok := m.addrs[addr]; ok {
		return true
	}
	for _, p := range m.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// pathMatcher is the compiled form of one side of an open or exec behavior.
// The kernel programs key their banned/allowed maps on the exact path string,
// so matching here is exact too: anything cleverer would report findings the
// enforcing form of the same policy would not act on.
type pathMatcher struct {
	star  bool
	paths map[string]struct{}
}

func newPathMatcher(values []string) pathMatcher {
	// rejected values are dropped: lsm.PathKeys derives its keys from the same
	// call, so matching one here would report a finding enforcement never acts on
	paths, star, _ := compiler.ParsePathList(values)
	m := pathMatcher{star: star}
	if len(paths) == 0 {
		return m
	}
	m.paths = make(map[string]struct{}, len(paths))
	for _, p := range paths {
		m.paths[p] = struct{}{}
	}
	return m
}

func (m pathMatcher) matches(path string) bool {
	if path == "" {
		return false
	}
	_, ok := m.paths[path]
	return ok
}

// nameMatcher is the compiled form of one side of a dns behavior. Both sides of
// every comparison it makes are lowercase: policy values through
// compiler.ParseDNSValue, observed question names through the kernel program
// that lowercases them on the wire.
type nameMatcher struct {
	star  bool
	names map[string]struct{}
	// suffixes holds each wildcard as ".<name>", including the separating dot.
	suffixes []string
}

func newNameMatcher(values []string) nameMatcher {
	m := nameMatcher{}
	for _, raw := range values {
		v, err := compiler.ParseDNSValue(raw)
		if err != nil {
			// a value the schema rejects must never produce a match the
			// enforcing side of that schema would not have admitted
			continue
		}
		switch {
		case v.Star:
			m.star = true
		case v.Wildcard:
			m.suffixes = append(m.suffixes, "."+v.Name)
		default:
			if m.names == nil {
				m.names = make(map[string]struct{}, len(values))
			}
			m.names[v.Name] = struct{}{}
		}
	}
	return m
}

// empty reports a side with nothing to match on, either because the policy
// listed nothing or because every value it listed was rejected.
func (m nameMatcher) empty() bool {
	return !m.star && len(m.names) == 0 && len(m.suffixes) == 0
}

// matches reports whether name is covered by an explicit value. The "*"
// sentinel is not an explicit match; nameBehavior.eval handles it.
func (m nameMatcher) matches(name string) bool {
	if name == "" {
		return false
	}
	if _, ok := m.names[name]; ok {
		return true
	}
	for _, s := range m.suffixes {
		// The stored leading dot is what keeps a wildcard to subdomains:
		// "*.openai.azure.com" covers "foo.openai.azure.com" but neither the
		// apex "openai.azure.com" nor "evilopenai.azure.com".
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// netBehavior is a compiled network allow/deny pair.
type netBehavior struct {
	allow, deny netMatcher
}

// pathBehavior is a compiled open or exec allow/deny pair.
type pathBehavior struct {
	allow, deny pathMatcher
}

// nameBehavior is a compiled dns allow/deny pair.
type nameBehavior struct {
	allow, deny nameMatcher
}

// compileNetBehavior returns nil for a pair with no entries: the behavior is
// absent from the policy, and nil is what every reader checks.
func compileNetBehavior(p *compiler.AllowDenyPair) *netBehavior {
	if !p.HasEntries() {
		return nil
	}
	return &netBehavior{allow: newNetMatcher(p.Allow), deny: newNetMatcher(p.Deny)}
}

func compilePathBehavior(p *compiler.AllowDenyPair) *pathBehavior {
	if !p.HasEntries() {
		return nil
	}
	return &pathBehavior{allow: newPathMatcher(p.Allow), deny: newPathMatcher(p.Deny)}
}

func compileNameBehavior(p *compiler.AllowDenyPair) *nameBehavior {
	if !p.HasEntries() {
		return nil
	}
	return &nameBehavior{allow: newNameMatcher(p.Allow), deny: newNameMatcher(p.Deny)}
}

// eval implements the network half of DESIGN §2.10: the destination violates
// when an explicit deny value covers it, or when the behavior default-denies
// ("*" in deny) and no allow value covers it.
func (b *netBehavior) eval(addr netip.Addr, domain string) decision {
	if b == nil || (!addr.IsValid() && domain == "") {
		return decision{}
	}
	if b.deny.matches(addr, domain) {
		return decision{violation: true}
	}
	if b.deny.star && !b.allow.matches(addr, domain) {
		return decision{violation: true, defaultDeny: true}
	}
	return decision{}
}

// eval is the open/exec form of netBehavior.eval, over the path (or exec
// filename) instead of the destination address.
func (b *pathBehavior) eval(path string) decision {
	if b == nil || path == "" {
		return decision{}
	}
	if b.deny.matches(path) {
		return decision{violation: true}
	}
	if b.deny.star && !b.allow.matches(path) {
		return decision{violation: true, defaultDeny: true}
	}
	return decision{}
}

// eval reports whether an observed question name is worth surfacing.
//
// The allow list is inverted here relative to open and exec: it is the set of
// names the workload is expected to resolve, so a name matching none of its
// entries is reportable on its own, with no "*" in deny. An allow list that
// constrained nothing would make the whole behavior pointless, since observing
// a declared name tells an operator nothing.
//
// A behavior with nothing to match on either side is inert rather than
// all-reporting: an empty expected set is "nothing declared yet", not "every
// name is a surprise". Reporting every name is what "*" in deny asks for, and
// it is how an operator discovers a workload's names before writing the allow
// list.
//
// "*" in deny keeps the exemption shape the other behaviors have: an expected
// name stays silent. So narrowing a discovery policy is additive — entries move
// into allow one at a time and the noise drops — rather than requiring the "*"
// to come out in the same edit.
func (b *nameBehavior) eval(name string) decision {
	if b == nil || name == "" {
		return decision{}
	}
	// An explicit deny entry is more specific than the expected set, so it wins.
	if b.deny.matches(name) {
		return decision{violation: true}
	}
	if b.allow.star || b.allow.matches(name) {
		return decision{}
	}
	if b.allow.empty() && !b.deny.star {
		return decision{}
	}
	return decision{violation: true}
}

// protoMatcher is the compiled form of one side of a protocol behavior. A bare
// token matches any event with that protocol, whatever its ALPN; a tls/<alpn>
// value matches only tls with exactly that ALPN (case-sensitive, mirroring the
// kernel classifier's byte comparison).
type protoMatcher struct {
	star   bool
	tokens map[string]struct{}
	alpns  map[string]struct{}
}

func newProtoMatcher(values []string) protoMatcher {
	m := protoMatcher{}
	for _, raw := range values {
		v, err := compiler.ParseProtocolValue(raw)
		if err != nil {
			// a value the schema rejects must never produce a match the
			// enforcing side of that schema would not have admitted
			continue
		}
		switch {
		case v.Star:
			m.star = true
		case v.ALPN != "":
			if m.alpns == nil {
				m.alpns = make(map[string]struct{}, len(values))
			}
			m.alpns[v.ALPN] = struct{}{}
		default:
			if m.tokens == nil {
				m.tokens = make(map[string]struct{}, len(values))
			}
			m.tokens[v.Protocol] = struct{}{}
		}
	}
	return m
}

// matches reports whether an explicit value covers the observed protocol. The
// "*" sentinel is deliberately NOT a match here: it is the default-deny
// marker, handled separately by eval. An observed "unclassified" protocol can
// never match an explicit value — only a default deny covers it.
func (m protoMatcher) matches(protocol, alpn string) bool {
	if protocol == "" {
		return false
	}
	if _, ok := m.tokens[protocol]; ok {
		return true
	}
	if protocol == compiler.ProtocolTLS && alpn != "" {
		_, ok := m.alpns[alpn]
		return ok
	}
	return false
}

// protoBehavior is a compiled protocol allow/deny pair.
type protoBehavior struct {
	allow, deny protoMatcher
}

func compileProtocolBehavior(p *compiler.AllowDenyPair) *protoBehavior {
	if !p.HasEntries() {
		return nil
	}
	return &protoBehavior{allow: newProtoMatcher(p.Allow), deny: newProtoMatcher(p.Deny)}
}

// eval is the protocol form of netBehavior.eval, over the classified protocol
// and its ALPN.
func (b *protoBehavior) eval(protocol, alpn string) decision {
	if b == nil || protocol == "" {
		return decision{}
	}
	if b.deny.matches(protocol, alpn) {
		return decision{violation: true}
	}
	if b.deny.star && !b.allow.matches(protocol, alpn) {
		return decision{violation: true, defaultDeny: true}
	}
	return decision{}
}
