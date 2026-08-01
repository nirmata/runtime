package monitor

import (
	"net/netip"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
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
	m := pathMatcher{}
	for _, v := range values {
		if v == compiler.StarTarget {
			m.star = true
			continue
		}
		if v == "" {
			continue
		}
		if m.paths == nil {
			m.paths = make(map[string]struct{}, len(values))
		}
		m.paths[v] = struct{}{}
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

// netBehavior is a compiled network allow/deny pair.
type netBehavior struct {
	allow, deny netMatcher
}

// pathBehavior is a compiled open or exec allow/deny pair.
type pathBehavior struct {
	allow, deny pathMatcher
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
