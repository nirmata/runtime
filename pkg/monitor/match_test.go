package monitor

import (
	"net/netip"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

func TestNetMatcher(t *testing.T) {
	tests := []struct {
		name     string
		values   []string
		addr     string
		want     bool
		wantStar bool
	}{
		{name: "exact ipv4", values: []string{"10.0.0.5"}, addr: "10.0.0.5", want: true},
		{name: "exact ipv4 miss", values: []string{"10.0.0.5"}, addr: "10.0.0.6"},
		{name: "cidr /24 contains", values: []string{"10.0.0.0/24"}, addr: "10.0.0.254", want: true},
		{name: "cidr /24 excludes", values: []string{"10.0.0.0/24"}, addr: "10.0.1.1"},
		{name: "cidr /8 contains", values: []string{"10.0.0.0/8"}, addr: "10.9.9.9", want: true},
		{name: "unmasked cidr is masked", values: []string{"10.0.0.7/24"}, addr: "10.0.0.1", want: true},
		{name: "star is not an explicit match", values: []string{compiler.StarTarget}, addr: "10.0.0.5", wantStar: true},
		{name: "star plus explicit value", values: []string{compiler.StarTarget, "10.0.0.5"}, addr: "10.0.0.5", want: true, wantStar: true},
		{name: "quoted and bracketed value", values: []string{" \"[10.0.0.5]\" "}, addr: "10.0.0.5", want: true},
		{name: "ipv4-in-ipv6 value matches ipv4 addr", values: []string{"::ffff:10.0.0.5"}, addr: "10.0.0.5", want: true},
		{name: "ipv4-in-ipv6 cidr is unmapped and matches ipv4 addr", values: []string{"::ffff:10.0.0.0/120"}, addr: "10.0.0.5", want: true},
		{name: "crlf from a CEL rendered list is trimmed", values: []string{"10.0.0.5\r\n"}, addr: "10.0.0.5", want: true},
		{name: "empty value never matches", values: []string{"", "  "}, addr: "10.0.0.5"},
		{name: "unparseable value is skipped", values: []string{"example.com", "10.0.0.0/notacidr"}, addr: "10.0.0.5"},
		{name: "ipv6 value is skipped", values: []string{"2001:db8::/32", "10.0.0.5"}, addr: "10.0.0.5", want: true},
		{name: "no values", values: nil, addr: "10.0.0.5"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newNetMatcher(tc.values)
			if got := m.matches(netip.MustParseAddr(tc.addr)); got != tc.want {
				t.Errorf("matches(%s) = %v, want %v", tc.addr, got, tc.want)
			}
			if m.star != tc.wantStar {
				t.Errorf("star = %v, want %v", m.star, tc.wantStar)
			}
		})
	}
}

func TestNetMatcher_InvalidAddrNeverMatches(t *testing.T) {
	m := newNetMatcher([]string{"0.0.0.0/0", "10.0.0.5"})
	if m.matches(netip.Addr{}) {
		t.Error("the zero address matched")
	}
}

func TestPathMatcher(t *testing.T) {
	tests := []struct {
		name     string
		values   []string
		path     string
		want     bool
		wantStar bool
	}{
		{name: "exact path", values: []string{"/etc/shadow"}, path: "/etc/shadow", want: true},
		{name: "different path", values: []string{"/etc/shadow"}, path: "/etc/hosts"},
		// the kernel maps are keyed on the exact path string, so monitor must
		// not invent prefix or glob semantics the enforcer does not have
		{name: "parent directory is not a match", values: []string{"/etc"}, path: "/etc/shadow"},
		{name: "glob is not expanded", values: []string{"/etc/*"}, path: "/etc/shadow"},
		{name: "star is not an explicit match", values: []string{compiler.StarTarget}, path: "/etc/shadow", wantStar: true},
		{name: "empty value", values: []string{""}, path: "/etc/shadow"},
		{name: "empty path never matches", values: []string{"/etc/shadow"}, path: ""},
		{name: "no values", values: nil, path: "/etc/shadow"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newPathMatcher(tc.values)
			if got := m.matches(tc.path); got != tc.want {
				t.Errorf("matches(%q) = %v, want %v", tc.path, got, tc.want)
			}
			if m.star != tc.wantStar {
				t.Errorf("star = %v, want %v", m.star, tc.wantStar)
			}
		})
	}
}

func TestProtoMatcher(t *testing.T) {
	tests := []struct {
		name     string
		values   []string
		protocol string
		alpn     string
		want     bool
		wantStar bool
	}{
		{name: "bare token matches", values: []string{"ssh"}, protocol: "ssh", want: true},
		{name: "bare token miss", values: []string{"ssh"}, protocol: "tls"},
		{name: "bare tls matches any ALPN", values: []string{"tls"}, protocol: "tls", alpn: "h2", want: true},
		{name: "bare tls matches tls without ALPN", values: []string{"tls"}, protocol: "tls", want: true},
		{name: "tls with ALPN matches exactly that ALPN", values: []string{"tls/h2"}, protocol: "tls", alpn: "h2", want: true},
		{name: "tls with ALPN misses another ALPN", values: []string{"tls/h2"}, protocol: "tls", alpn: "http/1.1"},
		{name: "tls with ALPN misses tls without ALPN", values: []string{"tls/h2"}, protocol: "tls"},
		{name: "ALPN comparison is case-sensitive", values: []string{"tls/h2"}, protocol: "tls", alpn: "H2"},
		{name: "unknown is an ordinary token", values: []string{"unknown"}, protocol: "unknown", want: true},
		{name: "star is not an explicit match", values: []string{compiler.StarTarget}, protocol: "ssh", wantStar: true},
		{name: "star plus explicit value", values: []string{compiler.StarTarget, "ssh"}, protocol: "ssh", want: true, wantStar: true},
		{name: "unparseable value is skipped", values: []string{"grpc", "ssh"}, protocol: "ssh", want: true},
		{name: "empty protocol never matches", values: []string{"ssh"}, protocol: ""},
		{name: "no values", values: nil, protocol: "ssh"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newProtoMatcher(tc.values)
			if got := m.matches(tc.protocol, tc.alpn); got != tc.want {
				t.Errorf("matches(%q, %q) = %v, want %v", tc.protocol, tc.alpn, got, tc.want)
			}
			if m.star != tc.wantStar {
				t.Errorf("star = %v, want %v", m.star, tc.wantStar)
			}
		})
	}
}

func TestProtoBehaviorEval(t *testing.T) {
	tests := []struct {
		name            string
		allow, deny     []string
		protocol        string
		alpn            string
		wantViolation   bool
		wantDefaultDeny bool
	}{
		{name: "explicit deny", deny: []string{"ssh"}, protocol: "ssh", wantViolation: true},
		{
			name: "default deny not allowed", allow: []string{"tls/h2"}, deny: []string{compiler.StarTarget},
			protocol: "ssh", wantViolation: true, wantDefaultDeny: true,
		},
		{name: "default deny allowed by exact ALPN", allow: []string{"tls/h2"}, deny: []string{compiler.StarTarget}, protocol: "tls", alpn: "h2"},
		{
			name: "default deny with another ALPN", allow: []string{"tls/h2"}, deny: []string{compiler.StarTarget},
			protocol: "tls", alpn: "http/1.1", wantViolation: true, wantDefaultDeny: true,
		},
		{name: "default deny with allowed bare tls covers any ALPN", allow: []string{"tls"}, deny: []string{compiler.StarTarget}, protocol: "tls", alpn: "h2"},
		{
			name: "unknown is default-denied when not allowed", allow: []string{"tls"}, deny: []string{compiler.StarTarget},
			protocol: "unknown", wantViolation: true, wantDefaultDeny: true,
		},
		{name: "allowed unknown is not folded into star", allow: []string{"unknown"}, deny: []string{compiler.StarTarget}, protocol: "unknown"},
		{name: "explicit unknown deny", deny: []string{"unknown"}, protocol: "unknown", wantViolation: true},
		{name: "allow only, no deny", allow: []string{"ssh"}, protocol: "tls"},
		{name: "empty protocol", deny: []string{compiler.StarTarget}, protocol: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := compileProtocolBehavior(&compiler.AllowDenyPair{Allow: tc.allow, Deny: tc.deny})
			got := b.eval(tc.protocol, tc.alpn)
			if got.violation != tc.wantViolation || got.defaultDeny != tc.wantDefaultDeny {
				t.Errorf("eval(%q, %q) = %+v, want {violation:%v defaultDeny:%v}",
					tc.protocol, tc.alpn, got, tc.wantViolation, tc.wantDefaultDeny)
			}
		})
	}
}

func TestBehaviorsWithoutEntriesAreAbsent(t *testing.T) {
	for _, p := range []*compiler.AllowDenyPair{nil, {}, {Allow: nil, Deny: nil}} {
		nb := compileNetBehavior(p)
		if nb != nil {
			t.Errorf("net behavior for %+v = %+v, want nil", p, nb)
		}
		if nb.eval(netip.MustParseAddr("10.0.0.5")).violation {
			t.Errorf("absent net behavior for %+v reported a violation", p)
		}
		pb := compilePathBehavior(p)
		if pb != nil {
			t.Errorf("path behavior for %+v = %+v, want nil", p, pb)
		}
		if pb.eval("/etc/shadow").violation {
			t.Errorf("absent path behavior for %+v reported a violation", p)
		}
		prb := compileProtocolBehavior(p)
		if prb != nil {
			t.Errorf("protocol behavior for %+v = %+v, want nil", p, prb)
		}
		if prb.eval("ssh", "").violation {
			t.Errorf("absent protocol behavior for %+v reported a violation", p)
		}
	}
}

func TestNetBehaviorEval(t *testing.T) {
	tests := []struct {
		name            string
		allow, deny     []string
		addr            string
		wantViolation   bool
		wantDefaultDeny bool
	}{
		{name: "explicit deny", deny: []string{"10.0.0.5"}, addr: "10.0.0.5", wantViolation: true},
		{
			name: "explicit deny wins over allow of the same value",
			// contradictory policy: the kernel banned map is consulted first,
			// so deny wins here too
			allow: []string{"10.0.0.5"}, deny: []string{"10.0.0.5"}, addr: "10.0.0.5", wantViolation: true,
		},
		{
			name: "default deny not allowed", allow: []string{"10.0.0.1"}, deny: []string{compiler.StarTarget},
			addr: "10.0.0.5", wantViolation: true, wantDefaultDeny: true,
		},
		{name: "default deny allowed", allow: []string{"10.0.0.5"}, deny: []string{compiler.StarTarget}, addr: "10.0.0.5"},
		{name: "allow only, no deny", allow: []string{"10.0.0.1"}, addr: "10.0.0.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := compileNetBehavior(&compiler.AllowDenyPair{Allow: tc.allow, Deny: tc.deny})
			got := b.eval(netip.MustParseAddr(tc.addr))
			if got.violation != tc.wantViolation || got.defaultDeny != tc.wantDefaultDeny {
				t.Errorf("eval(%s) = %+v, want {violation:%v defaultDeny:%v}",
					tc.addr, got, tc.wantViolation, tc.wantDefaultDeny)
			}
		})
	}
}

func TestPathBehaviorEval(t *testing.T) {
	tests := []struct {
		name            string
		allow, deny     []string
		path            string
		wantViolation   bool
		wantDefaultDeny bool
	}{
		{name: "explicit deny", deny: []string{"/etc/shadow"}, path: "/etc/shadow", wantViolation: true},
		{
			name: "default deny not allowed", allow: []string{"/etc/hosts"}, deny: []string{compiler.StarTarget},
			path: "/etc/shadow", wantViolation: true, wantDefaultDeny: true,
		},
		{name: "default deny allowed", allow: []string{"/etc/shadow"}, deny: []string{compiler.StarTarget}, path: "/etc/shadow"},
		{name: "allow only, no deny", allow: []string{"/etc/hosts"}, path: "/etc/shadow"},
		{name: "empty path", deny: []string{compiler.StarTarget}, path: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := compilePathBehavior(&compiler.AllowDenyPair{Allow: tc.allow, Deny: tc.deny})
			got := b.eval(tc.path)
			if got.violation != tc.wantViolation || got.defaultDeny != tc.wantDefaultDeny {
				t.Errorf("eval(%q) = %+v, want {violation:%v defaultDeny:%v}",
					tc.path, got, tc.wantViolation, tc.wantDefaultDeny)
			}
		})
	}
}
