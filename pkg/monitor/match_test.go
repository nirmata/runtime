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
		domain   string
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
		{name: "unparseable value is skipped", values: []string{"10.0.0.0/notacidr"}, addr: "10.0.0.5"},
		{name: "ipv6 value is skipped", values: []string{"2001:db8::/32", "10.0.0.5"}, addr: "10.0.0.5", want: true},
		{name: "no values", values: nil, addr: "10.0.0.5"},

		{
			name:   "hostname value matches the attributed domain",
			values: []string{"api.example.com"}, addr: "10.0.0.5", domain: "api.example.com", want: true,
		},
		{
			name:   "hostname value does not match an unrelated domain",
			values: []string{"api.example.com"}, addr: "10.0.0.5", domain: "evil.example.com",
		},
		{
			// the fall-through bug this guards: a hostname must never become a
			// zero-address entry that quietly matches nothing
			name:   "hostname value does not match an unattributed address",
			values: []string{"api.example.com"}, addr: "10.0.0.5",
		},
		{
			name:   "hostname value is normalized by the shared schema",
			values: []string{" \"API.Example.COM.\" "}, addr: "10.0.0.5", domain: "api.example.com", want: true,
		},
		{
			name: "wildcard value is skipped", values: []string{"*.example.com"},
			addr: "10.0.0.5", domain: "api.example.com",
		},
		{
			name:   "address value does not match on the domain alone",
			values: []string{"10.0.0.9"}, addr: "10.0.0.5", domain: "api.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newNetMatcher(tc.values)
			if got := m.matches(netip.MustParseAddr(tc.addr), tc.domain); got != tc.want {
				t.Errorf("matches(%s, %q) = %v, want %v", tc.addr, tc.domain, got, tc.want)
			}
			if m.star != tc.wantStar {
				t.Errorf("star = %v, want %v", m.star, tc.wantStar)
			}
		})
	}
}

func TestNetMatcher_InvalidAddrNeverMatches(t *testing.T) {
	m := newNetMatcher([]string{"0.0.0.0/0", "10.0.0.5", "api.example.com"})
	if m.matches(netip.Addr{}, "") {
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

func TestNameMatcher(t *testing.T) {
	tests := []struct {
		name     string
		values   []string
		qname    string
		want     bool
		wantStar bool
	}{
		{name: "exact name", values: []string{"api.openai.com"}, qname: "api.openai.com", want: true},
		{name: "different name", values: []string{"api.openai.com"}, qname: "api.anthropic.com"},
		{name: "exact entry does not cover a subdomain", values: []string{"openai.azure.com"}, qname: "foo.openai.azure.com"},
		{name: "wildcard covers one label", values: []string{"*.openai.azure.com"}, qname: "foo.openai.azure.com", want: true},
		{name: "wildcard covers several labels", values: []string{"*.openai.azure.com"}, qname: "a.b.openai.azure.com", want: true},
		{name: "wildcard does not cover the apex", values: []string{"*.openai.azure.com"}, qname: "openai.azure.com"},
		{name: "wildcard matches on a label boundary not a prefix", values: []string{"*.openai.azure.com"}, qname: "evilopenai.azure.com"},
		{name: "policy value case is normalized", values: []string{"API.OpenAI.COM."}, qname: "api.openai.com", want: true},
		{name: "wildcard policy value case is normalized", values: []string{"*.OpenAI.Azure.COM"}, qname: "foo.openai.azure.com", want: true},
		{name: "star is not an explicit match", values: []string{compiler.StarTarget}, qname: "api.openai.com", wantStar: true},
		{name: "star plus explicit value", values: []string{compiler.StarTarget, "api.openai.com"}, qname: "api.openai.com", want: true, wantStar: true},
		{name: "rejected value is skipped", values: []string{"a.*.openai.com", "10.0.0.5", "not_a_host"}, qname: "api.openai.com"},
		{name: "rejected value does not hide a valid one", values: []string{"a.*.b", "api.openai.com"}, qname: "api.openai.com", want: true},
		{name: "empty value never matches", values: []string{"", "  "}, qname: "api.openai.com"},
		{name: "empty question never matches", values: []string{"api.openai.com"}, qname: ""},
		{name: "no values", values: nil, qname: "api.openai.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newNameMatcher(tc.values)
			if got := m.matches(tc.qname); got != tc.want {
				t.Errorf("matches(%q) = %v, want %v", tc.qname, got, tc.want)
			}
			if m.star != tc.wantStar {
				t.Errorf("star = %v, want %v", m.star, tc.wantStar)
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
		if nb.eval(netip.MustParseAddr("10.0.0.5"), "api.example.com").violation {
			t.Errorf("absent net behavior for %+v reported a violation", p)
		}
		pb := compilePathBehavior(p)
		if pb != nil {
			t.Errorf("path behavior for %+v = %+v, want nil", p, pb)
		}
		if pb.eval("/etc/shadow").violation {
			t.Errorf("absent path behavior for %+v reported a violation", p)
		}
		mb := compileNameBehavior(p)
		if mb != nil {
			t.Errorf("name behavior for %+v = %+v, want nil", p, mb)
		}
		if mb.eval("api.openai.com").violation {
			t.Errorf("absent name behavior for %+v reported a violation", p)
		}
	}
}

func TestNetBehaviorEval(t *testing.T) {
	tests := []struct {
		name            string
		allow, deny     []string
		addr            string
		domain          string
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

		{
			name: "explicit deny of a hostname", deny: []string{"api.example.com"},
			addr: "10.0.0.5", domain: "api.example.com", wantViolation: true,
		},
		{
			name: "denied hostname does not implicate another domain", deny: []string{"api.example.com"},
			addr: "10.0.0.5", domain: "cdn.example.com",
		},
		{
			name: "default deny allowed by hostname", allow: []string{"api.example.com"},
			deny: []string{compiler.StarTarget}, addr: "10.0.0.5", domain: "api.example.com",
		},
		{
			// the same address without an attributed domain is still a
			// violation: the allow entry names a domain, not an address
			name: "default deny with an allowed hostname but no attribution", allow: []string{"api.example.com"},
			deny: []string{compiler.StarTarget}, addr: "10.0.0.5",
			wantViolation: true, wantDefaultDeny: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := compileNetBehavior(&compiler.AllowDenyPair{Allow: tc.allow, Deny: tc.deny})
			got := b.eval(netip.MustParseAddr(tc.addr), tc.domain)
			if got.violation != tc.wantViolation || got.defaultDeny != tc.wantDefaultDeny {
				t.Errorf("eval(%s, %q) = %+v, want {violation:%v defaultDeny:%v}",
					tc.addr, tc.domain, got, tc.wantViolation, tc.wantDefaultDeny)
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

func TestNameBehaviorEval(t *testing.T) {
	tests := []struct {
		name          string
		allow, deny   []string
		qname         string
		wantViolation bool
	}{
		{
			// the inversion: an allow list is the expected set, so a name it
			// does not cover is reportable without any deny entry
			name:  "undeclared name is reported against an allow list alone",
			allow: []string{"api.openai.com"}, qname: "api.anthropic.com", wantViolation: true,
		},
		{name: "declared name is not reported", allow: []string{"api.openai.com"}, qname: "api.openai.com"},
		{
			name:  "declared wildcard covers a subdomain",
			allow: []string{"*.openai.azure.com"}, qname: "foo.openai.azure.com",
		},
		{
			name:  "declared wildcard does not cover its apex",
			allow: []string{"*.openai.azure.com"}, qname: "openai.azure.com", wantViolation: true,
		},
		{
			name:  "declared wildcard does not cover a prefix of its suffix",
			allow: []string{"*.openai.azure.com"}, qname: "evilopenai.azure.com", wantViolation: true,
		},
		{
			name:  "deny entry is reported despite the allow list",
			allow: []string{"api.openai.com"}, deny: []string{"api.openai.com"}, qname: "api.openai.com",
			wantViolation: true,
		},
		{
			name: "deny star reports every name",
			deny: []string{compiler.StarTarget}, qname: "api.openai.com", wantViolation: true,
		},
		{
			// Narrowing a discovery policy is additive: an entry moves into
			// allow and stops being reported without the "*" coming out.
			name:  "an expected name is exempt from deny star",
			allow: []string{"api.openai.com"}, deny: []string{compiler.StarTarget}, qname: "api.openai.com",
		},
		{
			name:  "deny star still reports a name outside the allow list",
			allow: []string{"api.anthropic.com"}, deny: []string{compiler.StarTarget}, qname: "api.openai.com",
			wantViolation: true,
		},
		{
			// An explicit deny entry is more specific than the expected set.
			name:  "an explicit deny beats the allow list",
			allow: []string{"api.openai.com"}, deny: []string{"api.openai.com"}, qname: "api.openai.com",
			wantViolation: true,
		},
		{
			name:  "allow star declares every name",
			allow: []string{compiler.StarTarget}, qname: "api.openai.com",
		},
		{
			name:  "behavior whose values were all rejected is inert",
			allow: []string{"a.*.openai.com"}, qname: "api.openai.com",
		},
		{
			name: "deny only reports nothing outside the deny list",
			deny: []string{"api.openai.com"}, qname: "api.anthropic.com",
		},
		{name: "empty question is never reported", deny: []string{compiler.StarTarget}, qname: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := compileNameBehavior(&compiler.AllowDenyPair{Allow: tc.allow, Deny: tc.deny})
			got := b.eval(tc.qname)
			if got.violation != tc.wantViolation {
				t.Errorf("eval(%q) = %+v, want violation %v", tc.qname, got, tc.wantViolation)
			}
			if got.defaultDeny {
				t.Errorf("eval(%q) reported defaultDeny, which a dns behavior never has", tc.qname)
			}
		})
	}
}

func TestNameBehaviorWithEmptyExpectedSetIsInert(t *testing.T) {
	b := compileNameBehavior(&compiler.AllowDenyPair{Allow: []string{}})
	if b != nil {
		t.Fatalf("behavior with no values = %+v, want nil", b)
	}
	if b.eval("api.openai.com").violation {
		t.Error("a dns behavior declaring nothing reported a name")
	}
}
