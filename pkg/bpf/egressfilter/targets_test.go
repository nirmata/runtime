package egressfilter

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/nirmata/runtime/pkg/compiler"

	"github.com/google/go-cmp/cmp"
)

// prefixStrings renders prefixes for comparison: netip.Prefix has unexported
// fields and no Equal method, so cmp cannot diff it directly.
func prefixStrings(in []netip.Prefix) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	return out
}

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name         string
		values       []string
		wantPrefixes []string
		wantHosts    []string
		wantStar     bool
		wantRejected []compiler.RejectedTarget
	}{
		{
			name: "nil input",
		},
		{
			name:         "single IPv4 literal becomes a slash 32",
			values:       []string{"10.0.0.1"},
			wantPrefixes: []string{"10.0.0.1/32"},
		},
		{
			name:         "multiple IPv4 literals keep order",
			values:       []string{"10.0.0.2", "10.0.0.1", "192.168.1.7"},
			wantPrefixes: []string{"10.0.0.2/32", "10.0.0.1/32", "192.168.1.7/32"},
		},
		{
			name:         "duplicate literals are collapsed",
			values:       []string{"10.0.0.1", "10.0.0.1"},
			wantPrefixes: []string{"10.0.0.1/32"},
		},
		{
			name:         "a literal and its slash 32 are one prefix",
			values:       []string{"10.0.0.1", "10.0.0.1/32"},
			wantPrefixes: []string{"10.0.0.1/32"},
		},
		{
			name:         "CIDR with host bits set is masked",
			values:       []string{"10.0.0.6/30"},
			wantPrefixes: []string{"10.0.0.4/30"},
		},
		{
			name:         "prefixes differing only in host bits collapse to one",
			values:       []string{"10.0.0.1/8", "10.0.0.0/8"},
			wantPrefixes: []string{"10.0.0.0/8"},
		},
		{
			name:         "wide CIDR is kept, not expanded",
			values:       []string{"10.0.0.0/8"},
			wantPrefixes: []string{"10.0.0.0/8"},
		},
		{
			name:         "slash 0 is a prefix covering everything, not the default deny sentinel",
			values:       []string{"0.0.0.0/0"},
			wantPrefixes: []string{"0.0.0.0/0"},
		},
		{
			name:         "overlapping prefixes are both kept, the trie resolves them",
			values:       []string{"10.0.0.0/8", "10.1.0.0/16"},
			wantPrefixes: []string{"10.0.0.0/8", "10.1.0.0/16"},
		},
		{
			name:         "IPv6 literal is rejected",
			values:       []string{"2001:db8::1"},
			wantRejected: []compiler.RejectedTarget{{Value: "2001:db8::1", Reason: ReasonIPv6}},
		},
		{
			name:         "IPv6 CIDR is rejected",
			values:       []string{"2001:db8::/126"},
			wantRejected: []compiler.RejectedTarget{{Value: "2001:db8::/126", Reason: ReasonIPv6}},
		},
		{
			name:         "IPv6 loopback is rejected",
			values:       []string{"::1"},
			wantRejected: []compiler.RejectedTarget{{Value: "::1", Reason: ReasonIPv6}},
		},
		{
			name:         "IPv4-mapped IPv6 literal is unmapped and accepted",
			values:       []string{"::ffff:10.0.0.1"},
			wantPrefixes: []string{"10.0.0.1/32"},
		},
		{
			name:         "IPv4-mapped IPv6 CIDR is unmapped and accepted",
			values:       []string{"::ffff:10.0.0.0/126"},
			wantPrefixes: []string{"10.0.0.0/30"},
		},
		{
			name:      "hostname yields a host, not an address",
			values:    []string{"api.example.com"},
			wantHosts: []string{"api.example.com"},
		},
		{
			name:      "hostnames are normalized and deduplicated",
			values:    []string{"API.Example.COM.", "api.example.com", " cdn.example.com "},
			wantHosts: []string{"api.example.com", "cdn.example.com"},
		},
		{
			name:         "prefixes and hostnames are returned separately",
			values:       []string{"10.0.0.1", "api.example.com"},
			wantPrefixes: []string{"10.0.0.1/32"},
			wantHosts:    []string{"api.example.com"},
		},
		{
			name:         "wildcard hostname is rejected",
			values:       []string{"*.example.com"},
			wantRejected: []compiler.RejectedTarget{{Value: "*.example.com", Reason: ReasonWildcard}},
		},
		{
			name:         "hostname with a path-like slash is rejected",
			values:       []string{"api.example.com/v1"},
			wantRejected: []compiler.RejectedTarget{{Value: "api.example.com/v1", Reason: ReasonInvalidEntry}},
		},
		{
			name:         "single-label name is rejected",
			values:       []string{"localhost"},
			wantRejected: []compiler.RejectedTarget{{Value: "localhost", Reason: ReasonInvalidEntry}},
		},
		{
			name:         "truncated IPv4 is rejected",
			values:       []string{"10.0.0."},
			wantRejected: []compiler.RejectedTarget{{Value: "10.0.0.", Reason: ReasonInvalidEntry}},
		},
		{
			name:         "out of range prefix length is rejected",
			values:       []string{"10.0.0.1/33"},
			wantRejected: []compiler.RejectedTarget{{Value: "10.0.0.1/33", Reason: ReasonInvalidEntry}},
		},
		{
			name:         "empty value is rejected, not ignored",
			values:       []string{""},
			wantRejected: []compiler.RejectedTarget{{Value: "", Reason: ReasonEmpty}},
		},
		{
			name:         "whitespace-only value is rejected as empty",
			values:       []string{"  \t"},
			wantRejected: []compiler.RejectedTarget{{Value: "  \t", Reason: ReasonEmpty}},
		},
		{
			name:         "surrounding whitespace is trimmed",
			values:       []string{"  10.0.0.1\t"},
			wantPrefixes: []string{"10.0.0.1/32"},
		},
		{
			name:         "surrounding quotes are trimmed",
			values:       []string{"\"10.0.0.1\"", "'10.0.0.2'"},
			wantPrefixes: []string{"10.0.0.1/32", "10.0.0.2/32"},
		},
		{
			name:         "surrounding brackets are trimmed",
			values:       []string{"[10.0.0.1]"},
			wantPrefixes: []string{"10.0.0.1/32"},
		},
		{
			name:         "newline from a CEL rendered list is trimmed",
			values:       []string{"10.0.0.1\n"},
			wantPrefixes: []string{"10.0.0.1/32"},
		},
		{
			name:         "carriage return and newline are trimmed",
			values:       []string{"10.0.0.1\r\n"},
			wantPrefixes: []string{"10.0.0.1/32"},
		},
		{
			name:         "quoted CIDR is trimmed before parsing",
			values:       []string{"\"10.0.0.0/31\""},
			wantPrefixes: []string{"10.0.0.0/31"},
		},
		{
			name:         "IPv4-mapped IPv6 CIDR wider than the mapped range stays IPv6",
			values:       []string{"::ffff:10.0.0.0/64"},
			wantRejected: []compiler.RejectedTarget{{Value: "::ffff:10.0.0.0/64", Reason: ReasonIPv6}},
		},
		{
			name:     "star is the default deny sentinel and yields no prefix",
			values:   []string{"*"},
			wantStar: true,
		},
		{
			name:         "star mixes with literals",
			values:       []string{"*", "10.0.0.1"},
			wantPrefixes: []string{"10.0.0.1/32"},
			wantStar:     true,
		},
		{
			name:         "quoted star still sets the sentinel",
			values:       []string{"\" * \""},
			wantPrefixes: nil,
			wantStar:     true,
		},
		{
			name:         "mixed valid and invalid keeps the valid ones and reports the rest",
			values:       []string{"10.0.0.1", "2001:db8::1", "10.0.0.0/8", "api.example.com", "10.0.0.2/32", "*", "nope"},
			wantPrefixes: []string{"10.0.0.1/32", "10.0.0.0/8", "10.0.0.2/32"},
			wantHosts:    []string{"api.example.com"},
			wantStar:     true,
			wantRejected: []compiler.RejectedTarget{
				{Value: "2001:db8::1", Reason: ReasonIPv6},
				{Value: "nope", Reason: ReasonInvalidEntry},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotPrefixes, gotHosts, gotStar, gotRejected := ParseTargets(tc.values)

			if diff := cmp.Diff(tc.wantPrefixes, prefixStrings(gotPrefixes)); diff != "" {
				t.Errorf("prefixes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantHosts, gotHosts); diff != "" {
				t.Errorf("hosts mismatch (-want +got):\n%s", diff)
			}
			if gotStar != tc.wantStar {
				t.Errorf("star = %v, want %v", gotStar, tc.wantStar)
			}
			if diff := cmp.Diff(tc.wantRejected, gotRejected); diff != "" {
				t.Errorf("rejected mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRejectedTarget_StringNamesValueAndReason(t *testing.T) {
	got := compiler.RejectedTarget{Value: "2001:db8::1", Reason: ReasonIPv6}.String()
	want := `"2001:db8::1": ` + ReasonIPv6
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// The trie compares Addr most-significant-byte first, so the key must carry
// the address in wire order on both little- and big-endian hosts.
func TestPrefixKey_CarriesTheAddressInWireOrder(t *testing.T) {
	got, ok := prefixKey(netip.MustParsePrefix("1.2.3.4/24"))
	if !ok {
		t.Fatal("prefixKey rejected an IPv4 prefix")
	}
	want := ipv4LpmKey{Prefixlen: 24, Addr: [4]byte{1, 2, 3, 4}}
	if got != want {
		t.Errorf("prefixKey = %+v, want %+v", got, want)
	}
}

func TestPrefixKey_RejectsIPv6(t *testing.T) {
	if _, ok := prefixKey(netip.MustParsePrefix("2001:db8::/32")); ok {
		t.Error("prefixKey accepted an IPv6 prefix")
	}
}

// A DNS name whose wire form overflows the domain key must be reported, not
// truncated into a key that would match a different domain.
func TestParseTargets_RejectsNamesThatOverflowTheDomainKey(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + ".com"

	prefixes, hosts, star, rejected := ParseTargets([]string{name})

	if len(prefixes) != 0 || len(hosts) != 0 || star {
		t.Errorf("got prefixes=%v hosts=%v star=%v, want nothing programmed", prefixStrings(prefixes), hosts, star)
	}
	want := []compiler.RejectedTarget{{Value: name, Reason: ReasonDomainTooLong}}
	if diff := cmp.Diff(want, rejected); diff != "" {
		t.Errorf("rejected mismatch (-want +got):\n%s", diff)
	}
}
