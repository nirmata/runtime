package egressfilter

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// addrStrings renders addresses for comparison: netip.Addr has unexported
// fields and no Equal method, so cmp cannot diff it directly.
func addrStrings(in []netip.Addr) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.String())
	}
	return out
}

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name         string
		values       []string
		wantAddrs    []string
		wantStar     bool
		wantRejected []RejectedTarget
	}{
		{
			name: "nil input",
		},
		{
			name:      "single IPv4 literal",
			values:    []string{"10.0.0.1"},
			wantAddrs: []string{"10.0.0.1"},
		},
		{
			name:      "multiple IPv4 literals keep order",
			values:    []string{"10.0.0.2", "10.0.0.1", "192.168.1.7"},
			wantAddrs: []string{"10.0.0.2", "10.0.0.1", "192.168.1.7"},
		},
		{
			name:      "duplicate literals are collapsed",
			values:    []string{"10.0.0.1", "10.0.0.1"},
			wantAddrs: []string{"10.0.0.1"},
		},
		{
			name:      "slash 32 CIDR yields one address",
			values:    []string{"10.0.0.1/32"},
			wantAddrs: []string{"10.0.0.1"},
		},
		{
			name:      "slash 31 CIDR yields two addresses",
			values:    []string{"10.0.0.0/31"},
			wantAddrs: []string{"10.0.0.0", "10.0.0.1"},
		},
		{
			name:      "slash 30 CIDR includes network and broadcast",
			values:    []string{"10.0.0.4/30"},
			wantAddrs: []string{"10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"},
		},
		{
			name:      "CIDR with host bits set is masked first",
			values:    []string{"10.0.0.6/30"},
			wantAddrs: []string{"10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"},
		},
		{
			name:         "slash 23 CIDR is rejected as too wide",
			values:       []string{"10.0.0.0/23"},
			wantRejected: []RejectedTarget{{Value: "10.0.0.0/23", Reason: ReasonCIDRTooWide}},
		},
		{
			name:         "slash 8 CIDR is rejected as too wide",
			values:       []string{"10.0.0.0/8"},
			wantRejected: []RejectedTarget{{Value: "10.0.0.0/8", Reason: ReasonCIDRTooWide}},
		},
		{
			name:         "slash 0 CIDR is rejected as too wide, not treated as default deny",
			values:       []string{"0.0.0.0/0"},
			wantRejected: []RejectedTarget{{Value: "0.0.0.0/0", Reason: ReasonCIDRTooWide}},
		},
		{
			name:         "IPv6 literal is rejected",
			values:       []string{"2001:db8::1"},
			wantRejected: []RejectedTarget{{Value: "2001:db8::1", Reason: ReasonIPv6}},
		},
		{
			name:         "IPv6 CIDR is rejected",
			values:       []string{"2001:db8::/126"},
			wantRejected: []RejectedTarget{{Value: "2001:db8::/126", Reason: ReasonIPv6}},
		},
		{
			name:         "IPv6 loopback is rejected",
			values:       []string{"::1"},
			wantRejected: []RejectedTarget{{Value: "::1", Reason: ReasonIPv6}},
		},
		{
			name:      "IPv4-mapped IPv6 literal is unmapped and accepted",
			values:    []string{"::ffff:10.0.0.1"},
			wantAddrs: []string{"10.0.0.1"},
		},
		{
			name:      "IPv4-mapped IPv6 CIDR is unmapped and accepted",
			values:    []string{"::ffff:10.0.0.0/126"},
			wantAddrs: []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			name:         "hostname is rejected",
			values:       []string{"api.example.com"},
			wantRejected: []RejectedTarget{{Value: "api.example.com", Reason: ReasonNotAnIP}},
		},
		{
			name:         "hostname with a path-like slash is rejected",
			values:       []string{"api.example.com/v1"},
			wantRejected: []RejectedTarget{{Value: "api.example.com/v1", Reason: ReasonNotAnIP}},
		},
		{
			name:         "truncated IPv4 is rejected",
			values:       []string{"10.0.0."},
			wantRejected: []RejectedTarget{{Value: "10.0.0.", Reason: ReasonNotAnIP}},
		},
		{
			name:         "out of range prefix length is rejected",
			values:       []string{"10.0.0.1/33"},
			wantRejected: []RejectedTarget{{Value: "10.0.0.1/33", Reason: ReasonNotAnIP}},
		},
		{
			name:         "empty value is rejected, not ignored",
			values:       []string{""},
			wantRejected: []RejectedTarget{{Value: "", Reason: ReasonEmpty}},
		},
		{
			name:         "whitespace-only value is rejected as empty",
			values:       []string{"  \t"},
			wantRejected: []RejectedTarget{{Value: "  \t", Reason: ReasonEmpty}},
		},
		{
			name:      "surrounding whitespace is trimmed",
			values:    []string{"  10.0.0.1\t"},
			wantAddrs: []string{"10.0.0.1"},
		},
		{
			name:      "surrounding quotes are trimmed",
			values:    []string{"\"10.0.0.1\"", "'10.0.0.2'"},
			wantAddrs: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:      "surrounding brackets are trimmed",
			values:    []string{"[10.0.0.1]"},
			wantAddrs: []string{"10.0.0.1"},
		},
		{
			name:      "newline from a CEL rendered list is trimmed",
			values:    []string{"10.0.0.1\n"},
			wantAddrs: []string{"10.0.0.1"},
		},
		{
			name:     "star is the default deny sentinel and yields no address",
			values:   []string{"*"},
			wantStar: true,
		},
		{
			name:      "star mixes with literals",
			values:    []string{"*", "10.0.0.1"},
			wantAddrs: []string{"10.0.0.1"},
			wantStar:  true,
		},
		{
			name:      "quoted star still sets the sentinel",
			values:    []string{"\" * \""},
			wantAddrs: nil,
			wantStar:  true,
		},
		{
			name:      "mixed valid and invalid keeps the valid ones and reports the rest",
			values:    []string{"10.0.0.1", "2001:db8::1", "10.0.0.0/8", "api.example.com", "10.0.0.2/32", "*"},
			wantAddrs: []string{"10.0.0.1", "10.0.0.2"},
			wantStar:  true,
			wantRejected: []RejectedTarget{
				{Value: "2001:db8::1", Reason: ReasonIPv6},
				{Value: "10.0.0.0/8", Reason: ReasonCIDRTooWide},
				{Value: "api.example.com", Reason: ReasonNotAnIP},
			},
		},
		{
			name:      "overlapping CIDR and literal are deduplicated",
			values:    []string{"10.0.0.0/30", "10.0.0.2"},
			wantAddrs: []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAddrs, gotStar, gotRejected := ParseTargets(tc.values)

			if diff := cmp.Diff(tc.wantAddrs, addrStrings(gotAddrs)); diff != "" {
				t.Errorf("addrs mismatch (-want +got):\n%s", diff)
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

func TestParseTargets_ExpandsSlash24ToTheCap(t *testing.T) {
	got, star, rejected := ParseTargets([]string{"192.168.5.0/24"})
	if star {
		t.Error("star = true, want false")
	}
	if len(rejected) != 0 {
		t.Errorf("rejected = %v, want none", rejected)
	}
	if len(got) != MaxExpandedTargets {
		t.Fatalf("len(addrs) = %d, want %d", len(got), MaxExpandedTargets)
	}
	if want := netip.MustParseAddr("192.168.5.0"); got[0] != want {
		t.Errorf("first = %s, want %s", got[0], want)
	}
	if want := netip.MustParseAddr("192.168.5.255"); got[len(got)-1] != want {
		t.Errorf("last = %s, want %s", got[len(got)-1], want)
	}

	seen := make(map[netip.Addr]struct{}, len(got))
	for _, a := range got {
		if _, dup := seen[a]; dup {
			t.Fatalf("duplicate address %s in expansion", a)
		}
		seen[a] = struct{}{}
	}
}

func TestParseTargets_ExpandsTopOfAddressSpaceWithoutWrapping(t *testing.T) {
	got, _, rejected := ParseTargets([]string{"255.255.255.252/30"})
	if len(rejected) != 0 {
		t.Errorf("rejected = %v, want none", rejected)
	}
	want := []string{"255.255.255.252", "255.255.255.253", "255.255.255.254", "255.255.255.255"}
	if diff := cmp.Diff(want, addrStrings(got)); diff != "" {
		t.Errorf("addrs mismatch (-want +got):\n%s", diff)
	}
}

func TestRejectedTarget_StringNamesValueAndReason(t *testing.T) {
	got := RejectedTarget{Value: "2001:db8::1", Reason: ReasonIPv6}.String()
	want := `"2001:db8::1": ` + ReasonIPv6
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestAddrKey_RoundTripsThroughTheMapKeyEncoding(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "1.2.3.4", "10.0.0.1", "192.168.255.254", "255.255.255.255"} {
		addr := netip.MustParseAddr(s)
		key, ok := addrKey(addr)
		if !ok {
			t.Fatalf("addrKey(%s) not ok", s)
		}
		if got := keyAddr(key); got != addr {
			t.Errorf("keyAddr(addrKey(%s)) = %s, want %s", s, got, addr)
		}
	}
}

func TestAddrKey_RejectsIPv6(t *testing.T) {
	if _, ok := addrKey(netip.MustParseAddr("2001:db8::1")); ok {
		t.Error("addrKey accepted an IPv6 address")
	}
}
