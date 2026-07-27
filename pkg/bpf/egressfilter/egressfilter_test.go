package egressfilter

import (
	"net"
	"testing"

	"github.com/go-logr/logr"
)

// normalizeIP feeds the 4 byte keys of the allowed/banned bpf maps, so what it
// accepts and rejects is what actually gets enforced.
func TestNormalizeIP(t *testing.T) {
	discard := logr.Discard()
	e := &EgressFilter{logger: &discard}

	tests := []struct {
		name string
		in   string
		want net.IP // nil means the input must be rejected
	}{
		{name: "plain ipv4", in: "10.0.0.1", want: net.IPv4(10, 0, 0, 1).To4()},
		{name: "double quoted", in: `"10.0.0.1"`, want: net.IPv4(10, 0, 0, 1).To4()},
		{name: "single quoted", in: "'10.0.0.1'", want: net.IPv4(10, 0, 0, 1).To4()},
		{name: "bracketed", in: "[10.0.0.1]", want: net.IPv4(10, 0, 0, 1).To4()},
		{name: "surrounding whitespace", in: " \t10.0.0.1\t ", want: net.IPv4(10, 0, 0, 1).To4()},
		{name: "quoted and bracketed", in: `"[10.0.0.1]"`, want: net.IPv4(10, 0, 0, 1).To4()},
		// an ipv4 mapped ipv6 address still has a 4 byte form
		{name: "ipv4 in ipv6", in: "::ffff:10.0.0.1", want: net.IPv4(10, 0, 0, 1).To4()},
		{name: "ipv6", in: "2001:db8::1"},
		{name: "bracketed ipv6", in: "[2001:db8::1]"},
		{name: "empty", in: ""},
		{name: "whitespace only", in: "   "},
		{name: "hostname", in: "example.com"},
		{name: "cidr", in: "10.0.0.0/24"},
		{name: "ipv4 with port", in: "10.0.0.1:443"},
		{name: "out of range octet", in: "10.0.0.256"},
		{name: "garbage", in: "not-an-ip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.normalizeIP(tt.in)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("normalizeIP(%q) = %v, want nil", tt.in, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("normalizeIP(%q) = nil, want %v", tt.in, tt.want)
			}
			if len(got) != net.IPv4len {
				t.Errorf("normalizeIP(%q) returned %d bytes, want the 4 byte form", tt.in, len(got))
			}
			if !got.Equal(tt.want) {
				t.Errorf("normalizeIP(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
