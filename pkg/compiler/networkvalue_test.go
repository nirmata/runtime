package compiler

import (
	"errors"
	"testing"
)

func TestParseNetworkValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		// exactly one of the want fields below is set for a valid value
		wantStar   bool
		wantAddr   string
		wantPrefix string
		wantErr    error
	}{
		{name: "IPv4 literal", in: "1.2.3.4", wantAddr: "1.2.3.4"},
		{name: "IPv4 literal with padding and quotes", in: " \"10.0.0.1\" ", wantAddr: "10.0.0.1"},
		{name: "single quotes", in: "'10.0.0.2'", wantAddr: "10.0.0.2"},
		{name: "brackets", in: "[10.0.0.1]", wantAddr: "10.0.0.1"},
		{name: "trailing newline from CEL list rendering", in: "10.0.0.1\n", wantAddr: "10.0.0.1"},
		{name: "carriage return and newline", in: "10.0.0.1\r\n", wantAddr: "10.0.0.1"},
		{name: "IPv4 CIDR /24", in: "10.0.0.0/24", wantPrefix: "10.0.0.0/24"},
		{name: "IPv4 CIDR /32", in: "10.0.0.1/32", wantPrefix: "10.0.0.1/32"},
		{name: "wide IPv4 CIDR is accepted, width is the caller's policy", in: "10.0.0.0/8", wantPrefix: "10.0.0.0/8"},
		{name: "CIDR with host bits set is masked", in: "10.0.0.6/30", wantPrefix: "10.0.0.4/30"},
		{name: "default deny sentinel", in: "*", wantStar: true},
		{name: "quoted padded sentinel", in: "\" * \"", wantStar: true},
		{name: "IPv4-mapped IPv6 literal is unmapped", in: "::ffff:1.2.3.4", wantAddr: "1.2.3.4"},
		{name: "IPv4-mapped IPv6 CIDR is unmapped", in: "::ffff:10.0.0.0/126", wantPrefix: "10.0.0.0/30"},

		{name: "IPv6 literal rejected", in: "2001:db8::1", wantErr: ErrIPv6NetworkValue},
		{name: "IPv6 CIDR rejected", in: "2001:db8::/32", wantErr: ErrIPv6NetworkValue},
		{name: "IPv6 loopback rejected", in: "::1", wantErr: ErrIPv6NetworkValue},
		{name: "4-in-6 CIDR wider than the mapped range stays IPv6", in: "::ffff:10.0.0.0/64", wantErr: ErrIPv6NetworkValue},
		{name: "hostname rejected", in: "api.openai.com", wantErr: ErrNotAnIPNetworkValue},
		{name: "url rejected", in: "https://api.openai.com/v1", wantErr: ErrNotAnIPNetworkValue},
		{name: "empty string rejected", in: "", wantErr: ErrEmptyNetworkValue},
		{name: "whitespace only rejected", in: "   ", wantErr: ErrEmptyNetworkValue},
		{name: "partial address rejected", in: "10.0.0", wantErr: ErrNotAnIPNetworkValue},
		{name: "glob other than star rejected", in: "*.openai.com", wantErr: ErrNotAnIPNetworkValue},
		{name: "bad mask rejected", in: "10.0.0.0/64", wantErr: ErrNotAnIPNetworkValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNetworkValue(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseNetworkValue(%q) error = %v, want %v", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNetworkValue(%q) unexpected error = %v", tt.in, err)
			}
			if got.Star != tt.wantStar {
				t.Errorf("Star = %v, want %v", got.Star, tt.wantStar)
			}
			if tt.wantAddr != "" {
				if !got.Addr.IsValid() || got.Addr.String() != tt.wantAddr {
					t.Errorf("Addr = %v, want %s", got.Addr, tt.wantAddr)
				}
				if !got.Addr.Is4() {
					t.Errorf("Addr = %v, want an unmapped IPv4 address", got.Addr)
				}
			} else if got.Addr.IsValid() {
				t.Errorf("Addr = %v, want unset", got.Addr)
			}
			if tt.wantPrefix != "" {
				if !got.Prefix.IsValid() || got.Prefix.String() != tt.wantPrefix {
					t.Errorf("Prefix = %v, want %s", got.Prefix, tt.wantPrefix)
				}
				if !got.Prefix.Addr().Is4() {
					t.Errorf("Prefix = %v, want an unmapped IPv4 prefix", got.Prefix)
				}
			} else if got.Prefix.IsValid() {
				t.Errorf("Prefix = %v, want unset", got.Prefix)
			}
		})
	}
}
