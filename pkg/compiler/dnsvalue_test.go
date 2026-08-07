package compiler

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDNSValue(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		wantStar     bool
		wantName     string
		wantWildcard bool
		wantErr      error
	}{
		{name: "report every name sentinel", in: "*", wantStar: true},
		{name: "padded and quoted sentinel", in: "\" * \"", wantStar: true},

		{name: "exact hostname", in: "api.openai.com", wantName: "api.openai.com"},
		{name: "two label hostname", in: "example.com", wantName: "example.com"},
		{name: "hyphens and digits", in: "s3-eu-west-1.amazonaws.com", wantName: "s3-eu-west-1.amazonaws.com"},
		{name: "root dot is stripped", in: "example.com.", wantName: "example.com"},
		{name: "uppercase is lowercased", in: "API.Example.COM", wantName: "api.example.com"},
		{name: "padding, quotes and root dot", in: " \"API.Example.COM.\" ", wantName: "api.example.com"},
		{name: "trailing newline from CEL list rendering", in: "api.example.com\r\n", wantName: "api.example.com"},
		{name: "hostname at the length limit", in: longHostname(MaxDNSNameLen), wantName: longHostname(MaxDNSNameLen)},
		{name: "cluster Service name is an ordinary name here", in: "kube-dns.kube-system.svc.cluster.local", wantName: "kube-dns.kube-system.svc.cluster.local"},

		{name: "left wildcard", in: "*.openai.com", wantName: "openai.com", wantWildcard: true},
		{name: "left wildcard is lowercased", in: "*.API.Example.COM.", wantName: "api.example.com", wantWildcard: true},
		{name: "left wildcard over several labels", in: "*.eu.api.example.com", wantName: "eu.api.example.com", wantWildcard: true},

		{name: "interior wildcard rejected", in: "a.*.b.com", wantErr: ErrWildcardPositionDNSValue},
		{name: "trailing wildcard rejected", in: "api.example.*", wantErr: ErrWildcardPositionDNSValue},
		{name: "partial label wildcard rejected", in: "ap*.example.com", wantErr: ErrWildcardPositionDNSValue},
		{name: "bare wildcard label with no suffix rejected", in: "*.", wantErr: ErrWildcardPositionDNSValue},
		{name: "double wildcard rejected", in: "*.*.example.com", wantErr: ErrWildcardPositionDNSValue},
		{name: "sentinel with an adjacent label rejected", in: "*x", wantErr: ErrWildcardPositionDNSValue},

		{name: "wildcard of a single label suffix rejected", in: "*.com", wantErr: ErrNotAHostnameDNSValue},
		{name: "single label rejected", in: "localhost", wantErr: ErrNotAHostnameDNSValue},
		{name: "empty label rejected", in: "api..example.com", wantErr: ErrNotAHostnameDNSValue},
		{name: "double root dot rejected", in: "example.com..", wantErr: ErrNotAHostnameDNSValue},
		{name: "leading hyphen label rejected", in: "-api.example.com", wantErr: ErrNotAHostnameDNSValue},
		{name: "trailing hyphen label rejected", in: "api-.example.com", wantErr: ErrNotAHostnameDNSValue},
		{name: "over-long label rejected", in: strings.Repeat("a", 64) + ".com", wantErr: ErrNotAHostnameDNSValue},
		{name: "underscore rejected", in: "api_v1.example.com", wantErr: ErrNotAHostnameDNSValue},
		{name: "non-ascii rejected", in: "exämple.com", wantErr: ErrNotAHostnameDNSValue},
		{name: "address rejected", in: "1.2.3.4", wantErr: ErrNotAHostnameDNSValue},
		{name: "url rejected", in: "https://api.openai.com/v1", wantErr: ErrNotAHostnameDNSValue},
		{name: "name with port rejected", in: "api.example.com:443", wantErr: ErrNotAHostnameDNSValue},

		{name: "empty rejected", in: "", wantErr: ErrEmptyDNSValue},
		{name: "whitespace only rejected", in: "   ", wantErr: ErrEmptyDNSValue},
		{name: "over the length cap rejected", in: longHostname(MaxDNSNameLen + 1), wantErr: ErrTooLongDNSValue},
		{name: "wildcard over the length cap rejected", in: "*." + longHostname(MaxDNSNameLen), wantErr: ErrTooLongDNSValue},
		{name: "interior NUL rejected", in: "api\x00.example.com", wantErr: ErrNULDNSValue},
		{name: "NUL after a valid name rejected", in: "api.example.com\x00", wantErr: ErrNULDNSValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDNSValue(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseDNSValue(%q) error = %v, want %v", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDNSValue(%q) unexpected error = %v", tt.in, err)
			}
			if got.Star != tt.wantStar {
				t.Errorf("Star = %v, want %v", got.Star, tt.wantStar)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.Wildcard != tt.wantWildcard {
				t.Errorf("Wildcard = %v, want %v", got.Wildcard, tt.wantWildcard)
			}
		})
	}
}

// The kernel side lowercases the names it observes, so a value that keeps any
// uppercase byte would compare equal to nothing.
func TestParseDNSValueNamesAreLowercase(t *testing.T) {
	for _, in := range []string{"API.EXAMPLE.COM", "Api.Example.Com.", "*.API.Example.COM"} {
		got, err := ParseDNSValue(in)
		if err != nil {
			t.Fatalf("ParseDNSValue(%q) unexpected error = %v", in, err)
		}
		if got.Name != strings.ToLower(got.Name) {
			t.Errorf("ParseDNSValue(%q) Name = %q, want it lowercased", in, got.Name)
		}
	}
}

// Both schemas share validHostname, so within the length a dns value may carry
// an exact name is accepted by one exactly when it is accepted by the other.
// The wildcard and the length cap are the two deliberate differences, and each
// has its own test below.
func TestDNSAndNetworkSchemasAgreeOnHostnames(t *testing.T) {
	names := []string{
		"api.openai.com",
		"example.com",
		"s3-eu-west-1.amazonaws.com",
		"API.Example.COM.",
		longHostname(MaxDNSNameLen),
		"localhost",
		"api..example.com",
		"example.com..",
		"-api.example.com",
		"api-.example.com",
		strings.Repeat("a", 64) + ".com",
		"api_v1.example.com",
		"exämple.com",
		"api.example.com:443",
		"10.0.0",
		"1.2.3.4.5",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			netOK := validHostname(normalizeName(cleanValue(name)))
			_, dnsErr := ParseDNSValue(name)
			if netOK != (dnsErr == nil) {
				t.Errorf("validHostname(%q) = %v, ParseDNSValue error = %v: the two schemas disagree", name, netOK, dnsErr)
			}
		})
	}
}

func TestParseDNSValueWildcardIsRejectedAsANetworkValue(t *testing.T) {
	const value = "*.openai.com"

	got, err := ParseDNSValue(value)
	if err != nil {
		t.Fatalf("ParseDNSValue(%q) unexpected error = %v", value, err)
	}
	if !got.Wildcard || got.Name != "openai.com" {
		t.Fatalf("ParseDNSValue(%q) = %+v, want a wildcard of openai.com", value, got)
	}
	if _, err := ParseNetworkValue(value); !errors.Is(err, ErrWildcardNetworkValue) {
		t.Errorf("ParseNetworkValue(%q) error = %v, want %v", value, err, ErrWildcardNetworkValue)
	}
}

// The rejection message is the operator's only clue, so it has to name what is
// accepted instead.
func TestParseDNSValueErrorsNameTheRemedy(t *testing.T) {
	tests := []struct {
		in       string
		wantText []string
	}{
		{in: "a.*.b.com", wantText: []string{"leftmost label", `"*.example.com"`, `"*"`}},
		{in: "localhost", wantText: []string{"hostname", `"*.<hostname>"`, `"*"`}},
		{in: longHostname(MaxDNSNameLen + 1), wantText: []string{"126"}},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			_, err := ParseDNSValue(tt.in)
			if err == nil {
				t.Fatalf("ParseDNSValue(%q) error = nil, want a rejection", tt.in)
			}
			for _, want := range tt.wantText {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("ParseDNSValue(%q) error = %q, want it to contain %s", tt.in, err, want)
				}
			}
		})
	}
}

// A dns value is capped by the width of the kernel's question key, not by the DNS
// name limit, so it is stricter than a network hostname. Admitting a name the
// observer can never produce would give an author a policy that matches nothing
// while looking correct.
func TestParseDNSValueIsCappedByTheObservableWidth(t *testing.T) {
	name := longHostname(MaxDNSNameLen + 1)

	if !validHostname(normalizeName(cleanValue(name))) {
		t.Fatalf("validHostname(%d chars) = false, want true: a network hostname is not capped here", len(name))
	}
	if _, err := ParseDNSValue(name); !errors.Is(err, ErrTooLongDNSValue) {
		t.Errorf("ParseDNSValue(%d chars) error = %v, want %v", len(name), err, ErrTooLongDNSValue)
	}
}
