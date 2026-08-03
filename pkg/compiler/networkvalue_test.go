package compiler

import (
	"errors"
	"strings"
	"testing"
)

func TestParseNetworkValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		// exactly one of the want fields below is set for a valid value
		wantStar    bool
		wantAddr    string
		wantPrefix  string
		wantHost    string
		wantService *ClusterService
		wantErr     error
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

		{name: "hostname", in: "api.openai.com", wantHost: "api.openai.com"},
		{name: "two label hostname", in: "example.com", wantHost: "example.com"},
		{name: "hostname with hyphen and digits", in: "s3-eu-west-1.amazonaws.com", wantHost: "s3-eu-west-1.amazonaws.com"},
		{name: "trailing root dot is stripped", in: "example.com.", wantHost: "example.com"},
		{name: "uppercase is lowercased", in: "API.Example.COM", wantHost: "api.example.com"},
		{name: "hostname with padding, quotes and root dot", in: " \"API.Example.COM.\" ", wantHost: "api.example.com"},
		{name: "hostname with trailing newline from CEL list rendering", in: "api.example.com\r\n", wantHost: "api.example.com"},
		{name: "hostname at the length limit", in: longHostname(253), wantHost: longHostname(253)},
		{name: "label at the length limit", in: strings.Repeat("a", 63) + ".com", wantHost: strings.Repeat("a", 63) + ".com"},

		{name: "canonical Service name", in: "kube-dns.kube-system.svc.cluster.local", wantService: &ClusterService{Name: "kube-dns", Namespace: "kube-system"}},
		{name: "Service name uppercased, padded and with a root dot", in: " \"KUBE-DNS.Kube-System.SVC.Cluster.Local.\" ", wantService: &ClusterService{Name: "kube-dns", Namespace: "kube-system"}},
		{name: "namespace may start with a digit", in: "redis.2ns.svc.cluster.local", wantService: &ClusterService{Name: "redis", Namespace: "2ns"}},
		{name: "service and namespace at the label length limit", in: "a" + strings.Repeat("b", 62) + "." + strings.Repeat("c", 63) + ".svc.cluster.local", wantService: &ClusterService{Name: "a" + strings.Repeat("b", 62), Namespace: strings.Repeat("c", 63)}},

		{name: "service starting with a digit rejected", in: "1redis.default.svc.cluster.local", wantErr: ErrServiceLabelNetworkValue},
		{name: "over-long service label rejected", in: strings.Repeat("a", 64) + ".default.svc.cluster.local", wantErr: ErrServiceLabelNetworkValue},
		{name: "over-long namespace label rejected", in: "redis." + strings.Repeat("a", 64) + ".svc.cluster.local", wantErr: ErrServiceLabelNetworkValue},
		{name: "hyphenated service edge rejected", in: "-redis.default.svc.cluster.local", wantErr: ErrServiceLabelNetworkValue},
		{name: "short Service form with the cluster domain rejected", in: "kube-dns.svc.cluster.local", wantErr: ErrServiceFormNetworkValue},
		{name: "namespaced short form with the cluster domain rejected", in: "kube-dns.kube-system.cluster.local", wantErr: ErrServiceFormNetworkValue},
		{name: "pod record rejected", in: "10-1-2-3.default.pod.cluster.local", wantErr: ErrServiceFormNetworkValue},
		{name: "headless per-pod record rejected", in: "pod-0.redis.default.svc.cluster.local", wantErr: ErrServiceFormNetworkValue},
		{name: "bare svc label with the cluster domain rejected", in: "svc.cluster.local", wantErr: ErrServiceFormNetworkValue},
		{name: "Service name in another cluster domain rejected", in: "foo.bar.svc.example.com", wantErr: ErrServiceDomainNetworkValue},
		{name: "Service name in another cluster domain, single label suffix", in: "foo.bar.svc.internal", wantErr: ErrServiceDomainNetworkValue},

		{name: "external FQDN with a cluster-shaped prefix stays a host", in: "kube-dns.kube-system.example.com", wantHost: "kube-dns.kube-system.example.com"},
		{name: "two label short form stays an external host", in: "redis.default", wantHost: "redis.default"},

		{name: "hostname over the length limit rejected", in: longHostname(254), wantErr: ErrNotAnIPNetworkValue},
		{name: "label over the length limit rejected", in: strings.Repeat("a", 64) + ".com", wantErr: ErrNotAnIPNetworkValue},
		{name: "leading hyphen label rejected", in: "-api.example.com", wantErr: ErrNotAnIPNetworkValue},
		{name: "trailing hyphen label rejected", in: "api-.example.com", wantErr: ErrNotAnIPNetworkValue},
		{name: "single label rejected", in: "localhost", wantErr: ErrNotAnIPNetworkValue},
		{name: "single label with root dot rejected", in: "localhost.", wantErr: ErrNotAnIPNetworkValue},
		{name: "empty label rejected", in: "api..example.com", wantErr: ErrNotAnIPNetworkValue},
		{name: "double root dot rejected", in: "example.com..", wantErr: ErrNotAnIPNetworkValue},
		{name: "underscore rejected", in: "api_v1.example.com", wantErr: ErrNotAnIPNetworkValue},
		{name: "non-ascii rejected", in: "exämple.com", wantErr: ErrNotAnIPNetworkValue},
		{name: "over-long dotted address rejected", in: "1.2.3.4.5", wantErr: ErrNotAnIPNetworkValue},
		{name: "hostname with port rejected", in: "api.example.com:443", wantErr: ErrNotAnIPNetworkValue},
		{name: "wildcard hostname rejected", in: "*.openai.com", wantErr: ErrWildcardNetworkValue},
		{name: "wildcard address rejected", in: "10.0.*.1", wantErr: ErrWildcardNetworkValue},
		{name: "wildcard CIDR rejected", in: "10.0.*.0/24", wantErr: ErrWildcardNetworkValue},

		{name: "IPv6 literal rejected", in: "2001:db8::1", wantErr: ErrIPv6NetworkValue},
		{name: "IPv6 CIDR rejected", in: "2001:db8::/32", wantErr: ErrIPv6NetworkValue},
		{name: "IPv6 loopback rejected", in: "::1", wantErr: ErrIPv6NetworkValue},
		{name: "4-in-6 CIDR wider than the mapped range stays IPv6", in: "::ffff:10.0.0.0/64", wantErr: ErrIPv6NetworkValue},
		{name: "url rejected", in: "https://api.openai.com/v1", wantErr: ErrNotAnIPNetworkValue},
		{name: "empty string rejected", in: "", wantErr: ErrEmptyNetworkValue},
		{name: "whitespace only rejected", in: "   ", wantErr: ErrEmptyNetworkValue},
		{name: "partial address rejected", in: "10.0.0", wantErr: ErrNotAnIPNetworkValue},
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
			if got.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tt.wantHost)
			}
			if tt.wantService != nil {
				if got.Service == nil || *got.Service != *tt.wantService {
					t.Errorf("Service = %+v, want %+v", got.Service, tt.wantService)
				}
				if got.Host != "" {
					t.Errorf("Host = %q, want empty for a Service value", got.Host)
				}
			} else if got.Service != nil {
				t.Errorf("Service = %+v, want unset", got.Service)
			}
		})
	}
}

// The rejection message is an operator's only clue, so it has to name the
// canonical form, this cluster's domain, and what the value actually was.
func TestParseNetworkValueServiceErrorsNameTheRemedy(t *testing.T) {
	tests := []struct {
		in       string
		wantErr  error
		wantText []string
	}{
		{
			in:       "10-1-2-3.default.pod.cluster.local",
			wantErr:  ErrServiceFormNetworkValue,
			wantText: []string{"pod DNS record", `"<service>.<namespace>.svc.<cluster-domain>"`, `"cluster.local"`},
		},
		{
			in:       "pod-0.redis.default.svc.cluster.local",
			wantErr:  ErrServiceFormNetworkValue,
			wantText: []string{"per-pod DNS record", `"<service>.<namespace>.svc.<cluster-domain>"`, `"cluster.local"`},
		},
		{
			in:       "kube-dns.svc.cluster.local",
			wantErr:  ErrServiceFormNetworkValue,
			wantText: []string{"incomplete", `"<service>.<namespace>.svc.<cluster-domain>"`, `"cluster.local"`},
		},
		{
			in:       "redis.default.cluster.local",
			wantErr:  ErrServiceFormNetworkValue,
			wantText: []string{"incomplete", `"<service>.<namespace>.svc.<cluster-domain>"`, `"cluster.local"`},
		},
		{
			in:       "foo.bar.svc.example.com",
			wantErr:  ErrServiceDomainNetworkValue,
			wantText: []string{`"<service>.<namespace>.svc.cluster.local"`},
		},
		{
			in:       "1redis.default.svc.cluster.local",
			wantErr:  ErrServiceLabelNetworkValue,
			wantText: []string{"must start with a letter", "namespace label", "63"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			_, err := ParseNetworkValue(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseNetworkValue(%q) error = %v, want %v", tt.in, err, tt.wantErr)
			}
			for _, want := range tt.wantText {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("ParseNetworkValue(%q) error = %q, want it to contain %s", tt.in, err, want)
				}
			}
		})
	}
}

func TestParseNetworkValueHonoursClusterDomain(t *testing.T) {
	restore := ClusterDomain
	t.Cleanup(func() { ClusterDomain = restore })
	ClusterDomain = "k8s.acme.internal"

	got, err := ParseNetworkValue("redis.default.svc.k8s.acme.internal")
	if err != nil {
		t.Fatalf("unexpected error = %v", err)
	}
	if got.Service == nil || *got.Service != (ClusterService{Name: "redis", Namespace: "default"}) {
		t.Errorf("Service = %+v, want redis/default", got.Service)
	}
	if got.Host != "" {
		t.Errorf("Host = %q, want empty for a Service value", got.Host)
	}

	_, err = ParseNetworkValue("redis.default.svc.cluster.local")
	if !errors.Is(err, ErrServiceDomainNetworkValue) {
		t.Fatalf("error = %v, want %v", err, ErrServiceDomainNetworkValue)
	}
	if !strings.Contains(err.Error(), ClusterDomain) {
		t.Errorf("error %q does not name the expected cluster domain %q", err, ClusterDomain)
	}

	_, err = ParseNetworkValue("10-1-2-3.default.pod.k8s.acme.internal")
	if !errors.Is(err, ErrServiceFormNetworkValue) {
		t.Fatalf("error = %v, want %v", err, ErrServiceFormNetworkValue)
	}
	if !strings.Contains(err.Error(), ClusterDomain) {
		t.Errorf("error %q does not name the expected cluster domain %q", err, ClusterDomain)
	}
}

// longHostname builds a syntactically valid name of exactly n characters.
func longHostname(n int) string {
	var b strings.Builder
	for b.Len() < n {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		size := min(63, n-b.Len())
		b.WriteString(strings.Repeat("a", size))
	}
	return b.String()
}
