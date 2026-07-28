package aicontrols

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/collector"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"k8s.io/client-go/kubernetes/fake"
)

// The resolver must satisfy the collector stage seam.
var _ collector.Stage = (*EndpointResolver)(nil)

func netEvent(kind runtimeevent.Kind, ip string, port uint16) *runtimeevent.Event {
	ev := &runtimeevent.Event{
		Kind: kind,
		Pod:  runtimeevent.PodIdentity{UID: "pod-uid", Namespace: "team-a", Name: "agent-7c9f"},
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		addr = netip.Addr{}
	}
	ev.Net = &runtimeevent.NetFacts{DestIP: addr, DestPort: port, Protocol: "tcp"}
	return ev
}

func TestStageName(t *testing.T) {
	r := NewEndpointResolver(fake.NewClientset(), testConfig(), logr.Discard())
	if got := r.Name(); got != StageName {
		t.Errorf("Name() = %q, want %q", got, StageName)
	}
}

func TestProcessSetsGovernedOnlyWhenEnabledAndReady(t *testing.T) {
	// disabled and notReady build resolvers that must never stamp the bit.
	disabled := func(t *testing.T) *EndpointResolver {
		return NewEndpointResolver(fake.NewClientset(), Config{}, logr.Discard())
	}
	notReady := func(t *testing.T) *EndpointResolver {
		return NewEndpointResolver(fake.NewClientset(), testConfig(), logr.Discard())
	}

	tests := []struct {
		name string
		// resolver overrides the default ready resolver when set.
		resolver func(t *testing.T) *EndpointResolver
		ev       *runtimeevent.Event
		want     *bool // nil => Governed must stay unknown
	}{{
		name: "proxy destination is governed",
		ev:   netEvent(runtimeevent.KindNet, "10.96.14.22", 8080),
		want: ptr(true),
	}, {
		name: "backing endpoint destination is governed",
		ev:   netEvent(runtimeevent.KindNet, "10.244.1.5", 8080),
		want: ptr(true),
	}, {
		name: "provider destination is ungoverned",
		ev:   netEvent(runtimeevent.KindNet, "104.18.7.192", 443),
		want: ptr(false),
	}, {
		name: "tls event with net facts is stamped",
		ev: func() *runtimeevent.Event {
			ev := netEvent(runtimeevent.KindTLS, "104.18.7.192", 443)
			ev.TLS = &runtimeevent.TLSFacts{SNI: "api.openai.com"}
			return ev
		}(),
		want: ptr(false),
	}, {
		name: "http event with net facts is stamped",
		ev: func() *runtimeevent.Event {
			ev := netEvent(runtimeevent.KindHTTP, "10.96.14.22", 8080)
			ev.HTTP = runtimeevent.NewHTTPFacts("POST", "/v1/chat/completions", "api.openai.com", nil, nil)
			return ev
		}(),
		want: ptr(true),
	}, {
		name: "ipv4 mapped destination matches the proxy",
		ev:   netEvent(runtimeevent.KindNet, "::ffff:10.96.14.22", 8080),
		want: ptr(true),
	}, {
		name: "proxy address on a different port is still the proxy",
		ev:   netEvent(runtimeevent.KindNet, "10.96.14.22", 443),
		want: ptr(true),
	}, {
		name: "loopback stays unknown because of sidecar redirect topology",
		ev:   netEvent(runtimeevent.KindNet, "127.0.0.1", 15001),
		want: nil,
	}, {
		name: "unspecified destination stays unknown",
		ev:   netEvent(runtimeevent.KindNet, "0.0.0.0", 0),
		want: nil,
	}, {
		name: "invalid destination stays unknown",
		ev:   &runtimeevent.Event{Kind: runtimeevent.KindNet, Net: &runtimeevent.NetFacts{}},
		want: nil,
	}, {
		name: "network kind without net facts stays unknown",
		ev:   &runtimeevent.Event{Kind: runtimeevent.KindTLS, TLS: &runtimeevent.TLSFacts{SNI: "api.openai.com"}},
		want: nil,
	}, {
		name: "dns event is not stamped",
		ev: func() *runtimeevent.Event {
			ev := netEvent(runtimeevent.KindDNS, "104.18.7.192", 53)
			ev.DNS = &runtimeevent.DNSFacts{QName: "api.openai.com"}
			return ev
		}(),
		want: nil,
	}, {
		name: "exec event is not stamped",
		ev: func() *runtimeevent.Event {
			ev := netEvent(runtimeevent.KindExec, "104.18.7.192", 443)
			ev.Exec = &runtimeevent.ExecFacts{Filename: "/usr/bin/npx"}
			return ev
		}(),
		want: nil,
	}, {
		name:     "disabled resolver leaves governed unknown",
		resolver: disabled,
		ev:       netEvent(runtimeevent.KindNet, "104.18.7.192", 443),
		want:     nil,
	}, {
		name:     "enabled but not yet refreshed leaves governed unknown",
		resolver: notReady,
		ev:       netEvent(runtimeevent.KindNet, "104.18.7.192", 443),
		want:     nil,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var r *EndpointResolver
			if tc.resolver != nil {
				r = tc.resolver(t)
			} else {
				r, _ = newReady(t,
					service([]string{"10.96.14.22"}, []int32{8080}),
					slice("s1", []string{"10.244.1.5"}, 8080),
				)
			}

			if keep := r.Process(tc.ev); !keep {
				t.Fatal("Process must never drop an event")
			}

			var got *bool
			if tc.ev.Net != nil {
				got = tc.ev.Net.Governed
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Governed mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestProcessOnDisabledResolverLeavesEventUntouched(t *testing.T) {
	r := NewEndpointResolver(fake.NewClientset(), Config{}, logr.Discard())

	kinds := []runtimeevent.Kind{
		runtimeevent.KindNet, runtimeevent.KindTLS, runtimeevent.KindHTTP,
		runtimeevent.KindDNS, runtimeevent.KindExec, runtimeevent.KindOpen,
	}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			ev := netEvent(kind, "104.18.7.192", 443)
			want := *ev
			wantNet := *ev.Net

			if keep := r.Process(ev); !keep {
				t.Fatal("Process must never drop an event")
			}

			if diff := cmp.Diff(wantNet, *ev.Net, cmp.Comparer(func(a, b netip.Addr) bool { return a == b })); diff != "" {
				t.Errorf("net facts mutated (-want +got):\n%s", diff)
			}
			if want.Kind != ev.Kind || want.Pod.UID != ev.Pod.UID {
				t.Error("event fields other than Net.Governed must never be touched")
			}
		})
	}
}

func TestProcessDoesNotContactTheAPIServer(t *testing.T) {
	r, cs := newReady(t, service([]string{"10.96.14.22"}, []int32{8080}))
	before := len(cs.Actions())

	for i := 0; i < 100; i++ {
		r.Process(netEvent(runtimeevent.KindNet, "104.18.7.192", 443))
	}

	if got := len(cs.Actions()); got != before {
		t.Errorf("Process issued API calls: %d new actions (%v)", got-before, cs.Actions()[before:])
	}
}

func TestProcessNilEventIsSafe(t *testing.T) {
	r, _ := newReady(t, service([]string{"10.96.14.22"}, []int32{8080}))
	if keep := r.Process(nil); !keep {
		t.Error("Process(nil) must not drop")
	}
}

func TestGovernedFor(t *testing.T) {
	r, _ := newReady(t, service([]string{"10.96.14.22"}, []int32{8080}))

	tests := []struct {
		name      string
		addr      netip.Addr
		want      bool
		wantKnown bool
	}{
		{name: "proxy", addr: mustAddr(t, "10.96.14.22"), want: true, wantKnown: true},
		{name: "provider", addr: mustAddr(t, "104.18.7.192"), want: false, wantKnown: true},
		{name: "loopback", addr: mustAddr(t, "127.0.0.1"), wantKnown: false},
		{name: "invalid", addr: netip.Addr{}, wantKnown: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, known := r.GovernedFor(tc.addr)
			if got != tc.want || known != tc.wantKnown {
				t.Errorf("GovernedFor(%v) = (%v, %v), want (%v, %v)", tc.addr, got, known, tc.want, tc.wantKnown)
			}
		})
	}

	disabled := NewEndpointResolver(fake.NewClientset(), Config{}, logr.Discard())
	if _, known := disabled.GovernedFor(mustAddr(t, "104.18.7.192")); known {
		t.Error("a disabled resolver must report the governed bit as unknown")
	}
}

func TestProcessConcurrentWithRefresh(t *testing.T) {
	r, _ := newReady(t,
		service([]string{"10.96.14.22"}, []int32{8080}),
		slice("s1", []string{"10.244.1.5"}, 8080),
	)

	clusterIP := mustAddr(t, "10.96.14.22")

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Process(netEvent(runtimeevent.KindNet, "104.18.7.192", 443))
				r.IsProxyAddr(clusterIP)
			}
		}()
	}

	errs := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			if err := r.refresh(context.Background()); err != nil {
				select {
				case errs <- err:
				default:
				}
				return
			}
		}
	}()
	wg.Wait()

	select {
	case err := <-errs:
		t.Fatalf("refresh: %v", err)
	default:
	}
}

func ptr[T any](v T) *T { return &v }
