package aicontrols

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	testNS  = "aicontrols"
	testSvc = "aicontrols-proxy"
)

func testConfig() Config {
	return Config{Namespace: testNS, ServiceName: testSvc, Refresh: time.Hour}
}

func service(clusterIPs []string, ports []int32) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: testSvc},
		Spec:       corev1.ServiceSpec{ClusterIPs: clusterIPs},
	}
	if len(clusterIPs) > 0 {
		svc.Spec.ClusterIP = clusterIPs[0]
	}
	for _, p := range ports {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: p})
	}
	return svc
}

func slice(name string, addrs []string, port int32) *discoveryv1.EndpointSlice {
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNS,
			Name:      name,
			Labels:    map[string]string{discoveryv1.LabelServiceName: testSvc},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: addrs}},
	}
	if port > 0 {
		p := port
		es.Ports = []discoveryv1.EndpointPort{{Port: &p}}
	}
	return es
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return a
}

func newReady(t *testing.T, objs ...runtime.Object) (*EndpointResolver, *fake.Clientset) {
	t.Helper()
	cs := fake.NewClientset(objs...)
	r := NewEndpointResolver(cs, testConfig(), logr.Discard())
	if !r.Enabled() {
		t.Fatalf("resolver should be enabled for %+v", testConfig())
	}
	if err := r.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !r.Ready() {
		t.Fatal("resolver should be ready after a successful refresh")
	}
	return r, cs
}

func TestRefreshBuildsEndpointSetFromServiceAndEndpointSlices(t *testing.T) {
	tests := []struct {
		name      string
		objs      []runtime.Object
		wantAddrs []string
	}{{
		name:      "cluster ip only",
		objs:      []runtime.Object{service([]string{"10.96.14.22"}, []int32{8080})},
		wantAddrs: []string{"10.96.14.22"},
	}, {
		name: "cluster ip plus endpoints",
		objs: []runtime.Object{
			service([]string{"10.96.14.22"}, []int32{8080}),
			slice("s1", []string{"10.244.1.5", "10.244.2.9"}, 8080),
		},
		wantAddrs: []string{"10.96.14.22", "10.244.1.5", "10.244.2.9"},
	}, {
		name: "multiple slices merge",
		objs: []runtime.Object{
			service([]string{"10.96.14.22"}, []int32{8080}),
			slice("s1", []string{"10.244.1.5"}, 8080),
			slice("s2", []string{"10.244.3.7"}, 8080),
		},
		wantAddrs: []string{"10.96.14.22", "10.244.1.5", "10.244.3.7"},
	}, {
		name: "dual stack cluster ips",
		objs: []runtime.Object{service([]string{"10.96.14.22", "fd00::1"}, []int32{8080})},
		wantAddrs: []string{
			"10.96.14.22", "fd00::1",
		},
	}, {
		name: "headless service contributes only endpoints",
		objs: []runtime.Object{
			service([]string{corev1.ClusterIPNone}, []int32{8080}),
			slice("s1", []string{"10.244.1.5"}, 8080),
		},
		wantAddrs: []string{"10.244.1.5"},
	}, {
		name: "external and load balancer addresses count",
		objs: []runtime.Object{func() runtime.Object {
			svc := service([]string{"10.96.14.22"}, []int32{8080})
			svc.Spec.ExternalIPs = []string{"192.0.2.10"}
			svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
				{IP: "198.51.100.4"}, {Hostname: "lb.example.com"},
			}
			return svc
		}()},
		wantAddrs: []string{"10.96.14.22", "192.0.2.10", "198.51.100.4"},
	}, {
		name: "unparseable and empty addresses are skipped",
		objs: []runtime.Object{
			service([]string{"10.96.14.22"}, []int32{8080}),
			slice("s1", []string{"", "not-an-ip", "0.0.0.0", "10.244.1.5"}, 8080),
		},
		wantAddrs: []string{"10.96.14.22", "10.244.1.5"},
	}, {
		name: "slice for another service is ignored",
		objs: []runtime.Object{
			service([]string{"10.96.14.22"}, []int32{8080}),
			func() runtime.Object {
				es := slice("other", []string{"10.244.9.9"}, 8080)
				es.Labels[discoveryv1.LabelServiceName] = "some-other-service"
				return es
			}(),
		},
		wantAddrs: []string{"10.96.14.22"},
	}, {
		name:      "service with no addresses yields an empty set",
		objs:      []runtime.Object{service(nil, nil)},
		wantAddrs: nil,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset(tc.objs...)
			r := NewEndpointResolver(cs, testConfig(), logr.Discard())
			if err := r.refresh(context.Background()); err != nil {
				t.Fatalf("refresh: %v", err)
			}

			var want []netip.Addr
			for _, a := range tc.wantAddrs {
				want = append(want, mustAddr(t, a))
			}
			sortAddrs(want)

			if diff := cmp.Diff(want, r.Addrs(), cmp.Comparer(func(a, b netip.Addr) bool {
				return a == b
			})); diff != "" {
				t.Errorf("endpoint set mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRefreshRepublishesSetWhenEndpointsChange(t *testing.T) {
	svc := service([]string{"10.96.14.22"}, []int32{8080})
	es := slice("s1", []string{"10.244.1.5"}, 8080)
	r, cs := newReady(t, svc, es)

	if !r.IsProxyAddr(mustAddr(t, "10.244.1.5")) {
		t.Fatal("initial endpoint should be a proxy address")
	}

	// Scale: 10.244.1.5 goes away, 10.244.4.4 appears.
	updated := slice("s1", []string{"10.244.4.4"}, 8080)
	if _, err := cs.DiscoveryV1().EndpointSlices(testNS).Update(context.Background(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating endpointslice: %v", err)
	}
	if err := r.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if r.IsProxyAddr(mustAddr(t, "10.244.1.5")) {
		t.Error("removed endpoint should no longer be a proxy address")
	}
	if !r.IsProxyAddr(mustAddr(t, "10.244.4.4")) {
		t.Error("new endpoint should be a proxy address")
	}
	if !r.IsProxyAddr(mustAddr(t, "10.96.14.22")) {
		t.Error("cluster ip should still be a proxy address")
	}
	if got := r.Refreshes(); got != 2 {
		t.Errorf("Refreshes() = %d, want 2", got)
	}
}

func TestIsProxyAddr(t *testing.T) {
	r, _ := newReady(t,
		service([]string{"10.96.14.22", "fd00::1"}, []int32{8080}),
		slice("s1", []string{"10.244.1.5"}, 8080),
	)

	tests := []struct {
		name string
		addr netip.Addr
		want bool
	}{
		{name: "cluster ip", addr: mustAddr(t, "10.96.14.22"), want: true},
		{name: "ipv6 cluster ip", addr: mustAddr(t, "fd00::1"), want: true},
		{name: "endpoint ip", addr: mustAddr(t, "10.244.1.5"), want: true},
		{name: "ipv4 mapped form of cluster ip", addr: mustAddr(t, "::ffff:10.96.14.22"), want: true},
		{name: "provider ip", addr: mustAddr(t, "104.18.7.192"), want: false},
		{name: "other pod ip", addr: mustAddr(t, "10.244.9.9"), want: false},
		{name: "zero address", addr: netip.Addr{}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.IsProxyAddr(tc.addr); got != tc.want {
				t.Errorf("IsProxyAddr(%v) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestIsProxyAddrPortMatchesServiceAndEndpointPorts(t *testing.T) {
	r, _ := newReady(t,
		service([]string{"10.96.14.22"}, []int32{8080}),
		slice("s1", []string{"10.244.1.5"}, 9090),
	)

	tests := []struct {
		name string
		ap   string
		want bool
	}{
		{name: "cluster ip and service port", ap: "10.96.14.22:8080", want: true},
		{name: "cluster ip wrong port", ap: "10.96.14.22:443", want: false},
		{name: "endpoint ip and endpoint port", ap: "10.244.1.5:9090", want: true},
		{name: "endpoint ip service port", ap: "10.244.1.5:8080", want: false},
		{name: "unrelated", ap: "104.18.7.192:443", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ap, err := netip.ParseAddrPort(tc.ap)
			if err != nil {
				t.Fatalf("parsing %q: %v", tc.ap, err)
			}
			if got := r.IsProxyAddrPort(ap); got != tc.want {
				t.Errorf("IsProxyAddrPort(%s) = %v, want %v", tc.ap, got, tc.want)
			}
		})
	}
}

func TestIsProxyAddrOnUnrefreshedResolverIsFalse(t *testing.T) {
	r := NewEndpointResolver(fake.NewClientset(), testConfig(), logr.Discard())
	if r.Ready() {
		t.Error("resolver must not be ready before the first refresh")
	}
	if r.IsProxyAddr(mustAddr(t, "10.96.14.22")) {
		t.Error("IsProxyAddr must be false with an unpopulated set")
	}
	if got := r.Addrs(); got != nil {
		t.Errorf("Addrs() = %v, want nil", got)
	}
}

func TestNewEndpointResolverDisabledConfigurations(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		client bool
	}{
		{name: "no service name", cfg: Config{Namespace: testNS}, client: true},
		{name: "service without namespace", cfg: Config{ServiceName: testSvc}, client: true},
		{name: "empty config", cfg: Config{}, client: true},
		{name: "nil client", cfg: testConfig(), client: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cs *fake.Clientset
			r := NewEndpointResolver(nil, tc.cfg, logr.Discard())
			if tc.client {
				cs = fake.NewClientset()
				r = NewEndpointResolver(cs, tc.cfg, logr.Discard())
			}

			if r.Enabled() {
				t.Fatal("resolver must be disabled")
			}
			if err := r.Run(context.Background()); err != nil {
				t.Errorf("Run on a disabled resolver = %v, want nil", err)
			}
			if r.Ready() {
				t.Error("disabled resolver must never become ready")
			}
			if cs != nil && len(cs.Actions()) != 0 {
				t.Errorf("disabled resolver contacted the API server: %v", cs.Actions())
			}
		})
	}
}

func TestNewEndpointResolverDefaultsRefresh(t *testing.T) {
	r := NewEndpointResolver(fake.NewClientset(), Config{Namespace: testNS, ServiceName: testSvc}, logr.Discard())
	if r.cfg.Refresh != DefaultRefresh {
		t.Errorf("Refresh = %v, want %v", r.cfg.Refresh, DefaultRefresh)
	}
}

func TestRunRefreshesThenReturnsNilOnContextCancel(t *testing.T) {
	r, _ := newReady(t, service([]string{"10.96.14.22"}, []int32{8080}))
	r.ready.Store(false)
	r.refreshes.Store(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The interval seam fires once and cancels, so Run performs exactly two
	// refreshes and then exits deterministically without sleeping.
	ticks := 0
	r.after = func(time.Duration) <-chan time.Time {
		ticks++
		if ticks >= 2 {
			cancel()
		}
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}

	if err := r.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if !r.Ready() {
		t.Error("Run must populate the endpoint set before waiting on the interval")
	}
	if got := r.Refreshes(); got < 2 {
		t.Errorf("Refreshes() = %d, want >= 2", got)
	}
	if !r.IsProxyAddr(mustAddr(t, "10.96.14.22")) {
		t.Error("cluster ip should be a proxy address after Run")
	}
}

func TestRefreshFailureKeepsPreviousEndpointSet(t *testing.T) {
	r, cs := newReady(t,
		service([]string{"10.96.14.22"}, []int32{8080}),
		slice("s1", []string{"10.244.1.5"}, 8080),
	)

	wantErr := errors.New("apiserver is unhappy")
	cs.PrependReactor("get", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, wantErr
	})

	if err := r.refresh(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("refresh error = %v, want %v", err, wantErr)
	}
	if !r.Ready() {
		t.Error("a failed refresh must not clear readiness")
	}
	for _, addr := range []string{"10.96.14.22", "10.244.1.5"} {
		if !r.IsProxyAddr(mustAddr(t, addr)) {
			t.Errorf("addr %s must survive a failed refresh", addr)
		}
	}
}

func TestRefreshFailureOnEndpointSliceListKeepsPreviousSet(t *testing.T) {
	r, cs := newReady(t, service([]string{"10.96.14.22"}, []int32{8080}))

	wantErr := errors.New("list forbidden")
	cs.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, wantErr
	})

	if err := r.refresh(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("refresh error = %v, want %v", err, wantErr)
	}
	if !r.IsProxyAddr(mustAddr(t, "10.96.14.22")) {
		t.Error("previous set must survive a failed endpointslice list")
	}
}

func TestRunKeepsRunningAfterRefreshFailure(t *testing.T) {
	cs := fake.NewClientset()
	r := NewEndpointResolver(cs, testConfig(), logr.Discard())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.after = func(time.Duration) <-chan time.Time {
		cancel()
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}

	// The service does not exist: refresh fails, Run must not panic, must not
	// become ready, and must still return nil on cancellation.
	if err := r.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if r.Ready() {
		t.Error("resolver must not be ready when every refresh failed")
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Run("all set", func(t *testing.T) {
		t.Setenv(EnvNamespace, "ac")
		t.Setenv(EnvService, "proxy")
		t.Setenv(EnvRefresh, "5s")

		got, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		want := Config{Namespace: "ac", ServiceName: "proxy", Refresh: 5 * time.Second}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("config mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("unset yields disabled config", func(t *testing.T) {
		t.Setenv(EnvNamespace, "")
		t.Setenv(EnvService, "")
		t.Setenv(EnvRefresh, "")

		got, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		if diff := cmp.Diff(Config{}, got); diff != "" {
			t.Errorf("config mismatch (-want +got):\n%s", diff)
		}
		if NewEndpointResolver(fake.NewClientset(), got, logr.Discard()).Enabled() {
			t.Error("resolver built from an empty env must be disabled")
		}
	})

	t.Run("bad refresh is an error not a silent default", func(t *testing.T) {
		t.Setenv(EnvService, "proxy")
		t.Setenv(EnvRefresh, "half a minute")

		if _, err := ConfigFromEnv(); err == nil {
			t.Fatal("ConfigFromEnv should reject a malformed duration")
		}
	})
}
