package services

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func service(namespace, name, clusterIP string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.ServiceSpec{ClusterIP: clusterIP},
	}
}

func slice(namespace, name, serviceName string, addressType discoveryv1.AddressType, endpoints ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{discoveryv1.LabelServiceName: serviceName},
		},
		AddressType: addressType,
		Endpoints:   endpoints,
	}
}

func endpoint(ready *bool, addresses ...string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses:  addresses,
		Conditions: discoveryv1.EndpointConditions{Ready: ready},
	}
}

func ptr(b bool) *bool { return &b }

func start(t *testing.T, r *Resolver) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	errs := make(chan error, 1)
	go func() { errs <- r.Start(ctx) }()

	syncCtx, syncCancel := context.WithTimeout(ctx, 10*time.Second)
	defer syncCancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), r.HasSynced) {
		t.Fatal("caches did not sync")
	}
}

func started(t *testing.T, objs ...runtime.Object) *Resolver {
	t.Helper()
	r := NewResolver(fake.NewClientset(objs...), logr.Discard())
	start(t, r)
	return r
}

func TestResolveServiceClusterIPOnly(t *testing.T) {
	r := started(t, service("kube-system", "kube-dns", "10.96.0.10"))

	addrs, found := r.ResolveService("kube-system", "kube-dns")
	if !found {
		t.Fatal("expected the Service to be found")
	}
	if want := []string{"10.96.0.10"}; !reflect.DeepEqual(addrs, want) {
		t.Fatalf("got %v, want %v", addrs, want)
	}
}

func TestResolveServiceHeadlessOmitsNoneSentinel(t *testing.T) {
	r := started(t,
		service("default", "db", corev1.ClusterIPNone),
		slice("default", "db-abc", "db", discoveryv1.AddressTypeIPv4, endpoint(ptr(true), "10.244.1.5")),
	)

	addrs, found := r.ResolveService("default", "db")
	if !found {
		t.Fatal("expected the Service to be found")
	}
	if want := []string{"10.244.1.5"}; !reflect.DeepEqual(addrs, want) {
		t.Fatalf("got %v, want %v", addrs, want)
	}
	for _, addr := range addrs {
		if addr == corev1.ClusterIPNone {
			t.Fatalf(`the %q sentinel leaked into the resolved addresses: %v`, corev1.ClusterIPNone, addrs)
		}
	}
}

func TestResolveServiceReadyConditions(t *testing.T) {
	r := started(t,
		service("default", "api", ""),
		slice("default", "api-abc", "api", discoveryv1.AddressTypeIPv4,
			endpoint(ptr(true), "10.244.1.1"),
			endpoint(ptr(false), "10.244.1.2"),
			endpoint(nil, "10.244.1.3"),
		),
	)

	addrs, found := r.ResolveService("default", "api")
	if !found {
		t.Fatal("expected the Service to be found")
	}
	if want := []string{"10.244.1.1", "10.244.1.3"}; !reflect.DeepEqual(addrs, want) {
		t.Fatalf("got %v, want %v", addrs, want)
	}
}

func TestResolveServiceUnionsSlicesAndClusterIP(t *testing.T) {
	r := started(t,
		service("default", "api", "10.96.5.5"),
		slice("default", "api-1", "api", discoveryv1.AddressTypeIPv4, endpoint(ptr(true), "10.244.2.9")),
		slice("default", "api-2", "api", discoveryv1.AddressTypeIPv4,
			endpoint(ptr(true), "10.244.2.1", "10.244.2.9"),
			endpoint(nil, "10.244.10.4"),
		),
		slice("default", "other-1", "other", discoveryv1.AddressTypeIPv4, endpoint(ptr(true), "10.244.9.9")),
	)

	addrs, found := r.ResolveService("default", "api")
	if !found {
		t.Fatal("expected the Service to be found")
	}
	want := []string{"10.244.10.4", "10.244.2.1", "10.244.2.9", "10.96.5.5"}
	if !reflect.DeepEqual(addrs, want) {
		t.Fatalf("got %v, want %v (deduplicated and sorted)", addrs, want)
	}
}

func TestResolveServiceSkipsNonIPv4(t *testing.T) {
	r := started(t,
		service("default", "api", "10.96.5.5"),
		slice("default", "api-v6", "api", discoveryv1.AddressTypeIPv6, endpoint(ptr(true), "fd00::1")),
		slice("default", "api-fqdn", "api", discoveryv1.AddressTypeFQDN, endpoint(ptr(true), "api.default.svc")),
		slice("default", "api-v4", "api", discoveryv1.AddressTypeIPv4, endpoint(ptr(true), "10.244.3.3", "fd00::2")),
	)

	addrs, found := r.ResolveService("default", "api")
	if !found {
		t.Fatal("expected the Service to be found")
	}
	if want := []string{"10.244.3.3", "10.96.5.5"}; !reflect.DeepEqual(addrs, want) {
		t.Fatalf("got %v, want %v", addrs, want)
	}
}

func TestResolveServiceAbsentVersusEmpty(t *testing.T) {
	r := started(t, service("default", "scaled-to-zero", corev1.ClusterIPNone))

	if addrs, found := r.ResolveService("default", "nope"); found || len(addrs) != 0 {
		t.Fatalf("absent Service: got (%v, %v), want (empty, false)", addrs, found)
	}

	addrs, found := r.ResolveService("default", "scaled-to-zero")
	if !found {
		t.Fatal("a Service with nothing to resolve must still report found")
	}
	if len(addrs) != 0 {
		t.Fatalf("got %v, want no addresses", addrs)
	}
}

func TestResolveServiceIsNamespaceScoped(t *testing.T) {
	r := started(t,
		service("a", "api", "10.96.0.1"),
		service("b", "api", "10.96.0.2"),
		slice("b", "api-1", "api", discoveryv1.AddressTypeIPv4, endpoint(ptr(true), "10.244.0.2")),
	)

	addrs, _ := r.ResolveService("a", "api")
	if want := []string{"10.96.0.1"}; !reflect.DeepEqual(addrs, want) {
		t.Fatalf("got %v, want %v", addrs, want)
	}
}

type changed struct {
	namespace string
	name      string
}

func collect(t *testing.T, r *Resolver) chan changed {
	t.Helper()
	notified := make(chan changed, 32)
	r.AddChangeHandler(func(namespace, name string) {
		select {
		case notified <- changed{namespace: namespace, name: name}:
		default:
		}
	})
	return notified
}

func awaitChange(t *testing.T, notified chan changed, want changed) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case got := <-notified:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for a change notification for %v", want)
		}
	}
}

func TestChangeHandlerFiresForServiceUpdate(t *testing.T) {
	client := fake.NewClientset(service("default", "api", "10.96.0.1"))
	r := NewResolver(client, logr.Discard())
	notified := collect(t, r)
	start(t, r)

	updated := service("default", "api", "10.96.0.2")
	if _, err := client.CoreV1().Services("default").Update(context.Background(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating the Service: %v", err)
	}

	awaitChange(t, notified, changed{namespace: "default", name: "api"})
}

func TestChangeHandlerFiresForEndpointSliceUpdate(t *testing.T) {
	existing := slice("default", "api-1", "api", discoveryv1.AddressTypeIPv4, endpoint(ptr(true), "10.244.0.1"))
	client := fake.NewClientset(service("default", "api", "10.96.0.1"), existing)
	r := NewResolver(client, logr.Discard())
	notified := collect(t, r)
	start(t, r)

	updated := slice("default", "api-1", "api", discoveryv1.AddressTypeIPv4, endpoint(ptr(true), "10.244.0.2"))
	if _, err := client.DiscoveryV1().EndpointSlices("default").Update(context.Background(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating the EndpointSlice: %v", err)
	}

	awaitChange(t, notified, changed{namespace: "default", name: "api"})
}

func TestChangeHandlerHandlesTombstones(t *testing.T) {
	r := NewResolver(fake.NewClientset(), logr.Discard())
	notified := collect(t, r)

	r.serviceChanged(cache.DeletedFinalStateUnknown{Key: "default/api", Obj: service("default", "api", "10.96.0.1")})
	awaitChange(t, notified, changed{namespace: "default", name: "api"})

	r.sliceChanged(cache.DeletedFinalStateUnknown{
		Key: "default/api-1",
		Obj: slice("default", "api-1", "api", discoveryv1.AddressTypeIPv4),
	})
	awaitChange(t, notified, changed{namespace: "default", name: "api"})
}

func TestChangeHandlerIgnoresUnlabelledSliceAndUnknownObject(t *testing.T) {
	r := NewResolver(fake.NewClientset(), logr.Discard())
	notified := collect(t, r)

	unlabelled := slice("default", "orphan", "api", discoveryv1.AddressTypeIPv4)
	unlabelled.Labels = nil
	r.sliceChanged(unlabelled)
	r.sliceChanged(cache.DeletedFinalStateUnknown{Key: "default/orphan", Obj: nil})
	r.serviceChanged(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api"}})

	if len(notified) != 0 {
		t.Fatalf("expected no notifications, got %d", len(notified))
	}
}

func TestChangeHandlerRunsWhileResolveServiceIsReachable(t *testing.T) {
	client := fake.NewClientset(service("default", "api", "10.96.0.1"))
	r := NewResolver(client, logr.Discard())

	resolved := make(chan []string, 8)
	r.AddChangeHandler(func(namespace, name string) {
		addrs, _ := r.ResolveService(namespace, name)
		select {
		case resolved <- addrs:
		default:
		}
	})
	start(t, r)

	if _, err := client.CoreV1().Services("default").Update(context.Background(), service("default", "api", "10.96.0.2"), metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating the Service: %v", err)
	}

	select {
	case <-resolved:
	case <-time.After(10 * time.Second):
		t.Fatal("a handler calling ResolveService did not complete")
	}
}

func TestStartReturnsNilOnCancel(t *testing.T) {
	r := NewResolver(fake.NewClientset(), logr.Discard())
	ctx, cancel := context.WithCancel(context.Background())

	errs := make(chan error, 1)
	go func() { errs <- r.Start(ctx) }()

	if !cache.WaitForCacheSync(ctx.Done(), r.HasSynced) {
		t.Fatal("caches did not sync")
	}
	cancel()

	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("Start returned %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after the context was cancelled")
	}
}
