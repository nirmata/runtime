package services

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const serviceNameIndex = "kyverno-runtime/endpointslice-by-service-name"

type Resolver struct {
	factory  informers.SharedInformerFactory
	services cache.SharedIndexInformer
	slices   cache.SharedIndexInformer
	lister   corev1listers.ServiceLister

	mu       sync.RWMutex
	handlers []func(namespace, name string)

	log logr.Logger
}

func NewResolver(client kubernetes.Interface, log logr.Logger) *Resolver {
	factory := informers.NewSharedInformerFactory(client, 0)

	services := factory.Core().V1().Services()
	slices := factory.Discovery().V1().EndpointSlices()

	r := &Resolver{
		factory:  factory,
		services: services.Informer(),
		slices:   slices.Informer(),
		lister:   services.Lister(),
		log:      log,
	}

	if err := r.slices.AddIndexers(cache.Indexers{serviceNameIndex: sliceServiceKey}); err != nil {
		panic(fmt.Sprintf("registering the EndpointSlice service-name indexer: %v", err))
	}

	// AddEventHandler only errors once the informer has stopped, which cannot
	// happen before Start.
	_, _ = r.services.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    r.serviceChanged,
		UpdateFunc: func(_, newObj interface{}) { r.serviceChanged(newObj) },
		DeleteFunc: r.serviceChanged,
	})
	_, _ = r.slices.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    r.sliceChanged,
		UpdateFunc: func(_, newObj interface{}) { r.sliceChanged(newObj) },
		DeleteFunc: r.sliceChanged,
	})

	return r
}

// Start runs the informers and blocks until ctx is done. It returns an error if
// the caches do not sync.
func (r *Resolver) Start(ctx context.Context) error {
	r.factory.Start(ctx.Done())

	timeOut, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	if !cache.WaitForCacheSync(timeOut.Done(), r.services.HasSynced, r.slices.HasSynced) {
		// A cancelled ctx and a real timeout both come back as false here, and
		// the daemon treats a Start error as fatal.
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("timed out waiting for cache sync")
	}

	<-ctx.Done()
	return nil
}

// HasSynced reports whether both caches have synced.
func (r *Resolver) HasSynced() bool {
	return r.services.HasSynced() && r.slices.HasSynced()
}

// AddChangeHandler registers a callback invoked whenever the addresses for a
// Service may have changed. Handlers are registered before Start.
func (r *Resolver) AddChangeHandler(h func(namespace, name string)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers = append(r.handlers, h)
}

// ResolveService implements compiler.ServiceResolver.
//
// The result unions the ClusterIP with the ready endpoint addresses because
// which of them the egress hook sees depends on the client: an ordinary pod is
// DNATed in the host netns, after the hook has already fired in the pod netns,
// so the hook sees the ClusterIP; a hostNetwork pod is DNATed in nat/OUTPUT of
// its own netns before the hook, so the hook sees the backend address. Headless
// Services have no ClusterIP at all.
func (r *Resolver) ResolveService(namespace, name string) ([]string, bool) {
	svc, err := r.lister.Services(namespace).Get(name)
	if err != nil {
		return nil, false
	}

	set := make(map[string]struct{})
	if ip := svc.Spec.ClusterIP; ip != "" && ip != corev1.ClusterIPNone {
		r.addIPv4(set, ip)
	}

	key := namespace + "/" + name
	objs, err := r.slices.GetIndexer().ByIndex(serviceNameIndex, key)
	if err != nil {
		panic(fmt.Sprintf("querying the EndpointSlice service-name index: %v", err))
	}
	for _, obj := range objs {
		slice, ok := obj.(*discoveryv1.EndpointSlice)
		if !ok || slice.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}
		for _, endpoint := range slice.Endpoints {
			// A nil Ready condition means ready, per the EndpointSlice API
			// contract; only an explicit false excludes the addresses.
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			for _, addr := range endpoint.Addresses {
				r.addIPv4(set, addr)
			}
		}
	}

	addrs := make([]string, 0, len(set))
	for addr := range set {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)
	return addrs, true
}

func (r *Resolver) addIPv4(set map[string]struct{}, raw string) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		r.log.V(2).Info("skipping an address that is not a valid IP", "address", raw)
		return
	}
	if addr = addr.Unmap(); addr.Is4() {
		set[addr.String()] = struct{}{}
	}
}

func (r *Resolver) serviceChanged(obj interface{}) {
	svc, ok := unwrap[*corev1.Service](obj)
	if !ok {
		return
	}
	r.notify(svc.Namespace, svc.Name)
}

func (r *Resolver) sliceChanged(obj interface{}) {
	slice, ok := unwrap[*discoveryv1.EndpointSlice](obj)
	if !ok {
		return
	}
	name := slice.Labels[discoveryv1.LabelServiceName]
	if name == "" {
		return
	}
	r.notify(slice.Namespace, name)
}

// The handler snapshot is taken under the lock and the handlers are called
// without it, so a handler is free to call back into ResolveService.
func (r *Resolver) notify(namespace, name string) {
	r.mu.RLock()
	handlers := r.handlers
	r.mu.RUnlock()

	for _, h := range handlers {
		h(namespace, name)
	}
}

func sliceServiceKey(obj interface{}) ([]string, error) {
	slice, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return nil, nil
	}
	name := slice.Labels[discoveryv1.LabelServiceName]
	if name == "" {
		return nil, nil
	}
	return []string{slice.Namespace + "/" + name}, nil
}

func unwrap[T any](obj interface{}) (T, bool) {
	if typed, ok := obj.(T); ok {
		return typed, true
	}
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		typed, ok := tombstone.Obj.(T)
		return typed, ok
	}
	var zero T
	return zero, false
}
