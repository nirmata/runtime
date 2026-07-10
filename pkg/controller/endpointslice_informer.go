package controller

import (
	"context"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type DsEndpointResolver struct {
	daemonsetSvcName   string
	daemonsetSvcNs     string
	daemonSetEndpoints []string
}

func NewDsEndpointResolver(mgr ctrl.Manager, svcNs, svcName string) (*DsEndpointResolver, error) {
	informer, err := mgr.GetCache().GetInformer(context.Background(), &discoveryv1.EndpointSlice{})
	if err != nil {
		return nil, err
	}
	logger := log.FromContext(context.Background())
	dsr := &DsEndpointResolver{
		daemonsetSvcName: svcName,
		daemonsetSvcNs:   svcNs,
	}

	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			es := obj.(*discoveryv1.EndpointSlice)
			dsr.handleEndpointSliceEvent(es)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			es := newObj.(*discoveryv1.EndpointSlice)
			dsr.handleEndpointSliceEvent(es)
		},
		DeleteFunc: func(obj interface{}) {
			es, ok := obj.(*discoveryv1.EndpointSlice)
			if !ok {
				// handle cache.DeletedFinalStateUnknown
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				es = tombstone.Obj.(*discoveryv1.EndpointSlice)
			}

			if es.Labels["kubernetes.io/service-name"] != dsr.daemonsetSvcName || es.Namespace != dsr.daemonsetSvcNs {
				return
			}

			logger.Info("deleting the endpoint slice of the daemon ds will cause degredation in learning mode findings. please recreate it")
		},
	}); err != nil {
		return nil, err
	}
	return dsr, nil
}

func (d *DsEndpointResolver) GetEndpoints() []string {
	return d.daemonSetEndpoints
}

func (d *DsEndpointResolver) handleEndpointSliceEvent(es *discoveryv1.EndpointSlice) {
	if es.Labels["kubernetes.io/service-name"] != d.daemonsetSvcName || es.Namespace != d.daemonsetSvcNs {
		// not the daemon ds endpoint slice. do nothing
		return
	}
	currentEndpoints := make([]string, len(es.Endpoints))
	for _, e := range es.Endpoints {
		if e.Conditions.Ready != nil && *e.Conditions.Ready {
			currentEndpoints = append(currentEndpoints, e.Addresses...)
		}
	}
	d.daemonSetEndpoints = currentEndpoints
}
