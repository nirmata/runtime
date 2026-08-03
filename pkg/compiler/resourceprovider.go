package compiler

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type resourceProvider struct {
	client dynamic.Interface
}

func newResourceProvider(client dynamic.Interface) *resourceProvider {
	return &resourceProvider{
		client: client,
	}
}

func (rp *resourceProvider) ListResources(apiVersion, resource, namespace string, l map[string]string) (*unstructured.UnstructuredList, error) {
	groupVersion, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, err
	}
	resourceInteface := rp.getResourceClient(groupVersion, resource, namespace)
	labelSelector := labels.Everything()
	if len(l) > 0 {
		labelSelector = labels.SelectorFromSet(l)
	}
	return resourceInteface.List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector.String(),
	})
}

func (rp *resourceProvider) GetResource(apiVersion, resource, namespace, name string) (*unstructured.Unstructured, error) {
	groupVersion, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, err
	}
	resourceInteface := rp.getResourceClient(groupVersion, resource, namespace)
	return resourceInteface.Get(context.TODO(), name, metav1.GetOptions{})
}

func (rp *resourceProvider) PostResource(apiVersion, resource, namespace string, data map[string]any) (*unstructured.Unstructured, error) {
	groupVersion, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, err
	}
	resourceInteface := rp.getResourceClient(groupVersion, resource, namespace)
	return resourceInteface.Create(context.TODO(), &unstructured.Unstructured{Object: data}, metav1.CreateOptions{})
}

// ToGVR is reachable from user CEL via `resource.toGVR()`. It returns an
// error rather than panicking, because a panic here kills the privileged daemon.
func (rp *resourceProvider) ToGVR(apiVersion, kind string) (*schema.GroupVersionResource, error) {
	return nil, fmt.Errorf("resource.toGVR is not implemented: cannot map apiVersion %q kind %q to a resource", apiVersion, kind)
}

func (rp *resourceProvider) getResourceClient(groupVersion schema.GroupVersion, resource string, namespace string) dynamic.ResourceInterface {
	client := rp.client.Resource(groupVersion.WithResource(resource))
	if namespace != "" {
		return client.Namespace(namespace)
	}
	return client
}
