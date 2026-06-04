package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	GroupVersion       = schema.GroupVersion{Group: "runtime.kyverno.io", Version: "v1alpha1"}
	SchemeGroupVersion = GroupVersion

	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func Resource(resource string) schema.GroupResource {
	return GroupVersion.WithResource(resource).GroupResource()
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&RuntimePolicy{},
		&RuntimePolicyList{},
		&RuntimeBehavior{},
		&RuntimeBehaviorList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
