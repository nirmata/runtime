package controller

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrl "sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/pipeline"
)

func TestDaemonSetReconciler_AutoCreatesRuntimeBehaviorWithSharedDefaults(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo",
			Namespace: "runtime-demo",
			UID:       types.UID("1234567890abcdef"),
			Labels: map[string]string{
				"app":                              "demo",
				"runtime.kyverno.io/runtime-class": "jupyter",
			},
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "demo"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	objs := []runtime.Object{
		pod,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "runtime-demo"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kyverno-runtime"}},
		&v1alpha1.RuntimeBehavior{
			ObjectMeta: metav1.ObjectMeta{Name: "enterprise-safe-network", Namespace: "kyverno-runtime"},
			Spec:       v1alpha1.RuntimeBehaviorSpec{Allow: &v1alpha1.AllowRules{Network: []string{"10.0.0.0/8"}}},
		},
		&v1alpha1.RuntimeBehavior{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "jupyter-approved-patterns",
				Namespace: "kyverno-runtime",
				Labels: map[string]string{
					"runtime.kyverno.io/runtime-class": "jupyter",
				},
			},
			Spec: v1alpha1.RuntimeBehaviorSpec{Allow: &v1alpha1.AllowRules{Exec: []string{"/usr/bin/python3"}}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
	matcher := &pipeline.MockMatcher{}
	evaluator := &pipeline.MockEvaluator{}
	reporter := &pipeline.MockReporter{}
	source := datasource.NewMockSource()
	watchManager := pipeline.NewWatchManager(source, evaluator, reporter)

	enroll := DefaultRuntimeBehaviorEnrollmentConfig()
	enroll.AutoCreate = true
	enroll.IncludeControllers = map[string]bool{"Deployment": true}
	enroll.IncludeBarePods = false
	enroll.SharedDefaultsNamespace = "kyverno-runtime"

	r := NewDaemonSetReconcilerWithEnrollmentConfig(c, matcher, watchManager, enroll)
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "demo", Namespace: "runtime-demo"}})
	require.NoError(t, err)
	_, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "demo", Namespace: "runtime-demo"}})
	require.NoError(t, err)

	created := &v1alpha1.RuntimeBehaviorList{}
	require.NoError(t, c.List(context.Background(), created))

	managed := make([]*v1alpha1.RuntimeBehavior, 0)
	for i := range created.Items {
		rb := &created.Items[i]
		if rb.Namespace != "runtime-demo" {
			continue
		}
		if rb.Labels["runtime.kyverno.io/managed"] != "true" {
			continue
		}
		managed = append(managed, rb)
	}
	require.Len(t, managed, 1, "expected exactly one managed RuntimeBehavior for enrolled pod")

	rb := managed[0]
	require.Equal(t, v1alpha1.ModeLearning, rb.Spec.Mode)
	require.NotNil(t, rb.Spec.Allow)

	refs := make([]string, 0, len(rb.Spec.Allow.Refs))
	for _, ref := range rb.Spec.Allow.Refs {
		refs = append(refs, ref.Namespace+"/"+ref.Name)
	}
	sort.Strings(refs)
	require.Equal(t, []string{
		"kyverno-runtime/enterprise-safe-network",
		"kyverno-runtime/jupyter-approved-patterns",
	}, refs)
}

func TestDaemonSetReconciler_DoesNotAutoCreateForExcludedNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "syspod",
			Namespace:       "kube-system",
			UID:             types.UID("1234567890abcdef"),
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "syspod"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		pod,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
	).Build()
	matcher := &pipeline.MockMatcher{}
	evaluator := &pipeline.MockEvaluator{}
	reporter := &pipeline.MockReporter{}
	source := datasource.NewMockSource()
	watchManager := pipeline.NewWatchManager(source, evaluator, reporter)

	enroll := DefaultRuntimeBehaviorEnrollmentConfig()
	enroll.AutoCreate = true
	enroll.ExcludeNamespaces = map[string]bool{"kube-system": true}

	r := NewDaemonSetReconcilerWithEnrollmentConfig(c, matcher, watchManager, enroll)
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "syspod", Namespace: "kube-system"}})
	require.NoError(t, err)

	list := &v1alpha1.RuntimeBehaviorList{}
	require.NoError(t, c.List(context.Background(), list))
	require.Len(t, list.Items, 0)
}

func TestDaemonSetReconciler_DoesNotAutoCreateWhenOptedOut(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-optout",
			Namespace: "runtime-demo",
			UID:       types.UID("abcdef1234567890"),
			Labels: map[string]string{
				"runtime.kyverno.io/optout": "true",
			},
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "demo-optout"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		pod,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "runtime-demo"}},
	).Build()

	r := NewDaemonSetReconcilerWithEnrollmentConfig(
		c,
		&pipeline.MockMatcher{},
		pipeline.NewWatchManager(datasource.NewMockSource(), &pipeline.MockEvaluator{}, &pipeline.MockReporter{}),
		RuntimeBehaviorEnrollmentConfig{
			AutoCreate:         true,
			IncludeControllers: map[string]bool{"Deployment": true},
			ExcludeNamespaces:  map[string]bool{},
			OptOutLabel:        "runtime.kyverno.io/optout",
			InitialMode:        v1alpha1.ModeLearning,
		},
	)

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}})
	require.NoError(t, err)

	list := &v1alpha1.RuntimeBehaviorList{}
	require.NoError(t, c.List(context.Background(), list))
	require.Len(t, list.Items, 0)
}

func TestDaemonSetReconciler_UpdatesManagedRuntimeBehaviorRefs(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo",
			Namespace: "runtime-demo",
			UID:       types.UID("1234567890abcdef"),
			Labels: map[string]string{
				"app":                              "demo",
				"runtime.kyverno.io/runtime-class": "jupyter",
			},
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "demo"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	existingManaged := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auto-demo-12345678",
			Namespace: "runtime-demo",
			Labels: map[string]string{
				"runtime.kyverno.io/managed":      "true",
				"runtime.kyverno.io/workload-pod": "demo",
			},
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			Mode:  v1alpha1.ModeLearning,
			Allow: &v1alpha1.AllowRules{},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(
		pod,
		existingManaged,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "runtime-demo"}},
		&v1alpha1.RuntimeBehavior{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "global-safe",
				Namespace: "kyverno-runtime",
				Labels:    map[string]string{"scope": "all"},
			},
			Spec: v1alpha1.RuntimeBehaviorSpec{Allow: &v1alpha1.AllowRules{Network: []string{"10.0.0.0/8"}}},
		},
		&v1alpha1.RuntimeBehavior{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "class-jupyter",
				Namespace: "kyverno-runtime",
				Labels:    map[string]string{"runtime.kyverno.io/runtime-class": "jupyter"},
			},
			Spec: v1alpha1.RuntimeBehaviorSpec{Allow: &v1alpha1.AllowRules{Exec: []string{"/usr/bin/python3"}}},
		},
	).Build()

	enroll := DefaultRuntimeBehaviorEnrollmentConfig()
	enroll.AutoCreate = true
	enroll.IncludeControllers = map[string]bool{"Deployment": true}
	enroll.SharedDefaultsNamespace = "kyverno-runtime"

	r := NewDaemonSetReconcilerWithEnrollmentConfig(
		c,
		&pipeline.MockMatcher{},
		pipeline.NewWatchManager(datasource.NewMockSource(), &pipeline.MockEvaluator{}, &pipeline.MockReporter{}),
		enroll,
	)

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}})
	require.NoError(t, err)

	updated := &v1alpha1.RuntimeBehavior{}
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: existingManaged.Name, Namespace: existingManaged.Namespace}, updated))
	require.NotNil(t, updated.Spec.Allow)
	refs := []string{}
	for _, ref := range updated.Spec.Allow.Refs {
		refs = append(refs, ref.Namespace+"/"+ref.Name)
	}
	sort.Strings(refs)
	require.Equal(t, []string{
		"kyverno-runtime/class-jupyter",
		"kyverno-runtime/global-safe",
	}, refs)
}
