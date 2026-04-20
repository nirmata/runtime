package controller

import (
	"context"
	"errors"
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

func makeReconciler(t *testing.T, objs ...runtime.Object) (*DaemonSetReconciler, *pipeline.MockMatcher) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	clientObjs := make([]runtime.Object, len(objs))
	copy(clientObjs, objs)

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, o := range objs {
		builder = builder.WithRuntimeObjects(o)
	}
	c := builder.Build()

	matcher := &pipeline.MockMatcher{}
	evaluator := &pipeline.MockEvaluator{}
	reporter := &pipeline.MockReporter{}
	source := datasource.NewMockSource()
	watchManager := pipeline.NewWatchManager(source, evaluator, reporter)
	r := NewDaemonSetReconciler(c, matcher, watchManager)
	return r, matcher
}

func TestDaemonSetReconciler_PodNotFound(t *testing.T) {
	r, _ := makeReconciler(t)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"}}
	result, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)
}

func TestDaemonSetReconciler_NamespaceNotFound(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	r, _ := makeReconciler(t, pod)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-pod", Namespace: "default"}}
	_, err := r.Reconcile(context.Background(), req)
	require.Error(t, err)
}

func TestDaemonSetReconciler_NonRunningPodSkipped(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	r, _ := makeReconciler(t, pod, ns)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-pod", Namespace: "default"}}
	result, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)
}

func TestDaemonSetReconciler_RunningPodWithMatchingPolicy(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	policy := &v1alpha1.RuntimePolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy"}}
	r, matcher := makeReconciler(t, pod, ns, policy)
	matcher.MatchesFunc = func(_ *v1alpha1.RuntimePolicy, _ *corev1.Pod, _ map[string]string) (bool, error) {
		return true, nil
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-pod", Namespace: "default"}}
	result, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)
}

func TestDaemonSetReconciler_MatcherError(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	policy := &v1alpha1.RuntimePolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy"}}
	r, matcher := makeReconciler(t, pod, ns, policy)
	matchErr := errors.New("match error")
	matcher.MatchesFunc = func(_ *v1alpha1.RuntimePolicy, _ *corev1.Pod, _ map[string]string) (bool, error) {
		return false, matchErr
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-pod", Namespace: "default"}}
	_, err := r.Reconcile(context.Background(), req)
	require.ErrorIs(t, err, matchErr)
}
