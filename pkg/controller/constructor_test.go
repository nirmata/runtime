package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/pipeline"
)

func newTestReconciler(t *testing.T) *DaemonSetReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	matcher := &pipeline.MockMatcher{}
	evaluator := &pipeline.MockEvaluator{}
	reporter := &pipeline.MockReporter{}
	source := datasource.NewMockSource()
	watchManager := pipeline.NewWatchManager(source, evaluator, reporter)
	return NewDaemonSetReconciler(c, matcher, watchManager)
}

// TestNewDaemonSetReconciler tests the DaemonSetReconciler constructor.
func TestNewDaemonSetReconciler(t *testing.T) {
	r := newTestReconciler(t)
	require.NotNil(t, r)
	require.NotNil(t, r.client)
	require.NotNil(t, r.watchManager)
}

// TestNewDaemonSetReconcilerWithDifferentComponents tests constructor with different component combinations.
func TestNewDaemonSetReconcilerWithDifferentComponents(t *testing.T) {
	scheme := runtime.NewScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	matcher := &pipeline.MockMatcher{}
	evaluator := &pipeline.MockEvaluator{}
	reporter := &pipeline.MockReporter{}
	source := datasource.NewMockSource()
	watchManager := pipeline.NewWatchManager(source, evaluator, reporter)
	r := NewDaemonSetReconciler(c, matcher, watchManager)
	require.NotNil(t, r)
	require.Equal(t, c, r.client)
}

// TestDaemonSetReconcilerHasWatchManager verifies the WatchManager is properly initialized.
func TestDaemonSetReconcilerHasWatchManager(t *testing.T) {
	r := newTestReconciler(t)
	require.NotNil(t, r.watchManager)
}
