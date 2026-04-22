package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// mockStreamingSource is a streaming source that blocks until ctx is cancelled.
type mockStreamingSource struct{}

func (m *mockStreamingSource) Name() string { return "mock" }

func (m *mockStreamingSource) EventsForPod(_ context.Context, _ *corev1.Pod, _ datasource.QueryOptions) ([]runtimeevents.Event, error) {
	return nil, nil
}

func (m *mockStreamingSource) StreamEventsForPod(ctx context.Context, _ *corev1.Pod, _ datasource.QueryOptions, _ datasource.EventHandler) error {
	<-ctx.Done()
	return nil
}

// TestWatchManagerSyncRestartOnPolicyChange verifies that when policies change
// (even if the event types do not), Sync stops the old watch and starts a new
// one so that the updated policy set is evaluated.
func TestWatchManagerSyncRestartOnPolicyChange(t *testing.T) {
	t.Parallel()

	evalCalls := make(chan string, 16)
	evaluator := &MockEvaluator{
		EvaluateFunc: func(p *v1alpha1.RuntimePolicy, _ []runtimeevents.Event) EvaluationResult {
			evalCalls <- p.Name
			return EvaluationResult{}
		},
	}
	reporter := &MockReporter{}
	source := &mockStreamingSource{}

	wm := NewWatchManager(source, evaluator, reporter)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}

	policyA := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-a"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{Name: "v1", Event: "open"}},
		},
	}
	policyB := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-b"},
		Spec: v1alpha1.RuntimePolicySpec{
			Validations: []v1alpha1.RuntimeValidation{{Name: "v1", Event: "open"}},
		},
	}

	ctx := context.Background()

	// First Sync: only policy-a is active.
	wm.Sync(ctx, pod, []*v1alpha1.RuntimePolicy{policyA})

	// Second Sync: policy-a removed, policy-b added (same event types: open).
	wm.Sync(ctx, pod, []*v1alpha1.RuntimePolicy{policyB})

	// Allow a moment for the goroutine to start and process.
	time.Sleep(50 * time.Millisecond)

	// Inject a fake event directly through the evaluator to confirm policy-b is active.
	// The watch goroutine uses the new policiesCopy, so calling Evaluate on policyA
	// must no longer happen — only policyB is in the new watch.
	wm.mu.Lock()
	watchCount := len(wm.watches)
	wm.mu.Unlock()

	// Only one watch should be active (the new one for policy-b).
	require.Equal(t, 1, watchCount, "expected exactly one active watch after policy change")

	// Verify the active watch key includes policy-b (not policy-a).
	wm.mu.Lock()
	var activeKey podWatchKey
	for k := range wm.watches {
		activeKey = k
	}
	wm.mu.Unlock()

	require.Contains(t, activeKey.policies, "policy-b", "active watch key should reference policy-b")
	require.NotContains(t, activeKey.policies, "policy-a", "active watch key should not reference policy-a")

	wm.StopAll()
}
