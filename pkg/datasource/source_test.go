package datasource

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

// TestMockSourceName tests the Name method
func TestMockSourceName(t *testing.T) {
	source := NewMockSource()
	require.Equal(t, "mock", source.Name())
}

// TestMockSourceEventsForPod tests event retrieval from mock source
func TestMockSourceEventsForPod(t *testing.T) {
	events := []runtimeevents.Event{
		{Type: "exec", PodName: "test-pod", Namespace: "default"},
		{Type: "open", PodName: "test-pod", Namespace: "default"},
	}
	source := NewMockSource(events...)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
	}

	result, err := source.EventsForPod(context.Background(), pod, QueryOptions{})

	require.NoError(t, err)
	require.Len(t, result, 2)
	require.Equal(t, "exec", result[0].Type)
	require.Equal(t, "open", result[1].Type)
}

// TestMockSourceWithQueryOptions tests that query options don't affect mock
func TestMockSourceWithQueryOptions(t *testing.T) {
	events := []runtimeevents.Event{
		{Type: "exec", PodName: "test-pod", Namespace: "default"},
	}
	source := NewMockSource(events...)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
	}

	opts := QueryOptions{
		EventTypes: []string{"exec", "open"},
		Parameters: map[string]string{"key": "value"},
	}

	result, err := source.EventsForPod(context.Background(), pod, opts)

	require.NoError(t, err)
	require.Len(t, result, 1)
}

// TestInspektorGadgetSourceName tests the Name method
func TestInspektorGadgetSourceName(t *testing.T) {
	source := NewInspektorGadgetSource(0, 0)
	require.Equal(t, "inspektorgadget", source.Name())
}

// TestInspektorGadgetSourceDefaults tests default timeout values
func TestInspektorGadgetSourceDefaults(t *testing.T) {
	source := NewInspektorGadgetSource(0, 0)

	require.Equal(t, defaultIGExecTimeout, source.ExecTimeout)
	require.Equal(t, defaultIGCollectTimeout, source.CollectTimeout)
}

// TestInspektorGadgetSourceCustomTimeouts tests custom timeout values
func TestInspektorGadgetSourceCustomTimeouts(t *testing.T) {
	execTimeout := 10 * time.Second
	collectTimeout := 7 * time.Second

	source := NewInspektorGadgetSource(execTimeout, collectTimeout)

	require.Equal(t, execTimeout, source.ExecTimeout)
	require.Equal(t, collectTimeout, source.CollectTimeout)
}

// TestInspektorGadgetSourceNilPod tests EventsForPod with nil pod
func TestInspektorGadgetSourceNilPod(t *testing.T) {
	source := NewInspektorGadgetSource(0, 0)

	result, err := source.EventsForPod(context.Background(), nil, QueryOptions{})

	require.NoError(t, err)
	require.Empty(t, result)
}

// TestInspektorGadgetSourceEmptyEventTypes tests EventsForPod with no event types
func TestInspektorGadgetSourceEmptyEventTypes(t *testing.T) {
	source := NewInspektorGadgetSource(0, 0)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
	}

	result, err := source.EventsForPod(context.Background(), pod, QueryOptions{
		EventTypes: []string{},
	})

	require.NoError(t, err)
	require.Empty(t, result)
}

// TestNormalizeEventTypes tests event type normalization
func TestNormalizeEventTypes(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		checkFn func([]string) bool
	}{
		{
			name:  "empty input",
			input: []string{},
			checkFn: func(result []string) bool {
				// NormalizeEventTypes returns nil for empty input
				return len(result) == 0
			},
		},
		{
			name:  "single event type",
			input: []string{"exec"},
			checkFn: func(result []string) bool {
				return len(result) == 1 && result[0] == "exec"
			},
		},
		{
			name:  "multiple event types",
			input: []string{"exec", "open", "read"},
			checkFn: func(result []string) bool {
				return len(result) == 3
			},
		},
		{
			name:  "event types with duplicates",
			input: []string{"exec", "exec", "open"},
			checkFn: func(result []string) bool {
				// Should deduplicate
				return len(result) == 2
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeEventTypes(tt.input)
			require.True(t, tt.checkFn(result))
		})
	}
}

// TestQueryOptions tests QueryOptions structure
func TestQueryOptions(t *testing.T) {
	opts := QueryOptions{
		EventTypes: []string{"exec", "open"},
		Parameters: map[string]string{"timeout": "5s"},
	}

	require.Len(t, opts.EventTypes, 2)
	require.Len(t, opts.Parameters, 1)
	require.Equal(t, "5s", opts.Parameters["timeout"])
}
