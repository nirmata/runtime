package datasource

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

type fakeCollector struct {
	lastRequest GadgetCollectRequest
	events      []runtimeevents.Event
	err         error
}

func (f *fakeCollector) Collect(_ context.Context, request GadgetCollectRequest) ([]runtimeevents.Event, error) {
	f.lastRequest = request
	return append([]runtimeevents.Event{}, f.events...), f.err
}

func TestInspektorGadgetSourceCollectsMatchingEventTypes(t *testing.T) {
	c := &fakeCollector{events: []runtimeevents.Event{{Type: "connect", Fields: map[string]string{"destination.ip": "8.8.8.8"}}}}
	s := NewInspektorGadgetSource(3*time.Second, 5*time.Second)
	s.Collector = c

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"}}
	events, err := s.EventsForPod(context.Background(), pod, QueryOptions{EventTypes: []string{"connect"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "connect" {
		t.Fatalf("expected type connect, got %s", events[0].Type)
	}
	if events[0].Field("destination.ip") != "8.8.8.8" {
		t.Fatalf("expected destination.ip field")
	}
	if c.lastRequest.EventType != "connect" || c.lastRequest.Namespace != "prod" || c.lastRequest.Pod != "web" {
		t.Fatalf("unexpected collect request: %+v", c.lastRequest)
	}
	if c.lastRequest.CollectTimeout != 5*time.Second {
		t.Fatalf("expected collect timeout 5s, got %s", c.lastRequest.CollectTimeout)
	}
}

func TestInspektorGadgetSourcePassesThroughNonTimeoutParameters(t *testing.T) {
	c := &fakeCollector{events: []runtimeevents.Event{{Type: "open"}}}
	s := NewInspektorGadgetSource(3*time.Second, 5*time.Second)
	s.Collector = c

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"}}
	events, err := s.EventsForPod(context.Background(), pod, QueryOptions{EventTypes: []string{"open"}, Parameters: map[string]string{"rate": "10", "timeout": "4"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if c.lastRequest.Parameters["rate"] != "10" || c.lastRequest.Parameters["timeout"] != "4" {
		t.Fatalf("unexpected request parameters: %+v", c.lastRequest.Parameters)
	}
}

func TestMockSourceFiltersEventTypes(t *testing.T) {
	s := NewMockSource(
		runtimeevents.Event{Type: "open"},
		runtimeevents.Event{Type: "exec"},
	)

	events, err := s.EventsForPod(context.Background(), nil, QueryOptions{EventTypes: []string{"exec"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 || events[0].Type != "exec" {
		t.Fatalf("unexpected events: %+v", events)
	}
}
