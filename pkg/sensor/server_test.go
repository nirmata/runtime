package sensor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

type fakeCollector struct {
	eventsByType map[string][]runtimeevents.Event
	shouldError  bool
	errorMessage string
}

func (f *fakeCollector) Collect(_ context.Context, request datasource.GadgetCollectRequest) ([]runtimeevents.Event, error) {
	if f.shouldError {
		return nil, errors.New(f.errorMessage)
	}
	return append([]runtimeevents.Event{}, f.eventsByType[request.EventType]...), nil
}

func TestServerCollect(t *testing.T) {
	collector := &fakeCollector{eventsByType: map[string][]runtimeevents.Event{
		"open": {{Type: "open", Fields: map[string]string{"file.path": "/etc/hosts"}}},
	}}
	server := NewServer(collector, 0)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	body := `{"namespace":"runtime-demo","pod":"demo","eventTypes":["open"]}`
	resp, err := http.Post(httpServer.URL+"/collect", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post collect: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, string(b))
	}
}

func TestServerHealthz(t *testing.T) {
	server := NewServer(&fakeCollector{}, 0)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	resp, err := http.Get(httpServer.URL + "/healthz")
	if err != nil {
		t.Fatalf("get healthz: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

func TestCollectMethodNotAllowed(t *testing.T) {
	server := NewServer(&fakeCollector{}, 0)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	resp, err := http.Get(httpServer.URL + "/collect")
	if err != nil {
		t.Fatalf("get collect: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d, got %d", http.StatusMethodNotAllowed, resp.StatusCode)
	}
}

func TestCollectNilCollector(t *testing.T) {
	server := NewServer(nil, 0)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	body := `{"namespace":"test","pod":"test","eventTypes":["open"]}`
	resp, err := http.Post(httpServer.URL+"/collect", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post collect: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, resp.StatusCode)
	}
}

func TestCollectInvalidJSON(t *testing.T) {
	server := NewServer(&fakeCollector{}, 0)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	body := `{invalid json`
	resp, err := http.Post(httpServer.URL+"/collect", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post collect: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}

func TestCollectEmptyEventTypes(t *testing.T) {
	collector := &fakeCollector{eventsByType: map[string][]runtimeevents.Event{}}
	server := NewServer(collector, 0)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	body := `{"namespace":"test","pod":"test","eventTypes":[]}`
	resp, err := http.Post(httpServer.URL+"/collect", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post collect: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestCollectMultipleEventTypes(t *testing.T) {
	collector := &fakeCollector{eventsByType: map[string][]runtimeevents.Event{
		"open": {{Type: "open", Fields: map[string]string{"file.path": "/etc/hosts"}}},
		"exec": {{Type: "exec", Fields: map[string]string{"comm": "sh"}}},
	}}
	server := NewServer(collector, 0)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	body := `{"namespace":"test","pod":"test","eventTypes":["open","exec"]}`
	resp, err := http.Post(httpServer.URL+"/collect", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post collect: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestCollectCollectorError(t *testing.T) {
	collector := &fakeCollector{
		shouldError:  true,
		errorMessage: "gadget failed",
	}
	server := NewServer(collector, 0)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	body := `{"namespace":"test","pod":"test","eventTypes":["open"]}`
	resp, err := http.Post(httpServer.URL+"/collect", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post collect: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d", http.StatusBadGateway, resp.StatusCode)
	}
}

func TestNewServerDefaultTimeout(t *testing.T) {
	server := NewServer(&fakeCollector{}, 0)
	if server.defaultCollectTimeout.Seconds() != 5 {
		t.Fatalf("expected default timeout of 5s, got %v", server.defaultCollectTimeout)
	}
}

func TestNewServerCustomTimeout(t *testing.T) {
	customDuration := 10 * time.Second
	server := NewServer(&fakeCollector{}, customDuration)
	if server.defaultCollectTimeout != customDuration {
		t.Fatalf("expected timeout of %v, got %v", customDuration, server.defaultCollectTimeout)
	}
}

func TestCollectWithCustomTimeout(t *testing.T) {
	// Test that custom timeout is properly parsed and used
	collector := &fakeCollector{eventsByType: map[string][]runtimeevents.Event{
		"open": {{Type: "open"}},
	}}
	server := NewServer(collector, 5*time.Second)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	body := `{"namespace":"test","pod":"test","eventTypes":["open"],"collectTimeout":"2s"}`
	resp, err := http.Post(httpServer.URL+"/collect", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post collect: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.StatusCode)
	}
}
