package sensor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

type fakeCollector struct {
	eventsByType map[string][]runtimeevents.Event
}

func (f *fakeCollector) Collect(_ context.Context, request datasource.GadgetCollectRequest) ([]runtimeevents.Event, error) {
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
