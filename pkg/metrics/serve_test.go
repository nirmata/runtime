package metrics

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
)

// waitOrTimeout waits for done to fire and fails the test if it doesn't
// arrive within d. This is a single deadline guard, not a sleep-poll
// loop: there is no repeated sleep+check, just one select.
func waitOrTimeout(t *testing.T, done <-chan error, d time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatal("serve did not return within deadline after context cancellation")
		return nil
	}
}

func TestServe_ReturnsOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	reg := prometheus.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, reg, logr.Discard()) }()

	cancel()

	if err := waitOrTimeout(t, done, 5*time.Second); err != nil {
		t.Fatalf("serve returned error after context cancel: %v", err)
	}
}

func TestServe_ServesMetricsEndpointThenStopsOnCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	reg := prometheus.NewRegistry()
	m := New(reg)
	m.AttributionMisses.Inc()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, reg, logr.Discard()) }()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	const want = "kyverno_runtime_attribution_misses_total 1"
	if !strings.Contains(string(body), want) {
		t.Errorf("metrics response missing %q; got:\n%s", want, body)
	}

	cancel()
	if err := waitOrTimeout(t, done, 5*time.Second); err != nil {
		t.Fatalf("serve returned error after context cancel: %v", err)
	}
}

func TestServe_InvalidAddrReturnsError(t *testing.T) {
	reg := prometheus.NewRegistry()
	err := Serve(context.Background(), "this-is-not-a-valid-addr:zzz", reg, logr.Discard())
	if err == nil {
		t.Fatal("expected an error for an invalid listen address, got nil")
	}
}

func TestServe_ServerErrorPropagates(t *testing.T) {
	// Close the listener before serve() ever gets to Accept: srv.Serve
	// must return a non-ErrServerClosed error, and serve() must surface it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reg := prometheus.NewRegistry()
	err = serve(context.Background(), ln, reg, logr.Discard())
	if err == nil {
		t.Fatal("expected an error when serving on an already-closed listener")
	}
	if errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("expected a non-ErrServerClosed error, got: %v", err)
	}
}
