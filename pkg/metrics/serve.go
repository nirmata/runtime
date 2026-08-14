package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Serve starts an HTTP server exposing g at "/metrics" and health at
// "/healthz" on addr. It blocks until ctx is canceled or the server fails to
// serve, then shuts the server down and returns. A nil error is returned for
// both a clean shutdown and a graceful listener close.
func Serve(ctx context.Context, addr string, g prometheus.Gatherer, health func() error, log logr.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("metrics: listen on %s: %w", addr, err)
	}
	log.V(2).Info("metrics server listening", "addr", ln.Addr().String())
	return serve(ctx, ln, g, health, log)
}

// serve is the testable core of Serve: it accepts an already-bound
// listener so tests can bind ":0", pass the listener straight in, and
// observe context-cancel shutdown deterministically via channels — no
// sleep-polling for the server to become "ready".
func serve(ctx context.Context, ln net.Listener, g prometheus.Gatherer, health func() error, log logr.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(g, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := health(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		// Close the listener directly in addition to srv.Close(): if the
		// Serve goroutine hasn't registered ln with srv yet, srv.Close()
		// alone could race and leave ln open.
		_ = srv.Close()
		_ = ln.Close()
		<-errCh
		log.V(2).Info("metrics server stopped", "addr", ln.Addr().String())
		return nil
	case err := <-errCh:
		_ = ln.Close()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("metrics: serve %s: %w", ln.Addr(), err)
		}
		return nil
	}
}
