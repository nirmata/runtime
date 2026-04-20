package sensor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/datasource"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

type Server struct {
	collector             datasource.GadgetCollector
	defaultCollectTimeout time.Duration
}

type collectRequest struct {
	Namespace      string            `json:"namespace"`
	Pod            string            `json:"pod"`
	EventTypes     []string          `json:"eventTypes"`
	Parameters     map[string]string `json:"parameters,omitempty"`
	CollectTimeout string            `json:"collectTimeout,omitempty"`
}

type collectResponse struct {
	Events []runtimeevents.Event `json:"events"`
}

func NewServer(collector datasource.GadgetCollector, defaultCollectTimeout time.Duration) *Server {
	if defaultCollectTimeout <= 0 {
		defaultCollectTimeout = 5 * time.Second
	}
	return &Server{collector: collector, defaultCollectTimeout: defaultCollectTimeout}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/collect", s.collect)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) collect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.collector == nil {
		http.Error(w, "collector not configured", http.StatusServiceUnavailable)
		return
	}

	var req collectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	eventTypes := datasource.NormalizeEventTypes(req.EventTypes)
	if len(eventTypes) == 0 {
		writeJSON(w, http.StatusOK, collectResponse{Events: []runtimeevents.Event{}})
		return
	}

	collectTimeout := s.defaultCollectTimeout
	if req.CollectTimeout != "" {
		if parsed, err := time.ParseDuration(req.CollectTimeout); err == nil && parsed > 0 {
			collectTimeout = parsed
		}
	}

	events := make([]runtimeevents.Event, 0)
	for _, eventType := range eventTypes {
		collected, err := s.collector.Collect(r.Context(), datasource.GadgetCollectRequest{
			EventType:      eventType,
			Namespace:      req.Namespace,
			Pod:            req.Pod,
			CollectTimeout: collectTimeout,
			Parameters:     req.Parameters,
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("collect %s: %v", eventType, err), http.StatusBadGateway)
			return
		}
		events = append(events, collected...)
	}

	writeJSON(w, http.StatusOK, collectResponse{Events: events})
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}
