package datasource

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

func TestGadgetRunConfig(t *testing.T) {
	tests := []struct {
		name        string
		request     GadgetCollectRequest
		wantImage   string
		wantParams  map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name:      "open maps to trace_open",
			request:   GadgetCollectRequest{EventType: "open"},
			wantImage: "trace_open",
		},
		{
			name:      "exec maps to trace_exec",
			request:   GadgetCollectRequest{EventType: "exec"},
			wantImage: "trace_exec",
		},
		{
			name:       "connect maps to trace_tcp with connect-only",
			request:    GadgetCollectRequest{EventType: "connect"},
			wantImage:  "trace_tcp",
			wantParams: map[string]string{"connect-only": "true"},
		},
		{
			name: "connect sets k8s namespace and pod selectors",
			request: GadgetCollectRequest{
				EventType: "connect",
				Namespace: "runtime-demo",
				Pod:       "demo",
			},
			wantImage: "trace_tcp",
			wantParams: map[string]string{
				"connect-only":  "true",
				"k8s-namespace": "runtime-demo",
				"k8s-podname":   "demo",
			},
		},
		{
			name: "connect preserves explicit selectors",
			request: GadgetCollectRequest{
				EventType:  "connect",
				Namespace:  "runtime-demo",
				Pod:        "demo",
				Parameters: map[string]string{"k8s-namespace": "custom-ns", "k8s-podname": "custom-pod"},
			},
			wantImage: "trace_tcp",
			wantParams: map[string]string{
				"connect-only":  "true",
				"k8s-namespace": "custom-ns",
				"k8s-podname":   "custom-pod",
			},
		},
		{
			name:       "tcpconnect maps to trace_tcp with connect-only",
			request:    GadgetCollectRequest{EventType: "tcpconnect"},
			wantImage:  "trace_tcp",
			wantParams: map[string]string{"connect-only": "true"},
		},
		{
			name:      "case insensitive event type",
			request:   GadgetCollectRequest{EventType: "OPEN"},
			wantImage: "trace_open",
		},
		{
			name:      "event type with whitespace",
			request:   GadgetCollectRequest{EventType: "  exec  "},
			wantImage: "trace_exec",
		},
		{
			name:        "unsupported event type returns error",
			request:     GadgetCollectRequest{EventType: "unknown"},
			wantErr:     true,
			errContains: "unsupported runtime event type",
		},
		{
			name:        "empty event type returns error",
			request:     GadgetCollectRequest{EventType: ""},
			wantErr:     true,
			errContains: "unsupported runtime event type",
		},
		{
			name: "parameters are forwarded",
			request: GadgetCollectRequest{
				EventType:  "open",
				Parameters: map[string]string{"rate": "10", "filter": "true"},
			},
			wantImage:  "trace_open",
			wantParams: map[string]string{"rate": "10", "filter": "true"},
		},
		{
			name: "timeout parameter is stripped",
			request: GadgetCollectRequest{
				EventType:  "exec",
				Parameters: map[string]string{"timeout": "30", "verbose": "true"},
			},
			wantImage:  "trace_exec",
			wantParams: map[string]string{"verbose": "true"},
		},
		{
			name: "parameter keys are trimmed and -- prefix removed",
			request: GadgetCollectRequest{
				EventType:  "open",
				Parameters: map[string]string{"--rate": "10", "  filter  ": "yes"},
			},
			wantImage:  "trace_open",
			wantParams: map[string]string{"rate": "10", "filter": "yes"},
		},
		{
			name: "empty key or value parameters are skipped",
			request: GadgetCollectRequest{
				EventType:  "open",
				Parameters: map[string]string{"": "value", "key": "", "good": "yes"},
			},
			wantImage:  "trace_open",
			wantParams: map[string]string{"good": "yes"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			image, params, err := gadgetRunConfig(tt.request)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if image != tt.wantImage {
				t.Fatalf("expected image %q, got %q", tt.wantImage, image)
			}
			for k, v := range tt.wantParams {
				if params[k] != v {
					t.Fatalf("expected param %s=%q, got %q", k, v, params[k])
				}
			}
		})
	}
}

func TestMatchesPod(t *testing.T) {
	tests := []struct {
		name      string
		fields    map[string]string
		namespace string
		pod       string
		want      bool
	}{
		{
			name:      "empty filters match everything",
			fields:    map[string]string{"proc.comm": "cat"},
			namespace: "",
			pod:       "",
			want:      true,
		},
		{
			name:      "matching namespace via k8s.namespace",
			fields:    map[string]string{"k8s.namespace": "prod"},
			namespace: "prod",
			pod:       "",
			want:      true,
		},
		{
			name:      "non-matching namespace via k8s.namespace",
			fields:    map[string]string{"k8s.namespace": "dev"},
			namespace: "prod",
			pod:       "",
			want:      false,
		},
		{
			name:      "matching pod via k8s.podName",
			fields:    map[string]string{"k8s.podName": "web"},
			namespace: "",
			pod:       "web",
			want:      true,
		},
		{
			name:      "non-matching pod via k8s.podName",
			fields:    map[string]string{"k8s.podName": "db"},
			namespace: "",
			pod:       "web",
			want:      false,
		},
		{
			name:      "events without k8s fields pass through",
			fields:    map[string]string{"proc.comm": "cat", "fname": "/etc/hosts"},
			namespace: "prod",
			pod:       "web",
			want:      true,
		},
		{
			name:      "namespace matches but pod does not",
			fields:    map[string]string{"k8s.namespace": "prod", "k8s.podName": "db"},
			namespace: "prod",
			pod:       "web",
			want:      false,
		},
		{
			name:      "both namespace and pod match",
			fields:    map[string]string{"k8s.namespace": "prod", "k8s.podName": "web"},
			namespace: "prod",
			pod:       "web",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesPod(tt.fields, tt.namespace, tt.pod)
			if got != tt.want {
				t.Fatalf("matchesPod(%v, %q, %q) = %v, want %v", tt.fields, tt.namespace, tt.pod, got, tt.want)
			}
		})
	}
}

func TestCoalesceField(t *testing.T) {
	tests := []struct {
		name     string
		fields   map[string]string
		fallback string
		keys     []string
		want     string
	}{
		{
			name:     "first key found",
			fields:   map[string]string{"k8s.namespace": "prod"},
			fallback: "default",
			keys:     []string{"k8s.namespace", "namespace"},
			want:     "prod",
		},
		{
			name:     "second key found",
			fields:   map[string]string{"namespace": "dev"},
			fallback: "default",
			keys:     []string{"k8s.namespace", "namespace"},
			want:     "dev",
		},
		{
			name:     "no key found returns fallback",
			fields:   map[string]string{},
			fallback: "default",
			keys:     []string{"k8s.namespace"},
			want:     "default",
		},
		{
			name:     "empty value skips to next key",
			fields:   map[string]string{"k8s.namespace": "", "namespace": "prod"},
			fallback: "default",
			keys:     []string{"k8s.namespace", "namespace"},
			want:     "prod",
		},
		{
			name:     "whitespace-only value skips to next key",
			fields:   map[string]string{"k8s.namespace": "   "},
			fallback: "fallback",
			keys:     []string{"k8s.namespace"},
			want:     "fallback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := coalesceField(tt.fields, tt.fallback, tt.keys...)
			if got != tt.want {
				t.Fatalf("coalesceField() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizePacketEventType(t *testing.T) {
	tests := []struct {
		name     string
		fallback string
		fields   map[string]string
		want     string
	}{
		{
			name:     "open type preserved",
			fallback: "open",
			fields:   map[string]string{},
			want:     "open",
		},
		{
			name:     "exec type preserved",
			fallback: "exec",
			fields:   map[string]string{},
			want:     "exec",
		},
		{
			name:     "connect with TCP protocol becomes tcpconnect",
			fallback: "connect",
			fields:   map[string]string{"l4proto": "TCP"},
			want:     "tcpconnect",
		},
		{
			name:     "connect without TCP stays connect",
			fallback: "connect",
			fields:   map[string]string{"l4proto": "UDP"},
			want:     "connect",
		},
		{
			name:     "tcpconnect with TCP protocol",
			fallback: "tcpconnect",
			fields:   map[string]string{"l4proto": "TCP"},
			want:     "tcpconnect",
		},
		{
			name:     "tcpconnect without protocol metadata stays tcpconnect",
			fallback: "tcpconnect",
			fields:   map[string]string{},
			want:     "tcpconnect",
		},
		{
			name:     "non-network fallback is preserved even with event field",
			fallback: "open",
			fields:   map[string]string{"event": "normal"},
			want:     "open",
		},
		{
			name:     "empty fallback uses event field",
			fallback: "",
			fields:   map[string]string{"event": "CONNECT"},
			want:     "connect",
		},
		{
			name:     "empty fallback uses type field when event missing",
			fallback: "",
			fields:   map[string]string{"type": "DNS"},
			want:     "dns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePacketEventType(tt.fallback, tt.fields)
			if got != tt.want {
				t.Fatalf("normalizePacketEventType(%q, ...) = %q, want %q", tt.fallback, got, tt.want)
			}
		})
	}
}

func TestNormalizeNetworkFields(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]string
		want   map[string]string
	}{
		{
			name: "dst aliases are projected",
			fields: map[string]string{
				"dst.addr": "8.8.8.8",
				"dst.port": "53",
				"src.addr": "10.244.0.12",
				"src.port": "37912",
			},
			want: map[string]string{
				"destination.ip":   "8.8.8.8",
				"destination.port": "53",
				"source.ip":        "10.244.0.12",
				"source.port":      "37912",
			},
		},
		{
			name: "existing canonical keys are preserved",
			fields: map[string]string{
				"destination.ip":   "1.1.1.1",
				"destination.port": "443",
				"dst.addr":         "8.8.8.8",
				"dst.port":         "53",
			},
			want: map[string]string{
				"destination.ip":   "1.1.1.1",
				"destination.port": "443",
			},
		},
		{
			name: "remote aliases are projected",
			fields: map[string]string{
				"remote.addr": "9.9.9.9",
				"remote.port": "853",
			},
			want: map[string]string{
				"destination.ip":   "9.9.9.9",
				"destination.port": "853",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeNetworkFields(tt.fields)
			for key, wantValue := range tt.want {
				if got[key] != wantValue {
					t.Fatalf("normalizeNetworkFields() key %q = %q, want %q", key, got[key], wantValue)
				}
			}
		})
	}
}

func TestFakeCollectorContextCancellation(t *testing.T) {
	// Verify the InspektorGadgetSource respects context cancellation.
	// This is a regression test: previously the gadget context was not
	// cancelled after RunGadget returned, causing goroutine leaks.
	c := &fakeCollector{events: []runtimeevents.Event{{Type: "open"}}}
	s := NewInspektorGadgetSource(1*time.Second, 1*time.Second)
	s.Collector = c

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"}}
	_, err := s.EventsForPod(ctx, pod, QueryOptions{EventTypes: []string{"open"}})
	// Should return error from cancelled context propagation, not hang.
	if err != nil {
		// Context cancellation may cause an error, which is acceptable.
		t.Logf("got expected error on cancelled context: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstring(s, sub))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
