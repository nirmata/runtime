package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

func TestSyntheticSourceEmitsEveryEventThenReturnsNil(t *testing.T) {
	want := []runtimeevent.Event{netEvent("a"), netEvent("b"), netEvent("c")}
	s := NewSyntheticSource("fixtures", want)
	if s.Name() != "fixtures" {
		t.Errorf("Name() = %q, want fixtures", s.Name())
	}

	out := make(chan runtimeevent.Event, len(want))
	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background(), out) }()

	var got []string
	for range want {
		got = append(got, recvEvent(t, out).Comm)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil after replaying every event", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after replaying every event")
	}
	if diff := cmp.Diff([]string{"a", "b", "c"}, got); diff != "" {
		t.Errorf("emitted (-want +got):\n%s", diff)
	}
}

func TestSyntheticSourceStopsOnContextCancel(t *testing.T) {
	s := NewSyntheticSource("fixtures", []runtimeevent.Event{netEvent("a"), netEvent("b")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Unbuffered out: with ctx already cancelled Run must return instead of
	// blocking forever on the first send.
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, make(chan runtimeevent.Event)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Run did not return on a cancelled context")
	}
}

func TestLoadEvents(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []runtimeevent.Event
		wantErr string
		check   func(t *testing.T, got []runtimeevent.Event)
	}{{
		name: "empty array",
		in:   `[]`,
		want: []runtimeevent.Event{},
	}, {
		name: "net and dns events",
		in: `[
		  {"kind":"net","time":"2026-07-27T10:00:00Z","pid":42,"comm":"curl","count":3,
		   "net":{"destIP":"10.1.2.3","destPort":443,"protocol":"tcp"},
		   "pod":{"uid":"pod-1","namespace":"team-a","name":"agent-0"}},
		  {"kind":"dns","time":"2026-07-27T10:00:01Z","dns":{"qname":"api.openai.com","qtype":1}}
		]`,
		check: func(t *testing.T, got []runtimeevent.Event) {
			t.Helper()
			if len(got) != 2 {
				t.Fatalf("len = %d, want 2", len(got))
			}
			if got[0].Kind != runtimeevent.KindNet || got[0].Net == nil ||
				got[0].Net.DestIP.String() != "10.1.2.3" || got[0].Net.DestPort != 443 {
				t.Errorf("event 0 = %+v, want net 10.1.2.3:443", got[0])
			}
			if got[0].PID != 42 || got[0].Comm != "curl" || got[0].Count != 3 {
				t.Errorf("event 0 scalars = %+v", got[0])
			}
			if got[0].Pod.UID != "pod-1" || got[0].Pod.Namespace != "team-a" {
				t.Errorf("event 0 pod = %+v", got[0].Pod)
			}
			if got[1].Kind != runtimeevent.KindDNS || got[1].DNS == nil || got[1].DNS.QName != "api.openai.com" {
				t.Errorf("event 1 = %+v, want dns api.openai.com", got[1])
			}
			wantTime := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
			if !got[0].Time.Equal(wantTime) {
				t.Errorf("event 0 time = %v, want %v", got[0].Time, wantTime)
			}
		},
	}, {
		name: "http fixture is re-redacted on load",
		in: `[{"kind":"http","http":{"method":"POST","path":"/v1/messages","host":"API.ANTHROPIC.COM",
		     "headers":{"Authorization":"Bearer sk-ant-canary","X-Api-Key":"canary-KEY-123","content-type":"application/json"},
		     "bodyPreview":"{\"model\":\"claude\"}"}}]`,
		check: func(t *testing.T, got []runtimeevent.Event) {
			t.Helper()
			if len(got) != 1 || got[0].HTTP == nil {
				t.Fatalf("got %+v, want one http event", got)
			}
			h := got[0].HTTP
			if h.Header("authorization") != runtimeevent.Redacted {
				t.Errorf("authorization = %q, want %q", h.Header("authorization"), runtimeevent.Redacted)
			}
			if h.Header("x-api-key") != runtimeevent.Redacted {
				t.Errorf("x-api-key = %q, want %q", h.Header("x-api-key"), runtimeevent.Redacted)
			}
			if h.Header("content-type") != "application/json" {
				t.Errorf("content-type = %q, want it preserved", h.Header("content-type"))
			}
			if h.Host() != "api.anthropic.com" || h.Method() != "POST" || h.Path() != "/v1/messages" {
				t.Errorf("request line = %s %s %s", h.Method(), h.Path(), h.Host())
			}
			for k, v := range h.Headers() {
				if strings.Contains(v, "sk-ant-canary") || strings.Contains(v, "canary-KEY-123") {
					t.Errorf("header %q leaked a secret value: %q", k, v)
				}
			}
		},
	}, {
		name:    "malformed json",
		in:      `[{"kind":`,
		wantErr: "decoding events",
	}, {
		name:    "object instead of array",
		in:      `{"kind":"net"}`,
		wantErr: "decoding events",
	}, {
		name:    "trailing content",
		in:      `[] [] `,
		wantErr: "trailing",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LoadEvents(strings.NewReader(tc.in))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadEvents: %v", err)
			}
			if tc.check != nil {
				tc.check(t, got)
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("events (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoadEventsNilReader(t *testing.T) {
	if _, err := LoadEvents(nil); err == nil {
		t.Error("LoadEvents(nil) returned no error")
	}
}

func TestLoadEventsFeedsSyntheticSource(t *testing.T) {
	evs, err := LoadEvents(strings.NewReader(
		`[{"kind":"exec","comm":"npx","exec":{"filename":"/usr/bin/npx","argv":["npx","-y","mcp-server"]}}]`))
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	out := make(chan runtimeevent.Event, 1)
	if err := NewSyntheticSource("fixtures", evs).Run(context.Background(), out); err != nil {
		t.Fatalf("Run: %v", err)
	}
	ev := recvEvent(t, out)
	if ev.Kind != runtimeevent.KindExec || ev.Exec == nil {
		t.Fatalf("got %+v, want an exec event", ev)
	}
	if diff := cmp.Diff([]string{"npx", "-y", "mcp-server"}, ev.Exec.Argv); diff != "" {
		t.Errorf("argv (-want +got):\n%s", diff)
	}
}
