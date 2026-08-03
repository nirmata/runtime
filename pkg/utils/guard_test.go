package utils

import (
	"errors"
	"strings"
	"testing"
)

var errSentinel = errors.New("sentinel")

func TestGuard_ReturnsFnResult(t *testing.T) {
	tests := []struct {
		name string
		fn   func() error
		want error
	}{
		{
			name: "nil error passes through",
			fn:   func() error { return nil },
			want: nil,
		},
		{
			name: "error passes through unwrapped so sentinels survive",
			fn:   func() error { return errSentinel },
			want: errSentinel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Guard("op", tt.fn)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Guard() error = %v, want %v", err, tt.want)
			}
			if err != nil && errors.Is(err, ErrPanic) {
				t.Errorf("Guard() error = %v, must not be classified as a panic", err)
			}
		})
	}
}

func TestGuard_ConvertsPanicToError(t *testing.T) {
	tests := []struct {
		name string
		fn   func() error
		// wantIn is a substring the error message must contain.
		wantIn string
		// wantErr, when set, must be reachable via errors.Is.
		wantErr error
	}{
		{
			name:   "panic with a string",
			fn:     func() error { panic("boom") },
			wantIn: "boom",
		},
		{
			name:    "panic with an error is wrapped so errors.Is reaches it",
			fn:      func() error { panic(errSentinel) },
			wantIn:  "sentinel",
			wantErr: errSentinel,
		},
		{
			name: "nil map write",
			fn: func() error {
				var m map[string]string
				//nolint:staticcheck // SA5000: the nil-map write is the panic under test
				m["k"] = "v"
				return nil
			},
			wantIn: "nil map",
		},
		{
			name: "index out of range",
			fn: func() error {
				s := []string{}
				_ = s[1]
				return nil
			},
			wantIn: "index out of range",
		},
		{
			name: "nil pointer dereference",
			fn: func() error {
				type t struct{ n int }
				var p *t
				_ = p.n
				return nil
			},
			wantIn: "nil pointer dereference",
		},
		{
			name:   "panic with nil",
			fn:     func() error { panic(nil) },
			wantIn: "panic called with nil argument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Guard("guarded operation", tt.fn)
			if err == nil {
				t.Fatal("Guard() error = nil, want an error converted from a panic")
			}
			if !errors.Is(err, ErrPanic) {
				t.Errorf("Guard() error = %v, want errors.Is(err, ErrPanic)", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Guard() error = %v, want errors.Is(err, %v)", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantIn) {
				t.Errorf("Guard() error = %q, want it to contain %q", err.Error(), tt.wantIn)
			}
			if !strings.Contains(err.Error(), "guarded operation") {
				t.Errorf("Guard() error = %q, want it to name the guarded op", err.Error())
			}
			if !strings.Contains(err.Error(), "guard_test.go") {
				t.Errorf("Guard() error = %q, want it to carry the panic stack", err.Error())
			}
		})
	}
}

func TestGuard_PanicInNestedCallIsRecovered(t *testing.T) {
	deep := func() { panic("deep") }
	middle := func() error {
		deep()
		return nil
	}
	if err := Guard("nested", middle); err == nil || !errors.Is(err, ErrPanic) {
		t.Fatalf("Guard() error = %v, want a recovered panic error", err)
	}
}

func TestGuard_NilFunctionReturnsError(t *testing.T) {
	err := Guard("nil fn", nil)
	if err == nil {
		t.Fatal("Guard() error = nil, want an error for a nil function")
	}
	if errors.Is(err, ErrPanic) {
		t.Errorf("Guard() error = %v, a nil function must not be reported as a panic", err)
	}
}
