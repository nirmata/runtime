package main

import (
	"testing"

	"github.com/nirmata/runtime/pkg/pushsink"
	"github.com/nirmata/runtime/pkg/reporter"

	"github.com/go-logr/logr"
)

func TestFindingSinksSkipsAbsentSinks(t *testing.T) {
	rep := reporter.New(nil, logr.Discard(), nil, reporter.Options{})
	push := &pushsink.GRPCSink{}

	cases := []struct {
		name     string
		rep      *reporter.Reporter
		push     *pushsink.GRPCSink
		wantSize int
	}{
		{"both absent", nil, nil, 0},
		{"reporter only", rep, nil, 1},
		{"push only", nil, push, 1},
		{"both present", rep, push, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sinks := findingSinks(tc.rep, tc.push)
			if len(sinks) != tc.wantSize {
				t.Fatalf("findingSinks() len = %d, want %d", len(sinks), tc.wantSize)
			}
			for i, s := range sinks {
				if s == nil {
					t.Errorf("sinks[%d] is nil as an interface value", i)
				}
			}
		})
	}
}
