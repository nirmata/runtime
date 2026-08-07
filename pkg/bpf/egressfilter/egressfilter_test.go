package egressfilter

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
)

// newUnloadedFilter builds a filter with no BPF objects, which exercises the
// argument handling and the nil-guards. Kernel behavior is covered by the linux
// e2e lane.
func newUnloadedFilter() *EgressFilter {
	l := logr.Discard()
	return &EgressFilter{logger: &l}
}

// TestFlagIndicesMatchKernelDefines guards against the Go constants drifting
// from the committed BPF program, which cannot be regenerated here.
func TestFlagIndicesMatchKernelDefines(t *testing.T) {
	data, err := os.ReadFile("_cprog/maps.h")
	if err != nil {
		t.Fatalf("reading _cprog/maps.h: %v", err)
	}

	want := map[string]int{"DEFAULT_DENY": DEFAULT_DENY, "LEARNING_MODE": OBSERVE}
	for define, goValue := range want {
		re := regexp.MustCompile(`(?m)^#define\s+` + define + `\s+(\d+)\s*$`)
		m := re.FindSubmatch(data)
		if m == nil {
			t.Fatalf("#define %s not found in _cprog/maps.h", define)
		}
		if got := string(m[1]); got != strconv.Itoa(goValue) {
			t.Errorf("#define %s = %s, Go constant = %d", define, got, goValue)
		}
	}
}

func TestSetFlagIdx_DoesNotPanicWithoutLoadedObjects(t *testing.T) {
	e := newUnloadedFilter()
	e.SetFlagIdx(DEFAULT_DENY, true)
	e.SetFlagIdx(OBSERVE, false)
}

func TestFlagIdx_PanicsOnOutOfRangeIndex(t *testing.T) {
	e := newUnloadedFilter()

	for _, idx := range []uint8{maxFlagIdx + 1, 255} {
		assertPanics(t, fmt.Sprintf("SetFlagIdx(%d)", idx), func() { e.SetFlagIdx(idx, true) })
		assertPanics(t, fmt.Sprintf("FlagIdx(%d)", idx), func() { _, _ = e.FlagIdx(idx) })
	}
}

func assertPanics(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", what)
		}
	}()
	fn()
}

func TestSetFlagIdx_DoesNotPanicWithNilLogger(t *testing.T) {
	e := &EgressFilter{}
	e.SetFlagIdx(DEFAULT_DENY, true)
}

func TestFlagIdx_ReportsUnloadedObjectsAsAnError(t *testing.T) {
	e := newUnloadedFilter()

	if _, err := e.FlagIdx(DEFAULT_DENY); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("FlagIdx err = %v, want ErrNotLoaded", err)
	}
}

func TestAddIps_ReturnsRejectedTargetsAsTypedValues(t *testing.T) {
	tests := []struct {
		name         string
		pair         *compiler.AllowDenyPair
		wantRejected []compiler.RejectedTarget
	}{
		{
			name: "nil pair",
		},
		{
			name: "empty pair",
			pair: &compiler.AllowDenyPair{},
		},
		{
			name: "rejections from both lists are reported, allow first",
			pair: &compiler.AllowDenyPair{
				Allow: []string{"10.0.0.1", "*.example.com"},
				Deny:  []string{"2001:db8::1", "10.0.0.0/8"},
			},
			wantRejected: []compiler.RejectedTarget{
				{Value: "*.example.com", Reason: ReasonWildcard},
				{Value: "2001:db8::1", Reason: ReasonIPv6},
				{Value: "10.0.0.0/8", Reason: ReasonCIDRTooWide},
			},
		},
		{
			name: "star alone is not a rejection",
			pair: &compiler.AllowDenyPair{Deny: []string{"*"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newUnloadedFilter()

			gotAdd, _ := e.AddIps(tc.pair)
			if diff := cmp.Diff(tc.wantRejected, gotAdd); diff != "" {
				t.Errorf("AddIps rejected mismatch (-want +got):\n%s", diff)
			}

			gotDel, _ := e.DeleteIps(tc.pair)
			if diff := cmp.Diff(tc.wantRejected, gotDel); diff != "" {
				t.Errorf("DeleteIps rejected mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAddIps_NilPairIsANoOp(t *testing.T) {
	e := newUnloadedFilter()

	rejected, err := e.AddIps(nil)
	if err != nil {
		t.Errorf("AddIps(nil) err = %v, want nil", err)
	}
	if rejected != nil {
		t.Errorf("AddIps(nil) rejected = %v, want nil", rejected)
	}

	if rejected, err := e.DeleteIps(nil); err != nil || rejected != nil {
		t.Errorf("DeleteIps(nil) = (%v, %v), want (nil, nil)", rejected, err)
	}
}

// A pair whose every value is rejected must not report a map-plumbing error:
// there is nothing left to program, so the rejections are the whole story.
func TestAddIps_AllTargetsRejectedYieldsNoMapError(t *testing.T) {
	e := newUnloadedFilter()

	rejected, err := e.AddIps(&compiler.AllowDenyPair{Deny: []string{"2001:db8::1"}})
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if len(rejected) != 1 {
		t.Errorf("rejected = %v, want 1 entry", rejected)
	}
}

func TestReadIPEvents_ReportsUnloadedObjectsAsAnError(t *testing.T) {
	e := newUnloadedFilter()

	got, err := e.ReadIPEvents()
	if !errors.Is(err, ErrNotLoaded) {
		t.Errorf("err = %v, want ErrNotLoaded", err)
	}
	if got != nil {
		t.Errorf("events = %v, want nil", got)
	}
}

func TestAttach_ReportsUnloadedObjectsAsAnError(t *testing.T) {
	e := newUnloadedFilter()

	if _, err := e.Attach("/sys/fs/cgroup/does-not-matter"); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("err = %v, want ErrNotLoaded", err)
	}
}

func TestSetObserve_UsesTheObserveFlagBit(t *testing.T) {
	// SetObserve must not panic and must not touch DEFAULT_DENY; without loaded
	// objects the only observable contract is that it is a safe no-op.
	e := newUnloadedFilter()
	e.SetObserve(true)
	e.SetObserve(false)
}
