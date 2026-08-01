package protofilter

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
func newUnloadedFilter() *ProtoFilter {
	l := logr.Discard()
	return &ProtoFilter{logger: &l}
}

// TestDefinesMatchKernelHeader guards against the Go constants drifting from
// the committed BPF program, which cannot be regenerated here.
func TestDefinesMatchKernelHeader(t *testing.T) {
	data, err := os.ReadFile("_cprog/maps.h")
	if err != nil {
		t.Fatalf("reading _cprog/maps.h: %v", err)
	}

	want := map[string]int{
		"DEFAULT_DENY":  DEFAULT_DENY,
		"LEARNING_MODE": OBSERVE,
		"ALPN_MAX_LEN":  compiler.MaxALPNLength,
		"PROTO_UNKNOWN": protoIDUnknown,
		"PROTO_SSH":     protoIDSSH,
		"PROTO_TLS":     protoIDTLS,
		"PROTO_HTTP1":   protoIDHTTP1,
		"PROTO_H2C":     protoIDH2C,
		"PROTO_QUIC":    protoIDQUIC,
	}
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
	p := newUnloadedFilter()
	p.SetFlagIdx(DEFAULT_DENY, true)
	p.SetFlagIdx(OBSERVE, false)
}

func TestFlagIdx_PanicsOnOutOfRangeIndex(t *testing.T) {
	p := newUnloadedFilter()

	for _, idx := range []uint8{maxFlagIdx + 1, 255} {
		assertPanics(t, fmt.Sprintf("SetFlagIdx(%d)", idx), func() { p.SetFlagIdx(idx, true) })
		assertPanics(t, fmt.Sprintf("FlagIdx(%d)", idx), func() { _, _ = p.FlagIdx(idx) })
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
	p := &ProtoFilter{}
	p.SetFlagIdx(DEFAULT_DENY, true)
}

func TestFlagIdx_ReportsUnloadedObjectsAsAnError(t *testing.T) {
	p := newUnloadedFilter()

	if _, err := p.FlagIdx(DEFAULT_DENY); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("FlagIdx err = %v, want ErrNotLoaded", err)
	}
}

func TestAddProtocols_ReturnsRejectedTargetsAsTypedValues(t *testing.T) {
	tests := []struct {
		name         string
		pair         *compiler.AllowDenyPair
		wantRejected []RejectedTarget
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
				Allow: []string{"ssh", "gopher"},
				Deny:  []string{"tls/", "h2c/h2"},
			},
			wantRejected: []RejectedTarget{
				{Value: "gopher", Reason: ReasonNotAProtocol},
				{Value: "tls/", Reason: ReasonInvalidALPN},
				{Value: "h2c/h2", Reason: ReasonNotAProtocol},
			},
		},
		{
			name: "star alone is not a rejection",
			pair: &compiler.AllowDenyPair{Deny: []string{"*"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newUnloadedFilter()

			gotAdd, _ := p.AddProtocols(tc.pair)
			if diff := cmp.Diff(tc.wantRejected, gotAdd); diff != "" {
				t.Errorf("AddProtocols rejected mismatch (-want +got):\n%s", diff)
			}

			gotDel, _ := p.DeleteProtocols(tc.pair)
			if diff := cmp.Diff(tc.wantRejected, gotDel); diff != "" {
				t.Errorf("DeleteProtocols rejected mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAddProtocols_NilPairIsANoOp(t *testing.T) {
	p := newUnloadedFilter()

	rejected, err := p.AddProtocols(nil)
	if err != nil {
		t.Errorf("AddProtocols(nil) err = %v, want nil", err)
	}
	if rejected != nil {
		t.Errorf("AddProtocols(nil) rejected = %v, want nil", rejected)
	}

	if rejected, err := p.DeleteProtocols(nil); err != nil || rejected != nil {
		t.Errorf("DeleteProtocols(nil) = (%v, %v), want (nil, nil)", rejected, err)
	}
}

// A pair whose every value is rejected must not report a map-plumbing error:
// there is nothing left to program, so the rejections are the whole story.
func TestAddProtocols_AllTargetsRejectedYieldsNoMapError(t *testing.T) {
	p := newUnloadedFilter()

	rejected, err := p.AddProtocols(&compiler.AllowDenyPair{Deny: []string{"gopher"}})
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if len(rejected) != 1 {
		t.Errorf("rejected = %v, want 1 entry", rejected)
	}
}

func TestReadProtoEvents_ReportsUnloadedObjectsAsAnError(t *testing.T) {
	p := newUnloadedFilter()

	got, err := p.ReadProtoEvents()
	if !errors.Is(err, ErrNotLoaded) {
		t.Errorf("err = %v, want ErrNotLoaded", err)
	}
	if got != nil {
		t.Errorf("events = %v, want nil", got)
	}
}

func TestSeedProtoEvent_ReportsUnloadedObjectsAsAnError(t *testing.T) {
	p := newUnloadedFilter()

	if err := p.SeedProtoEvent(Target{Protocol: compiler.ProtocolSSH}, 0, 1); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("err = %v, want ErrNotLoaded", err)
	}
}

func TestAttach_ReportsUnloadedObjectsAsAnError(t *testing.T) {
	p := newUnloadedFilter()

	if _, err := p.Attach("/sys/fs/cgroup/does-not-matter"); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("err = %v, want ErrNotLoaded", err)
	}
}
