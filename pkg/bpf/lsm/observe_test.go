package lsm

import (
	"errors"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMergeCounts(t *testing.T) {
	tests := []struct {
		name string
		dst  map[string]uint32
		src  map[string]uint32
		want map[string]uint32
	}{
		{
			name: "empty destination takes everything",
			dst:  map[string]uint32{},
			src:  map[string]uint32{"/usr/bin/curl": 3},
			want: map[string]uint32{"/usr/bin/curl": 3},
		},
		{
			name: "disjoint keys are unioned",
			dst:  map[string]uint32{"/usr/bin/curl": 3},
			src:  map[string]uint32{"/usr/bin/wget": 1},
			want: map[string]uint32{"/usr/bin/curl": 3, "/usr/bin/wget": 1},
		},
		{
			name: "shared keys are summed",
			dst:  map[string]uint32{"/usr/bin/curl": 3, "/etc/passwd": 2},
			src:  map[string]uint32{"/usr/bin/curl": 4},
			want: map[string]uint32{"/usr/bin/curl": 7, "/etc/passwd": 2},
		},
		{
			name: "nil source leaves the destination untouched",
			dst:  map[string]uint32{"/usr/bin/curl": 3},
			src:  nil,
			want: map[string]uint32{"/usr/bin/curl": 3},
		},
		{
			name: "empty source leaves the destination untouched",
			dst:  map[string]uint32{"/usr/bin/curl": 3},
			src:  map[string]uint32{},
			want: map[string]uint32{"/usr/bin/curl": 3},
		},
		{
			name: "zero counts are still recorded as keys",
			dst:  map[string]uint32{},
			src:  map[string]uint32{"/usr/bin/curl": 0},
			want: map[string]uint32{"/usr/bin/curl": 0},
		},
		{
			name: "addition saturates instead of wrapping",
			dst:  map[string]uint32{"/usr/bin/curl": math.MaxUint32 - 1},
			src:  map[string]uint32{"/usr/bin/curl": 5},
			want: map[string]uint32{"/usr/bin/curl": math.MaxUint32},
		},
		{
			name: "saturated destination stays saturated",
			dst:  map[string]uint32{"/usr/bin/curl": math.MaxUint32},
			src:  map[string]uint32{"/usr/bin/curl": 1},
			want: map[string]uint32{"/usr/bin/curl": math.MaxUint32},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mergeCounts(tc.dst, tc.src)
			if diff := cmp.Diff(tc.want, tc.dst); diff != "" {
				t.Errorf("dst mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMergeCounts_NilDestinationDoesNotPanic(t *testing.T) {
	mergeCounts(nil, map[string]uint32{"/usr/bin/curl": 1})
}

// TestMergeCounts_FoldsEveryEnforcer_Issue52 pins the bug class from #52: the
// deleted LsmManager.Read broke out of its loop after the first enforcer, so
// every later enforcer's observations were invisible. The fold must accumulate
// all of them regardless of order or overlap.
func TestMergeCounts_FoldsEveryEnforcer_Issue52(t *testing.T) {
	perEnforcer := []map[string]uint32{
		{"/usr/bin/curl": 1},                        // file_open enforcer
		{"/usr/bin/curl": 2, "/usr/bin/python3": 5}, // exec enforcer
		{"/etc/shadow": 7},                          // a third enforcer
		{},                                          // an enforcer that saw nothing
		nil,                                         // an enforcer with no map at all
		{"/usr/bin/python3": 1, "/usr/bin/nc": 9}, // a late enforcer
	}

	got := map[string]uint32{}
	for _, counts := range perEnforcer {
		mergeCounts(got, counts)
	}

	want := map[string]uint32{
		"/usr/bin/curl":    3,
		"/usr/bin/python3": 6,
		"/etc/shadow":      7,
		"/usr/bin/nc":      9,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("folded counts mismatch (-want +got):\n%s", diff)
	}
}

func TestTrimPathKey(t *testing.T) {
	pad := func(s string) [maxPathLen]byte {
		var k [maxPathLen]byte
		copy(k[:], s)
		return k
	}
	full := func() [maxPathLen]byte {
		var k [maxPathLen]byte
		for i := range k {
			k[i] = 'a'
		}
		return k
	}

	tests := []struct {
		name string
		key  [maxPathLen]byte
		want string
	}{
		{name: "NUL terminated path", key: pad("/usr/bin/curl"), want: "/usr/bin/curl"},
		{name: "all zero key is empty", key: pad(""), want: ""},
		{name: "single byte path", key: pad("/"), want: "/"},
		{name: "unterminated full width key", key: full(), want: strings.Repeat("a", maxPathLen)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := trimPathKey(tc.key); got != tc.want {
				t.Errorf("trimPathKey() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A zero-value enforcer has no maps: the observation API must report that as an
// error and never dereference a nil map.
func TestObservationWithoutMapsReportsUnavailable(t *testing.T) {
	l := &LsmEnforcer{}

	if err := l.EnableObservation([]uint64{1, 2}); !errors.Is(err, ErrObservationUnavailable) {
		t.Errorf("EnableObservation err = %v, want ErrObservationUnavailable", err)
	}
	if err := l.DisableObservation([]uint64{1, 2}); !errors.Is(err, ErrObservationUnavailable) {
		t.Errorf("DisableObservation err = %v, want ErrObservationUnavailable", err)
	}

	got, err := l.ReadEvents([]uint64{1, 2})
	if !errors.Is(err, ErrObservationUnavailable) {
		t.Errorf("ReadEvents err = %v, want ErrObservationUnavailable", err)
	}
	if diff := cmp.Diff(map[uint64]map[string]uint32{}, got); diff != "" {
		t.Errorf("ReadEvents result mismatch (-want +got):\n%s", diff)
	}
}

func TestObservationWithNoCgidsIsANoOp(t *testing.T) {
	l := &LsmEnforcer{}

	if err := l.EnableObservation(nil); err != nil {
		t.Errorf("EnableObservation(nil) err = %v, want nil", err)
	}
	if err := l.DisableObservation(nil); err != nil {
		t.Errorf("DisableObservation(nil) err = %v, want nil", err)
	}
	got, err := l.ReadEvents(nil)
	if err != nil {
		t.Errorf("ReadEvents(nil) err = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("ReadEvents(nil) = %v, want empty", got)
	}
}

func TestClose_ZeroValueEnforcerIsSafe(t *testing.T) {
	l := &LsmEnforcer{}
	if err := l.Close(); err != nil {
		t.Errorf("Close() err = %v, want nil", err)
	}
}

// TestMaxPathLenMatchesKernelDefine guards the Go key width against the
// committed BPF program, which cannot be regenerated on this host.
func TestMaxPathLenMatchesKernelDefine(t *testing.T) {
	data, err := os.ReadFile("_cprog/maps.h")
	if err != nil {
		t.Fatalf("reading _cprog/maps.h: %v", err)
	}
	m := regexp.MustCompile(`(?m)^#define\s+MAX_PATH_LEN\s+(\d+)\s*$`).FindSubmatch(data)
	if m == nil {
		t.Fatal("#define MAX_PATH_LEN not found in _cprog/maps.h")
	}
	if got, want := string(m[1]), strconv.Itoa(maxPathLen); got != want {
		t.Errorf("#define MAX_PATH_LEN = %s, Go maxPathLen = %s", got, want)
	}
}
