package openexec

import (
	"errors"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

// pk builds an allow-decision key; pkDeny a deny-decision one. Counts for the
// same path under different decisions must never merge.
func pk(path string) PathEventKey {
	return PathEventKey{Path: path, Decision: runtimeevent.DecisionAllow}
}

func pkDeny(path string) PathEventKey {
	return PathEventKey{Path: path, Decision: runtimeevent.DecisionDeny}
}

func TestMergeCounts(t *testing.T) {
	tests := []struct {
		name string
		dst  map[PathEventKey]uint32
		src  map[PathEventKey]uint32
		want map[PathEventKey]uint32
	}{
		{
			name: "empty destination takes everything",
			dst:  map[PathEventKey]uint32{},
			src:  map[PathEventKey]uint32{pk("/usr/bin/curl"): 3},
			want: map[PathEventKey]uint32{pk("/usr/bin/curl"): 3},
		},
		{
			name: "disjoint keys are unioned",
			dst:  map[PathEventKey]uint32{pk("/usr/bin/curl"): 3},
			src:  map[PathEventKey]uint32{pk("/usr/bin/wget"): 1},
			want: map[PathEventKey]uint32{pk("/usr/bin/curl"): 3, pk("/usr/bin/wget"): 1},
		},
		{
			name: "shared keys are summed",
			dst:  map[PathEventKey]uint32{pk("/usr/bin/curl"): 3, pk("/etc/passwd"): 2},
			src:  map[PathEventKey]uint32{pk("/usr/bin/curl"): 4},
			want: map[PathEventKey]uint32{pk("/usr/bin/curl"): 7, pk("/etc/passwd"): 2},
		},
		{
			name: "same path under different decisions stays distinct",
			dst:  map[PathEventKey]uint32{pk("/etc/shadow"): 3},
			src:  map[PathEventKey]uint32{pkDeny("/etc/shadow"): 4},
			want: map[PathEventKey]uint32{pk("/etc/shadow"): 3, pkDeny("/etc/shadow"): 4},
		},
		{
			name: "nil source leaves the destination untouched",
			dst:  map[PathEventKey]uint32{pk("/usr/bin/curl"): 3},
			src:  nil,
			want: map[PathEventKey]uint32{pk("/usr/bin/curl"): 3},
		},
		{
			name: "empty source leaves the destination untouched",
			dst:  map[PathEventKey]uint32{pk("/usr/bin/curl"): 3},
			src:  map[PathEventKey]uint32{},
			want: map[PathEventKey]uint32{pk("/usr/bin/curl"): 3},
		},
		{
			name: "zero counts are still recorded as keys",
			dst:  map[PathEventKey]uint32{},
			src:  map[PathEventKey]uint32{pk("/usr/bin/curl"): 0},
			want: map[PathEventKey]uint32{pk("/usr/bin/curl"): 0},
		},
		{
			name: "addition saturates instead of wrapping",
			dst:  map[PathEventKey]uint32{pk("/usr/bin/curl"): math.MaxUint32 - 1},
			src:  map[PathEventKey]uint32{pk("/usr/bin/curl"): 5},
			want: map[PathEventKey]uint32{pk("/usr/bin/curl"): math.MaxUint32},
		},
		{
			name: "saturated destination stays saturated",
			dst:  map[PathEventKey]uint32{pk("/usr/bin/curl"): math.MaxUint32},
			src:  map[PathEventKey]uint32{pk("/usr/bin/curl"): 1},
			want: map[PathEventKey]uint32{pk("/usr/bin/curl"): math.MaxUint32},
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
	mergeCounts(nil, map[PathEventKey]uint32{pk("/usr/bin/curl"): 1})
}

// TestMergeCounts_FoldsEveryEnforcer pins the bug class where a read loop
// stops after the first enforcer, making every later enforcer's observations
// invisible. The fold must accumulate all of them regardless of order or
// overlap.
func TestMergeCounts_FoldsEveryEnforcer(t *testing.T) {
	perEnforcer := []map[PathEventKey]uint32{
		{pk("/usr/bin/curl"): 1},                            // file_open enforcer
		{pk("/usr/bin/curl"): 2, pk("/usr/bin/python3"): 5}, // exec enforcer
		{pkDeny("/etc/shadow"): 7},                          // a third enforcer (denies)
		{},                                                  // an enforcer that saw nothing
		nil,                                                 // an enforcer with no map at all
		{pk("/usr/bin/python3"): 1, pk("/usr/bin/nc"): 9}, // a late enforcer
	}

	got := map[PathEventKey]uint32{}
	for _, counts := range perEnforcer {
		mergeCounts(got, counts)
	}

	want := map[PathEventKey]uint32{
		pk("/usr/bin/curl"):    3,
		pk("/usr/bin/python3"): 6,
		pkDeny("/etc/shadow"):  7,
		pk("/usr/bin/nc"):      9,
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
	l := &OpenExecEnforcer{}

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
	if diff := cmp.Diff(map[uint64]map[PathEventKey]uint32{}, got); diff != "" {
		t.Errorf("ReadEvents result mismatch (-want +got):\n%s", diff)
	}
}

func TestObservationWithNoCgidsIsANoOp(t *testing.T) {
	l := &OpenExecEnforcer{}

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
	l := &OpenExecEnforcer{}
	if err := l.Close(); err != nil {
		t.Errorf("Close() err = %v, want nil", err)
	}
}

// TestPathEventKernelKeyLayout pins the hand-written iterator key against the
// bpf2go-generated struct for the C's `struct path_event_key` and against the
// documented 132-byte no-padding layout. A drift here is exactly the kind of
// BTF key-size mismatch cilium/ebpf rejects at runtime on Linux; this makes it
// fail in the unit suite on any host.
func TestPathEventKernelKeyLayout(t *testing.T) {
	const want = maxPathLen + 4 // char[128] + __u32, no padding
	if got := int(unsafe.Sizeof(pathEventKernelKey{})); got != want {
		t.Errorf("sizeof(pathEventKernelKey) = %d, want %d", got, want)
	}
	if got := int(unsafe.Sizeof(lsmRuntimePolicyPathEventKey{})); got != want {
		t.Errorf("sizeof(lsmRuntimePolicyPathEventKey) = %d, want %d (generated from the C)", got, want)
	}
	if got, want := unsafe.Offsetof(pathEventKernelKey{}.Decision), unsafe.Offsetof(lsmRuntimePolicyPathEventKey{}.Decision); got != want {
		t.Errorf("offsetof(Decision) = %d, want %d (generated from the C)", got, want)
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

func TestReadEventsLostReportsDeltaNotTotal(t *testing.T) {
	var l OpenExecEnforcer

	for _, tc := range []struct {
		total uint64
		want  uint64
	}{
		{total: 0, want: 0},
		{total: 7, want: 7},
		{total: 7, want: 0},
		{total: 10, want: 3},
		{total: 2, want: 0}, // counter reset: baseline follows it down
		{total: 5, want: 3},
	} {
		if got := l.lostSince(tc.total); got != tc.want {
			t.Errorf("lostSince(%d) = %d, want %d", tc.total, got, tc.want)
		}
	}
}

func TestReadEventsLostReportsUnavailableWithoutStatsMap(t *testing.T) {
	var l OpenExecEnforcer
	got, err := l.ReadEventsLost()
	if !errors.Is(err, ErrObservationUnavailable) {
		t.Errorf("err = %v, want ErrObservationUnavailable", err)
	}
	if got != 0 {
		t.Errorf("lost = %d, want 0", got)
	}
}

// TestPathStatKeysMatchKernelEnum guards the Go stat key against the committed
// BPF program, which cannot be regenerated on this host.
func TestPathStatKeysMatchKernelEnum(t *testing.T) {
	data, err := os.ReadFile("_cprog/maps.h")
	if err != nil {
		t.Fatalf("reading _cprog/maps.h: %v", err)
	}
	m := regexp.MustCompile(`(?m)^\s*PATH_STAT_COUNT_MAP_FULL\s*=\s*(\d+)\s*,`).FindSubmatch(data)
	if m == nil {
		t.Fatal("PATH_STAT_COUNT_MAP_FULL not found in _cprog/maps.h")
	}
	if got, want := string(m[1]), strconv.FormatUint(uint64(pathStatCountMapFull), 10); got != want {
		t.Errorf("PATH_STAT_COUNT_MAP_FULL = %s, Go pathStatCountMapFull = %s", got, want)
	}
}
