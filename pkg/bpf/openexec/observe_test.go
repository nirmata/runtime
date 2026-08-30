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
func pk(t *testing.T, path string) PathEventKernelKey {
	t.Helper()
	k, err := NewKernelKeyFromGoTypes(path, uint32(runtimeevent.DecisionAllow))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pkDeny(t *testing.T, path string) PathEventKernelKey {
	t.Helper()
	k, err := NewKernelKeyFromGoTypes(path, uint32(runtimeevent.DecisionDeny))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestMergeCounts(t *testing.T) {
	tests := []struct {
		name string
		dst  map[PathEventKernelKey]uint32
		src  map[PathEventKernelKey]uint32
		want map[PathEventKernelKey]uint32
	}{
		{
			name: "empty destination takes everything",
			dst:  map[PathEventKernelKey]uint32{},
			src:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 3},
			want: map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 3},
		},
		{
			name: "disjoint keys are unioned",
			dst:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 3},
			src:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/wget"): 1},
			want: map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 3, pk(t, "/usr/bin/wget"): 1},
		},
		{
			name: "shared keys are summed",
			dst:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 3, pk(t, "/etc/passwd"): 2},
			src:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 4},
			want: map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 7, pk(t, "/etc/passwd"): 2},
		},
		{
			name: "same path under different decisions stays distinct",
			dst:  map[PathEventKernelKey]uint32{pk(t, "/etc/shadow"): 3},
			src:  map[PathEventKernelKey]uint32{pkDeny(t, "/etc/shadow"): 4},
			want: map[PathEventKernelKey]uint32{pk(t, "/etc/shadow"): 3, pkDeny(t, "/etc/shadow"): 4},
		},
		{
			name: "nil source leaves the destination untouched",
			dst:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 3},
			src:  nil,
			want: map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 3},
		},
		{
			name: "empty source leaves the destination untouched",
			dst:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 3},
			src:  map[PathEventKernelKey]uint32{},
			want: map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 3},
		},
		{
			name: "zero counts are still recorded as keys",
			dst:  map[PathEventKernelKey]uint32{},
			src:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 0},
			want: map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 0},
		},
		{
			name: "addition saturates instead of wrapping",
			dst:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): math.MaxUint32 - 1},
			src:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 5},
			want: map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): math.MaxUint32},
		},
		{
			name: "saturated destination stays saturated",
			dst:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): math.MaxUint32},
			src:  map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 1},
			want: map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): math.MaxUint32},
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
	mergeCounts(nil, map[PathEventKernelKey]uint32{pk(t, "/usr/bin/curl"): 1})
}

func TestNewKernelKeyRejectsOverlongPath(t *testing.T) {
	if _, err := NewKernelKeyFromGoTypes(strings.Repeat("a", maxPathLen+1), 0); err == nil {
		t.Error("NewKernelKeyFromGoTypes over maxPathLen returned nil error")
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

// A zero-value program has no maps: the observation API must report that as an
// error and never dereference a nil map.
func TestObservationWithoutMapsReportsUnavailable(t *testing.T) {
	l := &Prog{}

	if err := l.EnableObservation([]uint64{1, 2}); !errors.Is(err, ErrObservationUnavailable) {
		t.Errorf("EnableObservation err = %v, want ErrObservationUnavailable", err)
	}
	if err := l.DisableObservation([]uint64{1, 2}); !errors.Is(err, ErrObservationUnavailable) {
		t.Errorf("DisableObservation err = %v, want ErrObservationUnavailable", err)
	}

	got, err := l.ReadEvents()
	if !errors.Is(err, ErrObservationUnavailable) {
		t.Errorf("ReadEvents err = %v, want ErrObservationUnavailable", err)
	}
	if diff := cmp.Diff(map[uint64]map[PathEventKernelKey]uint32{}, got); diff != "" {
		t.Errorf("ReadEvents result mismatch (-want +got):\n%s", diff)
	}
}

func TestObservationWithNoCgidsIsANoOp(t *testing.T) {
	l := &Prog{}

	if err := l.EnableObservation(nil); err != nil {
		t.Errorf("EnableObservation(nil) err = %v, want nil", err)
	}
	if err := l.DisableObservation(nil); err != nil {
		t.Errorf("DisableObservation(nil) err = %v, want nil", err)
	}
}

func TestClose_ZeroValuePolicyMapIsSafe(t *testing.T) {
	m := &PolicyMap{}
	if err := m.Close(); err != nil {
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
	if got := int(unsafe.Sizeof(PathEventKernelKey{})); got != want {
		t.Errorf("sizeof(PathEventKernelKey) = %d, want %d", got, want)
	}
	if got := int(unsafe.Sizeof(runtimePolicyPathEventKey{})); got != want {
		t.Errorf("sizeof(runtimePolicyPathEventKey) = %d, want %d (generated from the C)", got, want)
	}
	if got, want := unsafe.Offsetof(PathEventKernelKey{}.Decision), unsafe.Offsetof(runtimePolicyPathEventKey{}.Decision); got != want {
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
	var l Prog

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
	var l Prog
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
