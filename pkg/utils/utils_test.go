package utils

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// The DiffSlice and MergeMapCount tables below originate from PR #57
// ("test: add unit tests for critical packages"), ported here so that work is
// not lost when this PR supersedes it. reflect.DeepEqual was swapped for
// cmp.Diff per CONVENTIONS, and the nil-map and overflow cases were added.

func TestDiffSlice(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want []string
	}{
		{name: "both nil", a: nil, b: nil, want: nil},
		{name: "empty a and b", a: []string{}, b: []string{}, want: nil},
		{name: "empty a returns all of b", a: []string{}, b: []string{"x", "y"}, want: []string{"x", "y"}},
		{name: "empty b returns nothing", a: []string{"x", "y"}, b: []string{}, want: nil},
		{name: "disjoint sets returns all of b", a: []string{"a", "b"}, b: []string{"c", "d"}, want: []string{"c", "d"}},
		{name: "overlap only returns entries unique to b", a: []string{"a", "b", "c"}, b: []string{"b", "c", "d"}, want: []string{"d"}},
		{name: "identical sets returns nothing", a: []string{"a", "b"}, b: []string{"a", "b"}, want: nil},
		{name: "duplicates in b not in a are preserved", a: []string{"a"}, b: []string{"b", "b", "c"}, want: []string{"b", "b", "c"}},
		{name: "duplicates in b that are in a are all removed", a: []string{"b"}, b: []string{"b", "b", "c"}, want: []string{"c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, DiffSlice(tt.a, tt.b)); diff != "" {
				t.Errorf("DiffSlice(%v, %v) (-want +got):\n%s", tt.a, tt.b, diff)
			}
		})
	}
}

// TestDiffSliceDoesNotMutateItsInputs matters because both managers call
// DiffSlice on state they still hold: a diff that reordered or truncated its
// arguments would corrupt the caller's tracking maps.
func TestDiffSliceDoesNotMutateItsInputs(t *testing.T) {
	a := []string{"a", "b"}
	b := []string{"b", "c"}

	DiffSlice(a, b)

	if diff := cmp.Diff([]string{"a", "b"}, a); diff != "" {
		t.Errorf("first argument was mutated (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"b", "c"}, b); diff != "" {
		t.Errorf("second argument was mutated (-want +got):\n%s", diff)
	}
}

func TestDiffSliceWithNonStringComparable(t *testing.T) {
	// exercise the generic parameter with a non-string comparable type
	got := DiffSlice([]int{1, 2, 3}, []int{2, 3, 4, 5})
	if diff := cmp.Diff([]int{4, 5}, got); diff != "" {
		t.Errorf("DiffSlice over ints (-want +got):\n%s", diff)
	}
}

func TestMergeMapCount(t *testing.T) {
	tests := []struct {
		name string
		dst  map[string]uint32
		src  map[string]uint32
		want map[string]uint32
	}{
		{
			name: "empty src leaves dst untouched",
			dst:  map[string]uint32{"a": 1},
			src:  map[string]uint32{},
			want: map[string]uint32{"a": 1},
		},
		{
			name: "empty dst gets populated from src",
			dst:  map[string]uint32{},
			src:  map[string]uint32{"a": 1, "b": 2},
			want: map[string]uint32{"a": 1, "b": 2},
		},
		{
			name: "overlapping keys accumulate counts",
			dst:  map[string]uint32{"a": 1, "b": 5},
			src:  map[string]uint32{"a": 2, "c": 3},
			want: map[string]uint32{"a": 3, "b": 5, "c": 3},
		},
		{
			name: "both empty",
			dst:  map[string]uint32{},
			src:  map[string]uint32{},
			want: map[string]uint32{},
		},
		{
			name: "nil src is a no-op",
			dst:  map[string]uint32{"a": 1},
			src:  nil,
			want: map[string]uint32{"a": 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			MergeMapCount(tt.dst, tt.src)
			if diff := cmp.Diff(tt.want, tt.dst); diff != "" {
				t.Errorf("after MergeMapCount, dst (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMergeMapCountIntoNilMapDoesNotPanic pins the no-panic rule: these counters
// come from BPF map reads, and a nil destination must be a no-op rather than a
// crash in the observation drain.
func TestMergeMapCountIntoNilMapDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MergeMapCount into a nil map panicked: %v", r)
		}
	}()

	var dst map[string]uint32
	MergeMapCount(dst, nil) // no entries to write: must not panic
}
