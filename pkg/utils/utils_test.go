package utils

import (
	"reflect"
	"testing"
)

func TestDiffSlice(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want []string
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: nil,
		},
		{
			name: "empty a and b",
			a:    []string{},
			b:    []string{},
			want: nil,
		},
		{
			name: "empty a returns all of b",
			a:    []string{},
			b:    []string{"x", "y"},
			want: []string{"x", "y"},
		},
		{
			name: "empty b returns nothing",
			a:    []string{"x", "y"},
			b:    []string{},
			want: nil,
		},
		{
			name: "disjoint sets returns all of b",
			a:    []string{"a", "b"},
			b:    []string{"c", "d"},
			want: []string{"c", "d"},
		},
		{
			name: "overlap only returns entries unique to b",
			a:    []string{"a", "b", "c"},
			b:    []string{"b", "c", "d"},
			want: []string{"d"},
		},
		{
			name: "identical sets returns nothing",
			a:    []string{"a", "b"},
			b:    []string{"a", "b"},
			want: nil,
		},
		{
			name: "duplicates in b not in a are preserved",
			a:    []string{"a"},
			b:    []string{"b", "b", "c"},
			want: []string{"b", "b", "c"},
		},
		{
			name: "duplicates in b that are in a are all removed",
			a:    []string{"b"},
			b:    []string{"b", "b", "c"},
			want: []string{"c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DiffSlice(tt.a, tt.b)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DiffSlice(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestDiffSliceInt(t *testing.T) {
	// exercise the generic parameter with a non-string comparable type
	a := []int{1, 2, 3}
	b := []int{2, 3, 4, 5}
	want := []int{4, 5}
	got := DiffSlice(a, b)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DiffSlice(%v, %v) = %v, want %v", a, b, got, want)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			MergeMapCount(tt.dst, tt.src)
			if !reflect.DeepEqual(tt.dst, tt.want) {
				t.Errorf("after MergeMapCount, dst = %v, want %v", tt.dst, tt.want)
			}
		})
	}
}
