package compiler_test

import (
	"reflect"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
)

func TestAllowDenyPair_HasEntries(t *testing.T) {
	tests := []struct {
		name string
		p    *compiler.AllowDenyPair
		want bool
	}{
		{
			name: "nil receiver",
			p:    nil,
			want: false,
		},
		{
			name: "empty pair",
			p:    &compiler.AllowDenyPair{},
			want: false,
		},
		{
			name: "empty slices explicitly",
			p:    &compiler.AllowDenyPair{Allow: []string{}, Deny: []string{}},
			want: false,
		},
		{
			name: "only allow populated",
			p:    &compiler.AllowDenyPair{Allow: []string{"a"}},
			want: true,
		},
		{
			name: "only deny populated",
			p:    &compiler.AllowDenyPair{Deny: []string{"d"}},
			want: true,
		},
		{
			name: "both populated",
			p:    &compiler.AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.HasEntries(); got != tt.want {
				t.Errorf("HasEntries() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllowDenyPair_DiffPair(t *testing.T) {
	tests := []struct {
		name   string
		p      *compiler.AllowDenyPair
		target *compiler.AllowDenyPair
		want   *compiler.AllowDenyPair
	}{
		{
			name:   "nil target returns empty pair",
			p:      &compiler.AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}},
			target: nil,
			want:   &compiler.AllowDenyPair{},
		},
		{
			name:   "nil receiver returns target unchanged",
			p:      nil,
			target: &compiler.AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}},
			want:   &compiler.AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}},
		},
		{
			name:   "both nil-ish: nil receiver, nil target",
			p:      nil,
			target: nil,
			want:   &compiler.AllowDenyPair{},
		},
		{
			name:   "both empty",
			p:      &compiler.AllowDenyPair{},
			target: &compiler.AllowDenyPair{},
			want:   &compiler.AllowDenyPair{},
		},
		{
			name:   "disjoint entries: everything in target is new",
			p:      &compiler.AllowDenyPair{Allow: []string{"a"}, Deny: []string{"x"}},
			target: &compiler.AllowDenyPair{Allow: []string{"b"}, Deny: []string{"y"}},
			want:   &compiler.AllowDenyPair{Allow: []string{"b"}, Deny: []string{"y"}},
		},
		{
			name:   "identical entries: nothing new in target",
			p:      &compiler.AllowDenyPair{Allow: []string{"a", "b"}, Deny: []string{"x", "y"}},
			target: &compiler.AllowDenyPair{Allow: []string{"a", "b"}, Deny: []string{"x", "y"}},
			want:   &compiler.AllowDenyPair{},
		},
		{
			name:   "overlapping: only entries unique to target survive",
			p:      &compiler.AllowDenyPair{Allow: []string{"a", "b"}, Deny: []string{"x"}},
			target: &compiler.AllowDenyPair{Allow: []string{"b", "c"}, Deny: []string{"x", "y"}},
			want:   &compiler.AllowDenyPair{Allow: []string{"c"}, Deny: []string{"y"}},
		},
		{
			name:   "duplicate entries in target not in p are preserved",
			p:      &compiler.AllowDenyPair{Allow: []string{"a"}},
			target: &compiler.AllowDenyPair{Allow: []string{"b", "b", "c"}},
			want:   &compiler.AllowDenyPair{Allow: []string{"b", "b", "c"}},
		},
		{
			name:   "allow and deny sides are diffed independently",
			p:      &compiler.AllowDenyPair{Allow: []string{"shared"}, Deny: []string{}},
			target: &compiler.AllowDenyPair{Allow: []string{}, Deny: []string{"shared"}},
			want:   &compiler.AllowDenyPair{Deny: []string{"shared"}},
		},
		{
			name:   "empty target sides against non-empty p",
			p:      &compiler.AllowDenyPair{Allow: []string{"a"}, Deny: []string{"d"}},
			target: &compiler.AllowDenyPair{},
			want:   &compiler.AllowDenyPair{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.p.DiffPair(tt.target)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DiffPair() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
