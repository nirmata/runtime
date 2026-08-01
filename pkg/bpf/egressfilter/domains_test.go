package egressfilter

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// wire builds the expected key bytes from hand-written labels, so the test
// states the encoding rather than re-deriving it from the encoder.
func wire(parts ...string) []byte {
	out := make([]byte, 0, maxDomainKeyLen)
	for _, p := range parts {
		out = append(out, byte(len(p)))
		out = append(out, p...)
	}
	return append(out, 0)
}

func TestEncodeDomainKey_MatchesTheWireFormat(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []byte
	}{
		{
			name: "three labels",
			in:   "api.example.com",
			want: wire("api", "example", "com"),
		},
		{
			name: "two labels",
			in:   "example.com",
			want: wire("example", "com"),
		},
		{
			name: "uppercase is lowered",
			in:   "API.Example.COM",
			want: wire("api", "example", "com"),
		},
		{
			name: "root dot is dropped",
			in:   "api.example.com.",
			want: wire("api", "example", "com"),
		},
		{
			name: "digits and dashes survive unchanged",
			in:   "s3-eu-west-1.amazonaws.com",
			want: wire("s3-eu-west-1", "amazonaws", "com"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := encodeDomainKey(tc.in)
			if err != nil {
				t.Fatalf("encodeDomainKey(%q) err = %v", tc.in, err)
			}

			var want [maxDomainKeyLen]byte
			copy(want[:], tc.want)
			if diff := cmp.Diff(want[:], key.Name[:]); diff != "" {
				t.Errorf("key bytes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// The label byte immediately after the terminating zero must stay zero: the
// kernel compares the whole 128-byte key, so a stale byte would split one
// logical name across two entries.
func TestEncodeDomainKey_PadsWithZeros(t *testing.T) {
	key, err := encodeDomainKey("a.io")
	if err != nil {
		t.Fatalf("encodeDomainKey err = %v", err)
	}
	encoded := len(wire("a", "io"))
	for i := encoded; i < maxDomainKeyLen; i++ {
		if key.Name[i] != 0 {
			t.Fatalf("byte %d = %d, want 0", i, key.Name[i])
		}
	}
}

// The widest name that still fits: its wire form is exactly the key width.
func TestEncodeDomainKey_AcceptsTheWidestNameThatFits(t *testing.T) {
	name := strings.Repeat("a", 60) + "." + strings.Repeat("b", 61) + ".com"

	key, err := encodeDomainKey(name)
	if err != nil {
		t.Fatalf("encodeDomainKey err = %v", err)
	}
	want := wire(strings.Repeat("a", 60), strings.Repeat("b", 61), "com")
	if len(want) != maxDomainKeyLen {
		t.Fatalf("expected encoding is %d bytes, want %d", len(want), maxDomainKeyLen)
	}
	if diff := cmp.Diff(want, key.Name[:]); diff != "" {
		t.Errorf("key bytes mismatch (-want +got):\n%s", diff)
	}
}

// A key that does not fit must be rejected: truncating it would silently match
// a different domain.
func TestEncodeDomainKey_RejectsNamesThatOverflowTheKey(t *testing.T) {
	oneOver := strings.Repeat("a", 61) + "." + strings.Repeat("b", 61) + ".com"
	atDNSLimit := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 61)
	if len(atDNSLimit) != 253 {
		t.Fatalf("fixture is %d characters, want the 253 DNS limit", len(atDNSLimit))
	}

	for _, name := range []string{oneOver, atDNSLimit} {
		key, err := encodeDomainKey(name)
		if !errors.Is(err, errDomainKeyTooLong) {
			t.Errorf("encodeDomainKey(%d chars) err = %v, want errDomainKeyTooLong", len(name), err)
		}
		if key.Name != ([maxDomainKeyLen]byte{}) {
			t.Errorf("encodeDomainKey(%d chars) returned a non-zero key", len(name))
		}
	}
}

func TestEncodeDomainKey_RejectsUnencodableNames(t *testing.T) {
	for _, name := range []string{"", ".", "api..example.com", strings.Repeat("a", 64) + ".com"} {
		if _, err := encodeDomainKey(name); !errors.Is(err, errDomainMalformed) {
			t.Errorf("encodeDomainKey(%q) err = %v, want errDomainMalformed", name, err)
		}
	}
}

func TestReserveDomainID_StartsAtOneAndIsStable(t *testing.T) {
	e := newUnloadedFilter()

	first, ok := e.reserveDomainID("api.example.com")
	if !ok {
		t.Fatal("reserveDomainID reported the table full on the first name")
	}
	if first != 1 {
		t.Errorf("first id = %d, want 1: the kernel reserves 0 for \"no domain known\"", first)
	}

	again, ok := e.reserveDomainID("api.example.com")
	if !ok || again != first {
		t.Errorf("re-interning gave (%d, %v), want (%d, true)", again, ok, first)
	}

	second, ok := e.reserveDomainID("cdn.example.com")
	if !ok || second != 2 {
		t.Errorf("second name gave (%d, %v), want (2, true)", second, ok)
	}
}

func TestReserveDomainID_ExhaustsAtTheMapCapacity(t *testing.T) {
	e := newUnloadedFilter()

	for i := 0; i < maxDomains; i++ {
		if _, ok := e.reserveDomainID(fmt.Sprintf("host-%d.example.com", i)); !ok {
			t.Fatalf("table reported full after %d names, want %d", i, maxDomains)
		}
	}

	if _, ok := e.reserveDomainID("one.too.many"); ok {
		t.Errorf("reserveDomainID accepted name %d, want the table to be full", maxDomains+1)
	}
	// an already interned name still resolves once the table is full
	if id, ok := e.reserveDomainID("host-0.example.com"); !ok || id != 1 {
		t.Errorf("interned name gave (%d, %v), want (1, true)", id, ok)
	}
}

func TestPutDomains_SurfacesExhaustionAsARejectedTarget(t *testing.T) {
	e := newUnloadedFilter()
	for i := 0; i < maxDomains; i++ {
		e.reserveDomainID(fmt.Sprintf("host-%d.example.com", i))
	}

	rejected, _ := e.putDomains(nil, "allowed_domains", []string{"one.too.many"})

	want := []RejectedTarget{{Value: "one.too.many", Reason: ReasonTooManyDomains}}
	if diff := cmp.Diff(want, rejected); diff != "" {
		t.Errorf("rejected mismatch (-want +got):\n%s", diff)
	}
}

func TestPutDomains_ReportsUnloadedObjectsAsAnError(t *testing.T) {
	e := newUnloadedFilter()

	rejected, err := e.putDomains(nil, "allowed_domains", []string{"api.example.com"})
	if !errors.Is(err, ErrNotLoaded) {
		t.Errorf("err = %v, want ErrNotLoaded", err)
	}
	if len(rejected) != 0 {
		t.Errorf("rejected = %v, want none: an unloaded map is a plumbing failure, not a bad target", rejected)
	}
}

// A name that was never interned was never programmed, so removing it is a
// no-op rather than an error.
func TestDeleteDomains_IgnoresNamesThatWereNeverInterned(t *testing.T) {
	e := newUnloadedFilter()

	if err := e.deleteDomains(nil, "allowed_domains", []string{"api.example.com"}); err != nil {
		t.Errorf("deleteDomains err = %v, want nil", err)
	}
}
