package egressfilter

import (
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unsafe"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr/funcr"
	"github.com/google/go-cmp/cmp"
)

// TestIPEventKernelKeyMirrorsTheCStruct pins the Go key to `struct
// ip_event_key`. cilium/ebpf marshals a key by its Go memory layout, so a
// drifted field order, width or offset is not a compile error: it silently
// reads and writes the wrong bytes.
func TestIPEventKernelKeyMirrorsTheCStruct(t *testing.T) {
	cFields := cStructFields(t, "ip_event_key")
	if diff := cmp.Diff([]string{"daddr", "decision", "domain_id"}, cFields); diff != "" {
		t.Fatalf("_cprog/maps.h struct ip_event_key fields changed (-want +got):\n%s", diff)
	}

	typ := reflect.TypeOf(ipEventKernelKey{})
	if typ.NumField() != len(cFields) {
		t.Fatalf("ipEventKernelKey has %d fields, struct ip_event_key has %d", typ.NumField(), len(cFields))
	}
	for i, cName := range cFields {
		f := typ.Field(i)
		if want := goFieldName(cName); f.Name != want {
			t.Errorf("field %d is %s, want %s (C field %s)", i, f.Name, want, cName)
		}
		if f.Type.Kind() != reflect.Uint32 {
			t.Errorf("field %s is %s, want uint32 (C field %s is __u32)", f.Name, f.Type, cName)
		}
		if want := uintptr(4 * i); f.Offset != want {
			t.Errorf("field %s is at offset %d, want %d", f.Name, f.Offset, want)
		}
	}
	if got := unsafe.Sizeof(ipEventKernelKey{}); got != 12 {
		t.Errorf("sizeof(ipEventKernelKey) = %d, want 12 (three __u32, no padding)", got)
	}
}

// TestIPEventsMapKeySizeMatchesTheGoKey checks the Go key against the key size
// the committed BPF object declares, which is the size the kernel will enforce
// on every lookup. Reading the ELF needs no kernel, so this runs everywhere.
func TestIPEventsMapKeySizeMatchesTheGoKey(t *testing.T) {
	spec, err := loadEgressBlock()
	if err != nil {
		t.Fatalf("loading the committed egress BPF object: %v", err)
	}
	m, ok := spec.Maps["ip_events"]
	if !ok {
		t.Fatal("the committed BPF object declares no ip_events map")
	}
	if want := uint32(unsafe.Sizeof(ipEventKernelKey{})); m.KeySize != want {
		t.Errorf("ip_events KeySize = %d, sizeof(ipEventKernelKey) = %d", m.KeySize, want)
	}
}

// cStructFields returns the field names of a struct in _cprog/maps.h, in
// declaration order.
func cStructFields(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile("_cprog/maps.h")
	if err != nil {
		t.Fatalf("reading _cprog/maps.h: %v", err)
	}
	re := regexp.MustCompile(`(?s)struct\s+` + regexp.QuoteMeta(name) + `\s*\{(.*?)\}`)
	m := re.FindSubmatch(data)
	if m == nil {
		t.Fatalf("struct %s not found in _cprog/maps.h", name)
	}

	var fields []string
	for _, decl := range strings.Split(string(m[1]), ";") {
		parts := strings.Fields(decl)
		if len(parts) < 2 {
			continue
		}
		fields = append(fields, strings.TrimSuffix(parts[len(parts)-1], ","))
	}
	return fields
}

func goFieldName(cName string) string {
	var b strings.Builder
	for _, part := range strings.Split(cName, "_") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		b.WriteString(part[1:])
	}
	return b.String()
}

func TestDomainNamer(t *testing.T) {
	e := newUnloadedFilter()
	id, ok := e.reserveDomainID("api.example.com")
	if !ok {
		t.Fatal("reserveDomainID reported the table full on an empty filter")
	}

	namer := e.domainNamer()
	tests := []struct {
		name string
		id   uint32
		want string
	}{
		{name: "no domain known", id: 0},
		{name: "interned id", id: id, want: "api.example.com"},
		{name: "id the table cannot name", id: id + 1000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := namer(tc.id); got != tc.want {
				t.Errorf("namer(%d) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

// An id the intern table cannot name must not turn into a silent gap: the
// observation keeps its address and the miss is logged.
func TestDomainNamer_LogsAnUnnameableID(t *testing.T) {
	var logged []string
	l := funcr.New(func(prefix, args string) { logged = append(logged, args) }, funcr.Options{})
	e := &EgressFilter{logger: &l}

	if got := e.domainNamer()(42); got != "" {
		t.Errorf("namer(42) = %q, want the empty name", got)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "42") {
		t.Errorf("log lines = %v, want one naming domain id 42", logged)
	}
}

func TestEventKeyCarriesTheResolvedDomain(t *testing.T) {
	e := newUnloadedFilter()
	id, _ := e.reserveDomainID("api.example.com")
	namer := e.domainNamer()

	daddr, ok := addrKey(netip.MustParseAddr("192.0.2.55"))
	if !ok {
		t.Fatal("addrKey rejected an IPv4 literal")
	}

	tests := []struct {
		name     string
		domainID uint32
		want     IPEventKey
	}{
		{
			name: "no domain known",
			want: IPEventKey{Addr: netip.MustParseAddr("192.0.2.55"), Decision: runtimeevent.DecisionDeny},
		},
		{
			name:     "known domain",
			domainID: id,
			want: IPEventKey{
				Addr:     netip.MustParseAddr("192.0.2.55"),
				Decision: runtimeevent.DecisionDeny,
				Domain:   "api.example.com",
			},
		},
		{
			name:     "unnameable domain id keeps the address",
			domainID: id + 1000,
			want:     IPEventKey{Addr: netip.MustParseAddr("192.0.2.55"), Decision: runtimeevent.DecisionDeny},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := ipEventKernelKey{Daddr: daddr, Decision: uint32(runtimeevent.DecisionDeny), DomainId: tc.domainID}
			if diff := cmp.Diff(tc.want, eventKey(k, namer), cmp.Comparer(func(a, b netip.Addr) bool { return a == b })); diff != "" {
				t.Errorf("eventKey mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
