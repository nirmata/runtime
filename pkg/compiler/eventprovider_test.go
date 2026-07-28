package compiler

import (
	"sort"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/go-cmp/cmp"
)

// TestEventSchema_MatchesTheDocumentedFieldTable is the schema's golden test.
// The `event` variable is a published contract (proposal §2.5, DESIGN §3.4) that
// policies are written against, so adding, renaming or retyping a field must be
// a deliberate edit here -- and to the docs -- rather than a silent break of
// every RuntimePolicy in the field.
func TestEventSchema_MatchesTheDocumentedFieldTable(t *testing.T) {
	want := map[string]map[string]string{
		"kyverno.event": {
			"kind":     "string",
			"time":     "google.protobuf.Timestamp",
			"pod":      "kyverno.event.pod",
			"workload": "kyverno.event.workload",
			"process":  "kyverno.event.process",
			"net":      "kyverno.event.net",
			"dns":      "kyverno.event.dns",
			"tls":      "kyverno.event.tls",
			"http":     "kyverno.event.http",
			"ai":       "kyverno.event.ai",
		},
		"kyverno.event.pod": {
			"namespace": "string",
			"name":      "string",
			"uid":       "string",
			"labels":    "map(string, string)",
			"container": "string",
		},
		"kyverno.event.workload": {
			"kind": "string",
			"name": "string",
		},
		"kyverno.event.process": {
			"pid":  "int",
			"comm": "string",
			"argv": "list(string)",
		},
		"kyverno.event.net": {
			"destIP":   "string",
			"destPort": "int",
			"protocol": "string",
			"governed": "bool",
		},
		"kyverno.event.dns": {
			"qname": "string",
		},
		"kyverno.event.tls": {
			"sni":  "string",
			"alpn": "list(string)",
			"ja4":  "string",
		},
		"kyverno.event.http": {
			"method":      "string",
			"path":        "string",
			"host":        "string",
			"headers":     "map(string, string)",
			"bodyPreview": "string",
		},
		"kyverno.event.ai": {
			"class":         "string",
			"provider":      "string",
			"model":         "string",
			"endpointKind":  "string",
			"jsonrpcMethod": "string",
			"transport":     "string",
			"confidence":    "int",
			"evidence":      "list(string)",
			"sanctioned":    "bool",
		},
	}

	got := make(map[string]map[string]string, len(eventFields))
	for typeName, fields := range eventFields {
		out := make(map[string]string, len(fields))
		for name, t := range fields {
			out[name] = t.String()
		}
		got[typeName] = out
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("event schema drifted from the documented field table (-want +got):\n%s", diff)
	}
}

// TestEventProvider_ResolvesEventTypesAndRejectsUnknownFields pins the provider
// contract: known types resolve, an unknown field on a known type is a
// compile-time rejection (never a fallthrough to the inner provider, which
// would report a confusing type), and everything else delegates.
func TestEventProvider_ResolvesEventTypesAndRejectsUnknownFields(t *testing.T) {
	inner := &recordingProvider{}
	p := newEventProvider(inner)

	for typeName := range eventFields {
		if _, ok := p.FindStructType(typeName); !ok {
			t.Errorf("FindStructType(%q) not found", typeName)
		}
		names, ok := p.FindStructFieldNames(typeName)
		if !ok {
			t.Fatalf("FindStructFieldNames(%q) not found", typeName)
		}
		wantNames := make([]string, 0, len(eventFields[typeName]))
		for name := range eventFields[typeName] {
			wantNames = append(wantNames, name)
		}
		sort.Strings(wantNames)
		if diff := cmp.Diff(wantNames, names); diff != "" {
			t.Errorf("FindStructFieldNames(%q) (-want +got):\n%s", typeName, diff)
		}
		for name, want := range eventFields[typeName] {
			ft, ok := p.FindStructFieldType(typeName, name)
			if !ok {
				t.Errorf("FindStructFieldType(%q, %q) not found", typeName, name)
				continue
			}
			if !ft.Type.IsExactType(want) {
				t.Errorf("FindStructFieldType(%q, %q) = %s, want %s", typeName, name, ft.Type, want)
			}
		}
		if _, ok := p.FindStructFieldType(typeName, "nopeNotAField"); ok {
			t.Errorf("FindStructFieldType(%q, %q) found, want rejected", typeName, "nopeNotAField")
		}
	}

	if inner.calls != 0 {
		t.Errorf("inner provider was consulted %d times for event types, want 0", inner.calls)
	}
}

// TestEventProvider_DelegatesEverythingElse pins that the provider is additive:
// the base registry still answers for every non-event type, so the standard
// library types keep working inside a match expression.
func TestEventProvider_DelegatesEverythingElse(t *testing.T) {
	inner := &recordingProvider{}
	p := newEventProvider(inner)

	if _, ok := p.FindStructType("some.other.Type"); ok {
		t.Error("FindStructType(some.other.Type) found, want the inner provider's answer (false)")
	}
	if _, ok := p.FindStructFieldNames("some.other.Type"); ok {
		t.Error("FindStructFieldNames(some.other.Type) found, want the inner provider's answer (false)")
	}
	if _, ok := p.FindStructFieldType("some.other.Type", "x"); ok {
		t.Error("FindStructFieldType(some.other.Type, x) found, want the inner provider's answer (false)")
	}
	if _, ok := p.FindIdent("whatever"); ok {
		t.Error("FindIdent(whatever) found, want the inner provider's answer (false)")
	}
	p.EnumValue("some.Enum")
	p.NewValue("some.other.Type", nil)

	want := []string{
		"EnumValue(some.Enum)",
		"FindIdent(whatever)",
		"FindStructFieldNames(some.other.Type)",
		"FindStructFieldType(some.other.Type,x)",
		"FindStructType(some.other.Type)",
		"NewValue(some.other.Type)",
	}
	got := append([]string(nil), inner.seen...)
	sort.Strings(got)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("delegated calls (-want +got):\n%s", diff)
	}
}

// recordingProvider is a types.Provider that records what it was asked and
// answers "not found" to everything.
type recordingProvider struct {
	calls int
	seen  []string
}

func (r *recordingProvider) record(call string) {
	r.calls++
	r.seen = append(r.seen, call)
}

func (r *recordingProvider) EnumValue(enumName string) ref.Val {
	r.record("EnumValue(" + enumName + ")")
	return types.NewErr("unknown enum value %q", enumName)
}

func (r *recordingProvider) FindIdent(identName string) (ref.Val, bool) {
	r.record("FindIdent(" + identName + ")")
	return nil, false
}

func (r *recordingProvider) FindStructType(structType string) (*types.Type, bool) {
	r.record("FindStructType(" + structType + ")")
	return nil, false
}

func (r *recordingProvider) FindStructFieldNames(structType string) ([]string, bool) {
	r.record("FindStructFieldNames(" + structType + ")")
	return nil, false
}

func (r *recordingProvider) FindStructFieldType(structType, fieldName string) (*types.FieldType, bool) {
	r.record("FindStructFieldType(" + structType + "," + fieldName + ")")
	return nil, false
}

func (r *recordingProvider) NewValue(structType string, _ map[string]ref.Val) ref.Val {
	r.record("NewValue(" + structType + ")")
	return types.NewErr("unknown type %q", structType)
}
