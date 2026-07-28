package compiler

import (
	"sort"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// The `event` variable's static type surface. Unlike variablesProvider (whose
// fields are discovered from the policy's own variables), the event schema is
// FIXED: it is a contract with policy authors, so it is declared once here and
// type-checked at compile time. A typo in `event.ai.confidance` is a policy
// rejection, not a silently-false predicate at 10k events/s.
var (
	// EventType is the type of the `event` variable available to a behavior's
	// `match` expression.
	EventType         = types.NewObjectType("kyverno.event")
	eventPodType      = types.NewObjectType("kyverno.event.pod")
	eventWorkloadType = types.NewObjectType("kyverno.event.workload")
	eventProcessType  = types.NewObjectType("kyverno.event.process")
	eventNetType      = types.NewObjectType("kyverno.event.net")
	eventDNSType      = types.NewObjectType("kyverno.event.dns")
	eventTLSType      = types.NewObjectType("kyverno.event.tls")
	eventHTTPType     = types.NewObjectType("kyverno.event.http")
	eventAIType       = types.NewObjectType("kyverno.event.ai")
)

// Field names of the event object types. They are declared as constants because
// the provider (compile time) and the activation builder (event time) must
// agree exactly: a field declared here but never appended to the lazy map would
// resolve to "no such key" at runtime instead of a zero value.
const (
	fieldKind          = "kind"
	fieldTime          = "time"
	fieldPod           = "pod"
	fieldWorkload      = "workload"
	fieldProcess       = "process"
	fieldNet           = "net"
	fieldDNS           = "dns"
	fieldTLS           = "tls"
	fieldHTTP          = "http"
	fieldAI            = "ai"
	fieldNamespace     = "namespace"
	fieldName          = "name"
	fieldUID           = "uid"
	fieldLabels        = "labels"
	fieldContainer     = "container"
	fieldPID           = "pid"
	fieldComm          = "comm"
	fieldArgv          = "argv"
	fieldDestIP        = "destIP"
	fieldDestPort      = "destPort"
	fieldProtocol      = "protocol"
	fieldGoverned      = "governed"
	fieldQName         = "qname"
	fieldSNI           = "sni"
	fieldALPN          = "alpn"
	fieldJA4           = "ja4"
	fieldMethod        = "method"
	fieldPath          = "path"
	fieldHost          = "host"
	fieldHeaders       = "headers"
	fieldBodyPreview   = "bodyPreview"
	fieldClass         = "class"
	fieldProvider      = "provider"
	fieldModel         = "model"
	fieldEndpointKind  = "endpointKind"
	fieldJSONRPCMethod = "jsonrpcMethod"
	fieldTransport     = "transport"
	fieldConfidence    = "confidence"
	fieldEvidence      = "evidence"
	fieldSanctioned    = "sanctioned"
)

var (
	stringMapType  = types.NewMapType(types.StringType, types.StringType)
	stringListType = types.NewListType(types.StringType)
)

// eventFields is the whole event schema, keyed by declared type name.
var eventFields = map[string]map[string]*types.Type{
	EventType.DeclaredTypeName(): {
		fieldKind:     types.StringType,
		fieldTime:     types.TimestampType,
		fieldPod:      eventPodType,
		fieldWorkload: eventWorkloadType,
		fieldProcess:  eventProcessType,
		fieldNet:      eventNetType,
		fieldDNS:      eventDNSType,
		fieldTLS:      eventTLSType,
		fieldHTTP:     eventHTTPType,
		fieldAI:       eventAIType,
	},
	eventPodType.DeclaredTypeName(): {
		fieldNamespace: types.StringType,
		fieldName:      types.StringType,
		fieldUID:       types.StringType,
		fieldLabels:    stringMapType,
		fieldContainer: types.StringType,
	},
	eventWorkloadType.DeclaredTypeName(): {
		fieldKind: types.StringType,
		fieldName: types.StringType,
	},
	eventProcessType.DeclaredTypeName(): {
		fieldPID:  types.IntType,
		fieldComm: types.StringType,
		fieldArgv: stringListType,
	},
	eventNetType.DeclaredTypeName(): {
		fieldDestIP:   types.StringType,
		fieldDestPort: types.IntType,
		fieldProtocol: types.StringType,
		fieldGoverned: types.BoolType,
	},
	eventDNSType.DeclaredTypeName(): {
		fieldQName: types.StringType,
	},
	eventTLSType.DeclaredTypeName(): {
		fieldSNI:  types.StringType,
		fieldALPN: stringListType,
		fieldJA4:  types.StringType,
	},
	eventHTTPType.DeclaredTypeName(): {
		fieldMethod:      types.StringType,
		fieldPath:        types.StringType,
		fieldHost:        types.StringType,
		fieldHeaders:     stringMapType,
		fieldBodyPreview: types.StringType,
	},
	eventAIType.DeclaredTypeName(): {
		fieldClass:         types.StringType,
		fieldProvider:      types.StringType,
		fieldModel:         types.StringType,
		fieldEndpointKind:  types.StringType,
		fieldJSONRPCMethod: types.StringType,
		fieldTransport:     types.StringType,
		fieldConfidence:    types.IntType,
		fieldEvidence:      stringListType,
		fieldSanctioned:    types.BoolType,
	},
}

// eventTypeTypes and eventFieldNames are derived once from eventFields.
var (
	eventTypeTypes  = map[string]*types.Type{}
	eventFieldNames = map[string][]string{}
)

func init() {
	for _, t := range []*types.Type{
		EventType, eventPodType, eventWorkloadType, eventProcessType,
		eventNetType, eventDNSType, eventTLSType, eventHTTPType, eventAIType,
	} {
		name := t.DeclaredTypeName()
		eventTypeTypes[name] = types.NewTypeTypeWithParam(t)
		fields := eventFields[name]
		names := make([]string, 0, len(fields))
		for f := range fields {
			names = append(names, f)
		}
		sort.Strings(names)
		eventFieldNames[name] = names
	}
}

// eventProvider answers the CEL type checker's questions about the `event`
// object types, delegating everything else to the base provider. It mirrors
// variablesProvider, minus registerField: the schema is fixed, not accumulated.
type eventProvider struct {
	inner types.Provider
}

func newEventProvider(inner types.Provider) *eventProvider {
	return &eventProvider{inner: inner}
}

func (p *eventProvider) EnumValue(enumName string) ref.Val {
	return p.inner.EnumValue(enumName)
}

func (p *eventProvider) FindIdent(identName string) (ref.Val, bool) {
	return p.inner.FindIdent(identName)
}

func (p *eventProvider) FindStructType(structType string) (*types.Type, bool) {
	if t, ok := eventTypeTypes[structType]; ok {
		return t, true
	}
	return p.inner.FindStructType(structType)
}

func (p *eventProvider) FindStructFieldNames(structType string) ([]string, bool) {
	if names, ok := eventFieldNames[structType]; ok {
		return names, true
	}
	return p.inner.FindStructFieldNames(structType)
}

func (p *eventProvider) FindStructFieldType(structType, fieldName string) (*types.FieldType, bool) {
	if fields, ok := eventFields[structType]; ok {
		t, ok := fields[fieldName]
		if !ok {
			// An unknown field on a known event type is a policy authoring
			// error and must fail compilation, not fall through to the inner
			// provider (which would report a confusing type name).
			return nil, false
		}
		return &types.FieldType{Type: t}, true
	}
	return p.inner.FindStructFieldType(structType, fieldName)
}

func (p *eventProvider) NewValue(structType string, fields map[string]ref.Val) ref.Val {
	return p.inner.NewValue(structType, fields)
}
