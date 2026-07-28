package compiler

import (
	"context"
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/detect/ai"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"k8s.io/apiserver/pkg/cel/lazy"
)

// eventKey is the name of the per-event CEL variable.
const eventKey = "event"

// predicateStage is the metrics stage label for per-event predicate failures.
const predicateStage = "predicate"

// newEventEnv builds the per-event CEL environment: the base env, the `ai`
// catalog lib, and the `event` variable.
//
// HARD CONSTRAINT: this env deliberately omits the http, resource and json
// libs that newEnv registers. Those are fine at policy-evaluation time (once
// per evaluationInterval) and catastrophic per event: a `match` expression runs
// on the event path, so it must not be able to perform a network call, an
// apiserver read, or unbounded JSON parsing. Nothing in this function may add
// an I/O-capable library, and TestNewEventEnv_RejectsIOLibraries pins that.
func newEventEnv(cat *ai.Catalog) (*cel.Env, error) {
	base, err := newBaseEnv()
	if err != nil {
		return nil, err
	}
	withLib, err := base.Extend(ai.Lib(cat))
	if err != nil {
		return nil, err
	}
	return withLib.Extend(
		cel.Variable(eventKey, EventType),
		cel.CustomTypeProvider(newEventProvider(withLib.CELTypeProvider())),
	)
}

// EventPredicate is a compiled boolean CEL expression over a single runtime
// event: a behavior's `match`, compiled once at policy admission and evaluated
// per detected event.
type EventPredicate struct {
	prog cel.Program
	src  string

	// policy and metrics label the PolicyEvalErrors counter; both are optional
	// so a predicate compiled in a test is still usable.
	policy  string
	metrics *metrics.Metrics
}

// Source returns the expression the predicate was compiled from, for logs and
// findings. It never contains event data.
func (p *EventPredicate) Source() string {
	if p == nil {
		return ""
	}
	return p.src
}

// Eval evaluates the predicate against ev.
//
// It FAILS CLOSED: an evaluation error, a non-bool result, or a panic raised
// inside a CEL binding yields (false, err) and increments
// PolicyEvalErrors{stage:"predicate"}. A broken predicate must never manifest
// as a match, because a match becomes a reported violation against a workload.
//
// A nil predicate (or one with no compiled program) reports false without an
// error: "no predicate" means "the caller decides", and every caller checks
// `rule.Match == nil` before calling.
func (p *EventPredicate) Eval(ctx context.Context, ev *runtimeevent.Event) (bool, error) {
	if p == nil || p.prog == nil {
		return false, nil
	}

	var matched bool
	err := utils.Guard(fmt.Sprintf("evaluating match expression of RuntimePolicy %q", p.policy), func() error {
		out, _, err := p.prog.ContextEval(ctx, EventVars(ev))
		if err != nil {
			return fmt.Errorf("evaluating match expression %q: %w", p.src, err)
		}
		b, ok := out.(types.Bool)
		if !ok {
			return fmt.Errorf("match expression %q returned %s, want bool", p.src, out.Type().TypeName())
		}
		matched = bool(b)
		return nil
	})
	if err != nil {
		p.countError()
		return false, err
	}
	return matched, nil
}

func (p *EventPredicate) countError() {
	if p.metrics == nil {
		return
	}
	p.metrics.PolicyEvalErrors.WithLabelValues(p.policy, predicateStage).Inc()
}

// EventVars builds the CEL activation for ev. It is exported so tests (and the
// detect engine's own tests) can evaluate expressions against a raw event.
//
// Every field of the schema is always present: absent facts resolve to zero
// values ("" / 0 / false / empty), never to an error. A predicate over
// event.http on a DNS event is therefore false, not a failure — which matters
// because a failure would be counted and logged for every unrelated event.
func EventVars(ev *runtimeevent.Event) map[string]any {
	return map[string]any{eventKey: eventValue(ev)}
}

func eventValue(ev *runtimeevent.Event) ref.Val {
	if ev == nil {
		ev = &runtimeevent.Event{}
	}
	m := lazy.NewMapValue(EventType)
	set(m, fieldKind, types.String(string(ev.Kind)))
	set(m, fieldTime, types.Timestamp{Time: ev.Time.UTC()})
	set(m, fieldPod, podValue(ev))
	set(m, fieldWorkload, workloadValue(ev))
	set(m, fieldProcess, processValue(ev))
	set(m, fieldNet, netValue(ev))
	set(m, fieldDNS, dnsValue(ev))
	set(m, fieldTLS, tlsValue(ev))
	set(m, fieldHTTP, httpValue(ev))
	set(m, fieldAI, aiValue(ev))
	return m
}

func podValue(ev *runtimeevent.Event) ref.Val {
	m := lazy.NewMapValue(eventPodType)
	set(m, fieldNamespace, types.String(ev.Pod.Namespace))
	set(m, fieldName, types.String(ev.Pod.Name))
	set(m, fieldUID, types.String(ev.Pod.UID))
	set(m, fieldLabels, stringMap(ev.Pod.Labels))
	set(m, fieldContainer, types.String(ev.Pod.Container))
	return m
}

func workloadValue(ev *runtimeevent.Event) ref.Val {
	m := lazy.NewMapValue(eventWorkloadType)
	set(m, fieldKind, types.String(ev.Pod.OwnerKind))
	set(m, fieldName, types.String(ev.Pod.OwnerName))
	return m
}

func processValue(ev *runtimeevent.Event) ref.Val {
	var argv []string
	if ev.Exec != nil {
		argv = ev.Exec.Argv
	}
	m := lazy.NewMapValue(eventProcessType)
	set(m, fieldPID, types.Int(ev.PID))
	set(m, fieldComm, types.String(ev.Comm))
	set(m, fieldArgv, stringList(argv))
	return m
}

func netValue(ev *runtimeevent.Event) ref.Val {
	var (
		destIP   string
		destPort uint16
		protocol string
		governed bool
	)
	if ev.Net != nil {
		// An invalid netip.Addr stringifies to "invalid IP"; expose "" instead
		// so `cidr(...).containsIP(event.net.destIP)` fails cleanly on a
		// non-net event rather than matching a bogus literal.
		if ev.Net.DestIP.IsValid() {
			destIP = ev.Net.DestIP.String()
		}
		destPort = ev.Net.DestPort
		protocol = ev.Net.Protocol
		// Governed is a tri-state (nil = unknown); CEL sees unknown as false.
		governed = ev.Net.Governed != nil && *ev.Net.Governed
	}
	m := lazy.NewMapValue(eventNetType)
	set(m, fieldDestIP, types.String(destIP))
	set(m, fieldDestPort, types.Int(destPort))
	set(m, fieldProtocol, types.String(protocol))
	set(m, fieldGoverned, types.Bool(governed))
	return m
}

func dnsValue(ev *runtimeevent.Event) ref.Val {
	var qname string
	if ev.DNS != nil {
		qname = ev.DNS.QName
	}
	m := lazy.NewMapValue(eventDNSType)
	set(m, fieldQName, types.String(qname))
	return m
}

func tlsValue(ev *runtimeevent.Event) ref.Val {
	var (
		sni  string
		alpn []string
		ja4  string
	)
	if ev.TLS != nil {
		sni, alpn, ja4 = ev.TLS.SNI, ev.TLS.ALPN, ev.TLS.JA4
	}
	m := lazy.NewMapValue(eventTLSType)
	set(m, fieldSNI, types.String(sni))
	set(m, fieldALPN, stringList(alpn))
	set(m, fieldJA4, types.String(ja4))
	return m
}

// httpValue reads HTTP facts through their accessors only. Those are the
// redaction chokepoint (see runtimeevent.NewHTTPFacts): a policy author can
// read event.http.headers["authorization"], and what they get is "REDACTED".
func httpValue(ev *runtimeevent.Event) ref.Val {
	m := lazy.NewMapValue(eventHTTPType)
	set(m, fieldMethod, types.String(ev.HTTP.Method()))
	set(m, fieldPath, types.String(ev.HTTP.Path()))
	set(m, fieldHost, types.String(ev.HTTP.Host()))
	set(m, fieldHeaders, stringMap(ev.HTTP.Headers()))
	set(m, fieldBodyPreview, types.String(ev.HTTP.BodyPreview()))
	return m
}

func aiValue(ev *runtimeevent.Event) ref.Val {
	facts := ev.AI
	if facts == nil {
		facts = &runtimeevent.AIFacts{}
	}
	m := lazy.NewMapValue(eventAIType)
	set(m, fieldClass, types.String(string(facts.Class)))
	set(m, fieldProvider, types.String(facts.Provider))
	set(m, fieldModel, types.String(facts.Model))
	set(m, fieldEndpointKind, types.String(facts.EndpointKind))
	set(m, fieldJSONRPCMethod, types.String(facts.JSONRPCMethod))
	set(m, fieldTransport, types.String(facts.Transport))
	set(m, fieldConfidence, types.Int(facts.Confidence))
	set(m, fieldEvidence, stringList(facts.Evidence))
	set(m, fieldSanctioned, types.Bool(facts.Sanctioned))
	return m
}

// set appends an already-computed value to a lazy map. The event schema is
// small and cheap to materialize, so nothing here defers real work; the lazy
// map is used because it is the repo's idiom for object-typed CEL variables
// (see policy.go's variables) and because it resolves declared fields without
// reflection.
func set(m *lazy.MapValue, name string, v ref.Val) {
	m.Append(name, func(*lazy.MapValue) ref.Val { return v })
}

// stringList converts to a CEL list(string), mapping nil to an empty list.
func stringList(in []string) ref.Val {
	if in == nil {
		in = []string{}
	}
	return types.NewStringList(types.DefaultTypeAdapter, in)
}

// stringMap converts to a CEL map(string,string), mapping nil to an empty map.
func stringMap(in map[string]string) ref.Val {
	if in == nil {
		in = map[string]string{}
	}
	return types.NewStringStringMap(types.DefaultTypeAdapter, in)
}
