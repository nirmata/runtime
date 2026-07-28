package compiler

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// sampleEvent is a fully populated HTTP event: every fact struct is set so a
// single event exercises the whole `event` schema.
func sampleEvent() *runtimeevent.Event {
	governed := true
	return &runtimeevent.Event{
		Kind:     runtimeevent.KindHTTP,
		Time:     time.Date(2026, 7, 27, 10, 30, 0, 0, time.UTC),
		CgroupID: 4242,
		PID:      991,
		Comm:     "python3",
		Pod: runtimeevent.PodIdentity{
			UID:       "pod-uid-1",
			Namespace: "agents",
			Name:      "agent-0",
			Labels:    map[string]string{"ai.nirmata.io/workload": "true"},
			Container: "agent",
			OwnerKind: "Deployment",
			OwnerName: "agent",
		},
		Net: &runtimeevent.NetFacts{
			DestIP:   netip.MustParseAddr("52.1.2.3"),
			DestPort: 443,
			Protocol: "tcp",
			Governed: &governed,
		},
		DNS: &runtimeevent.DNSFacts{QName: "api.anthropic.com"},
		TLS: &runtimeevent.TLSFacts{
			SNI:  "api.anthropic.com",
			ALPN: []string{"h2", "http/1.1"},
			JA4:  "t13d1516h2_8daaf6152771_b186095e22b6",
		},
		HTTP: runtimeevent.NewHTTPFacts(
			"POST", "/v1/messages", "api.anthropic.com",
			map[string]string{
				"Authorization":     "Bearer sk-canary-XYZ",
				"anthropic-version": "2023-06-01",
			},
			[]byte(`{"model":"claude-opus-4","messages":[{"content":"hi"}]}`),
		),
		Exec: &runtimeevent.ExecFacts{
			Filename: "/usr/bin/npx",
			Argv:     []string{"npx", "-y", "@modelcontextprotocol/server-git"},
		},
		AI: &runtimeevent.AIFacts{
			Class:         runtimeevent.AIClassLLM,
			Provider:      "anthropic",
			Model:         "claude-opus-4",
			EndpointKind:  "messages",
			JSONRPCMethod: "tools/call",
			Transport:     "https",
			Confidence:    95,
			Evidence:      []string{"sni:api.anthropic.com", "http-path:/v1/messages"},
			Sanctioned:    true,
		},
	}
}

// newEventPredicate compiles expr in the per-event env, failing the test if it
// does not compile.
func newEventPredicate(t *testing.T, expr string) *EventPredicate {
	t.Helper()
	c := newTestCompiler(t)
	p, err := c.compileMatchExpression(expr)
	if err != nil {
		t.Fatalf("compileMatchExpression(%q) error = %v", expr, err)
	}
	return p
}

// TestNewEventEnv_RejectsIOLibraries is the point of the per-event env: a
// program that runs once per event must not be able to reach the network or the
// apiserver. http/resource/json are registered at policy-evaluation time only,
// so every one of these expressions must FAIL TO COMPILE here -- while the same
// expressions compile fine in the policy-time env (asserted below), proving the
// failure is the missing library and not a broken expression.
func TestNewEventEnv_RejectsIOLibraries(t *testing.T) {
	c := newTestCompiler(t)

	tests := []struct {
		name string
		expr string
		lib  string
	}{
		{
			name: "http.get cannot be called per event",
			expr: `http.Get("http://169.254.169.254/latest/meta-data").status == 200`,
			lib:  "http",
		},
		{
			name: "resource.get cannot be called per event",
			expr: `resource.Get("v1", "configmaps", "kyverno-runtime", "approved").metadata.name == "approved"`,
			lib:  "resource",
		},
		{
			name: "json.unmarshal cannot be called per event",
			expr: `json.Unmarshal(event.http.bodyPreview).model == "x"`,
			lib:  "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.compileMatchExpression(tt.expr)
			if err == nil {
				t.Fatalf("compileMatchExpression(%q) error = nil, want the %q library to be undeclared in the event env", tt.expr, tt.lib)
			}
			if !strings.Contains(err.Error(), tt.lib) {
				t.Errorf("compileMatchExpression(%q) error = %q, want it to name %q", tt.expr, err.Error(), tt.lib)
			}
			// The same identifier IS declared in the policy-time env.
			if _, issues := c.env.Compile(tt.lib); issues.Err() != nil {
				t.Errorf("policy-time env does not declare %q (%v); the event-env assertion above would pass for the wrong reason", tt.lib, issues.Err())
			}
			if _, issues := c.eventEnv.Compile(tt.lib); issues.Err() == nil {
				t.Errorf("event env declares %q, it must not", tt.lib)
			}
		})
	}
}

// TestCompileMatchExpression_ProposalSamples compiles the `match` predicates of
// the worked policy examples in the proposal (§2.4) and evaluates them against
// events that should and should not match.
func TestCompileMatchExpression_ProposalSamples(t *testing.T) {
	unsanctioned := sampleEvent()
	unsanctioned.AI.Provider = "openai"

	metadataOnly := &runtimeevent.Event{
		Kind: runtimeevent.KindTLS,
		TLS:  &runtimeevent.TLSFacts{SNI: "llm.example.internal"},
		Net:  &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("52.9.9.9"), DestPort: 443},
		AI: &runtimeevent.AIFacts{
			Class:      runtimeevent.AIClassLLM,
			Provider:   "unknown",
			Confidence: 40,
			Evidence:   []string{"sni"},
		},
	}

	externalA2A := &runtimeevent.Event{
		Kind: runtimeevent.KindHTTP,
		HTTP: runtimeevent.NewHTTPFacts("GET", "/.well-known/agent.json", "peer.example.com", nil, nil),
		Net:  &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("203.0.113.7"), DestPort: 80},
		AI:   &runtimeevent.AIFacts{Class: runtimeevent.AIClassA2A, Confidence: 70},
	}
	internalA2A := &runtimeevent.Event{
		Kind: runtimeevent.KindHTTP,
		HTTP: runtimeevent.NewHTTPFacts("GET", "/.well-known/agent.json", "peer.svc", nil, nil),
		Net:  &runtimeevent.NetFacts{DestIP: netip.MustParseAddr("10.42.0.9"), DestPort: 80},
		AI:   &runtimeevent.AIFacts{Class: runtimeevent.AIClassA2A, Confidence: 70},
	}

	tests := []struct {
		name  string
		expr  string
		match map[string]bool // event label -> want
		evs   map[string]*runtimeevent.Event
	}{
		{
			// Proposal §2.4 example (2): unsanctioned-llm-egress.
			name: "sample 2 unsanctioned llm egress",
			expr: `event.ai.class == "llm" && ` +
				`!(event.ai.provider in ["anthropic", "bedrock"]) && ` +
				`event.ai.confidence >= 60`,
			evs:   map[string]*runtimeevent.Event{"openai": unsanctioned, "anthropic": sampleEvent(), "low-confidence": metadataOnly},
			match: map[string]bool{"openai": true, "anthropic": false, "low-confidence": false},
		},
		{
			// Proposal §2.4 example (4): external-a2a-discovery.
			name: "sample 4 external a2a discovery",
			expr: `event.http.path.startsWith("/.well-known/agent") && ` +
				`!cidr("10.0.0.0/8").containsIP(event.net.destIP)`,
			evs:   map[string]*runtimeevent.Event{"external": externalA2A, "in-cluster": internalA2A, "not-http": sampleEvent()},
			match: map[string]bool{"external": true, "in-cluster": false, "not-http": false},
		},
		{
			// Proposal §2.4 example (5): metadata-only degraded mode. The
			// proposal writes `event.ai.evidence == "sni"`, which cannot
			// type-check against the list(string) evidence field declared by
			// its own §2.5 field table (see
			// TestCompileMatchExpression_RejectsNonBoolAndBadFields); the
			// membership form below is the same intent, well typed.
			name: "sample 5 metadata only degraded mode",
			expr: `"sni" in event.ai.evidence && ` +
				`event.ai.provider == "unknown" && ` +
				`event.net.destPort == 443`,
			evs:   map[string]*runtimeevent.Event{"sni-only": metadataOnly, "full-plaintext": sampleEvent()},
			match: map[string]bool{"sni-only": true, "full-plaintext": false},
		},
		{
			// Example (1) (ai-discovery) and (3) (mcp-allowlist) carry no
			// `match`; their class/target-only shape is compiled end to end by
			// TestCompile_ProposalAIPolicies. This predicate covers the same
			// mcp-allowlist intent expressed as a predicate, so the `ai` lib and
			// the exec facts are exercised together.
			name:  "mcp stdio server package via the ai lib",
			expr:  `event.ai.class == "mcp" || event.process.argv.exists(a, ai.isMCPServerPackage(a))`,
			evs:   map[string]*runtimeevent.Event{"npx-mcp": sampleEvent(), "no-argv": metadataOnly},
			match: map[string]bool{"npx-mcp": true, "no-argv": false},
		},
		{
			name:  "hosted provider recognised from sni by the ai lib",
			expr:  `ai.isProvider(event.tls.sni, "anthropic") && ai.isLLMPath(event.http.path)`,
			evs:   map[string]*runtimeevent.Event{"anthropic-messages": sampleEvent(), "unknown-host": metadataOnly},
			match: map[string]bool{"anthropic-messages": true, "unknown-host": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newEventPredicate(t, tt.expr)
			for label, want := range tt.match {
				ev, ok := tt.evs[label]
				if !ok {
					t.Fatalf("test bug: no event named %q", label)
				}
				got, err := p.Eval(t.Context(), ev)
				if err != nil {
					t.Fatalf("Eval(%s) error = %v", label, err)
				}
				if got != want {
					t.Errorf("Eval(%s) = %v, want %v", label, got, want)
				}
			}
		})
	}
}

// TestCompileMatchExpression_RejectsNonBoolAndBadFields pins the bool output
// assertion (the mirror of compileBehavior's list(string) assertion) and the
// fixed schema: a typo or a mistyped comparison is a policy rejection, not a
// predicate that is quietly false forever.
func TestCompileMatchExpression_RejectsNonBoolAndBadFields(t *testing.T) {
	c := newTestCompiler(t)

	tests := []struct {
		name    string
		expr    string
		wantErr string
	}{
		{
			name:    "string output type",
			expr:    `event.ai.provider`,
			wantErr: "invalid return type string for match expression",
		},
		{
			name:    "int output type",
			expr:    `event.ai.confidence`,
			wantErr: "invalid return type int for match expression",
		},
		{
			name:    "list output type (the policy-time shape)",
			expr:    `["1.2.3.4"]`,
			wantErr: "invalid return type list(string) for match expression",
		},
		{
			name:    "object output type",
			expr:    `event.ai`,
			wantErr: "invalid return type kyverno.event.ai for match expression",
		},
		{
			name:    "misspelled field",
			expr:    `event.ai.confidance >= 60`,
			wantErr: "undefined field 'confidance'",
		},
		{
			name:    "field on the wrong object",
			expr:    `event.sni == "x"`,
			wantErr: "undefined field 'sni'",
		},
		{
			name:    "list compared to scalar (proposal sample 5 as literally written)",
			expr:    `event.ai.evidence == "sni"`,
			wantErr: "no matching overload for '_==_' applied to '(list(string), string)'",
		},
		{
			name:    "policy-time variables are not reachable per event",
			expr:    `event.ai.provider in variables.approved`,
			wantErr: "undeclared reference to 'variables'",
		},
		{
			name:    "syntax error",
			expr:    `event.ai.class ==`,
			wantErr: "Syntax error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := c.compileMatchExpression(tt.expr)
			if err == nil {
				t.Fatalf("compileMatchExpression(%q) error = nil (predicate %+v), want an error", tt.expr, p)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("compileMatchExpression(%q) error = %q, want it to contain %q", tt.expr, err.Error(), tt.wantErr)
			}
		})
	}
}

// TestEventVars_EveryDeclaredFieldIsReadable walks the declared schema itself,
// so a field added to eventFields without a matching value in EventVars fails
// here instead of erroring at 10k events/s. Each field is read on an EMPTY
// event and must yield its zero value: absent facts are zero, never errors.
func TestEventVars_EveryDeclaredFieldIsReadable(t *testing.T) {
	c := newTestCompiler(t)

	for typeName, fields := range eventFields {
		prefix := strings.TrimPrefix(typeName, "kyverno.")
		for fieldName, fieldType := range fields {
			// Nested object fields are covered by their own type's entry.
			if _, nested := eventFields[fieldType.DeclaredTypeName()]; nested {
				continue
			}
			expr, ok := zeroValueExpr(prefix+"."+fieldName, fieldType)
			if !ok {
				t.Fatalf("test bug: no zero-value assertion for %s.%s of type %s", prefix, fieldName, fieldType)
			}
			t.Run(prefix+"."+fieldName, func(t *testing.T) {
				p, err := c.compileMatchExpression(expr)
				if err != nil {
					t.Fatalf("compileMatchExpression(%q) error = %v", expr, err)
				}
				got, err := p.Eval(t.Context(), &runtimeevent.Event{})
				if err != nil {
					t.Fatalf("Eval(%q) on an empty event error = %v, want the zero value", expr, err)
				}
				if !got {
					t.Errorf("Eval(%q) on an empty event = false, want the zero value to hold", expr)
				}
			})
		}
	}
}

// zeroValueExpr builds a boolean expression asserting that selector holds the
// zero value of t. It doubles as the schema's type assertion: an expression
// built for the wrong type would not compile.
func zeroValueExpr(selector string, t *types.Type) (string, bool) {
	switch {
	case t.IsExactType(types.StringType):
		return selector + ` == ""`, true
	case t.IsExactType(types.IntType):
		return selector + " == 0", true
	case t.IsExactType(types.BoolType):
		return selector + " == false", true
	case t.IsExactType(types.TimestampType):
		return selector + ` == timestamp("0001-01-01T00:00:00Z")`, true
	case t.IsExactType(stringListType):
		return selector + ".size() == 0", true
	case t.IsExactType(stringMapType):
		return selector + ".size() == 0", true
	}
	return "", false
}

// TestEventVars_PopulatedEventFieldValues asserts the actual mapping from an
// Event to each `event.*` field: the §2.5 contract, value by value.
func TestEventVars_PopulatedEventFieldValues(t *testing.T) {
	c := newTestCompiler(t)
	ev := sampleEvent()

	tests := []struct {
		name string
		expr string
	}{
		{"kind", `event.kind == "http"`},
		{"time", `event.time == timestamp("2026-07-27T10:30:00Z")`},
		{"pod.namespace", `event.pod.namespace == "agents"`},
		{"pod.name", `event.pod.name == "agent-0"`},
		{"pod.uid", `event.pod.uid == "pod-uid-1"`},
		{"pod.labels", `event.pod.labels["ai.nirmata.io/workload"] == "true"`},
		{"pod.container", `event.pod.container == "agent"`},
		{"workload.kind", `event.workload.kind == "Deployment"`},
		{"workload.name", `event.workload.name == "agent"`},
		{"process.pid", `event.process.pid == 991`},
		{"process.comm", `event.process.comm == "python3"`},
		{"process.argv", `event.process.argv == ["npx", "-y", "@modelcontextprotocol/server-git"]`},
		{"net.destIP", `event.net.destIP == "52.1.2.3"`},
		{"net.destIP is an IP literal", `ip(event.net.destIP).family() == 4`},
		{"net.destPort", `event.net.destPort == 443`},
		{"net.protocol", `event.net.protocol == "tcp"`},
		{"net.governed", `event.net.governed`},
		{"dns.qname", `event.dns.qname == "api.anthropic.com"`},
		{"tls.sni", `event.tls.sni == "api.anthropic.com"`},
		{"tls.alpn", `event.tls.alpn == ["h2", "http/1.1"]`},
		{"tls.ja4", `event.tls.ja4.startsWith("t13d")`},
		{"http.method", `event.http.method == "POST"`},
		{"http.path", `event.http.path == "/v1/messages"`},
		{"http.host", `event.http.host == "api.anthropic.com"`},
		{"http.headers keys are lowercased", `"anthropic-version" in event.http.headers`},
		{"http.bodyPreview", `event.http.bodyPreview.contains("claude-opus-4")`},
		{"ai.class", `event.ai.class == "llm"`},
		{"ai.provider", `event.ai.provider == "anthropic"`},
		{"ai.model", `event.ai.model == "claude-opus-4"`},
		{"ai.endpointKind", `event.ai.endpointKind == "messages"`},
		{"ai.jsonrpcMethod", `event.ai.jsonrpcMethod == "tools/call"`},
		{"ai.transport", `event.ai.transport == "https"`},
		{"ai.confidence", `event.ai.confidence == 95`},
		{"ai.evidence", `event.ai.evidence == ["sni:api.anthropic.com", "http-path:/v1/messages"]`},
		{"ai.sanctioned", `event.ai.sanctioned`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := c.compileMatchExpression(tt.expr)
			if err != nil {
				t.Fatalf("compileMatchExpression(%q) error = %v", tt.expr, err)
			}
			got, err := p.Eval(t.Context(), ev)
			if err != nil {
				t.Fatalf("Eval(%q) error = %v", tt.expr, err)
			}
			if !got {
				t.Errorf("Eval(%q) = false, want true", tt.expr)
			}
		})
	}
}

// TestEventVars_HTTPHeaderValuesAreRedacted pins that the only path from an
// event to a CEL program goes through the HTTPFacts accessors, so a policy that
// reads a secret header sees "REDACTED" and cannot exfiltrate the credential
// into a finding.
func TestEventVars_HTTPHeaderValuesAreRedacted(t *testing.T) {
	p := newEventPredicate(t, `event.http.headers["authorization"] == "`+runtimeevent.Redacted+`"`)

	got, err := p.Eval(t.Context(), sampleEvent())
	if err != nil {
		t.Fatalf("Eval() error = %v", err)
	}
	if !got {
		t.Error("Eval() = false, want the authorization header value to be redacted")
	}
}

// TestEventVars_AbsentFactsAreZeroNotErrors is the second half of the
// fail-closed story: a predicate written for HTTP events must be quietly false
// on a DNS event, because an error there would be counted and logged for every
// unrelated event on the node.
func TestEventVars_AbsentFactsAreZeroNotErrors(t *testing.T) {
	dnsOnly := &runtimeevent.Event{
		Kind: runtimeevent.KindDNS,
		Time: time.Date(2026, 7, 27, 10, 30, 0, 0, time.UTC),
		DNS:  &runtimeevent.DNSFacts{QName: "api.openai.com"},
	}

	tests := []struct {
		name string
		expr string
		want bool
		ev   *runtimeevent.Event
	}{
		{
			name: "http predicate on a dns event",
			expr: `event.http.path.startsWith("/v1/") && event.http.method == "POST"`,
			ev:   dnsOnly,
		},
		{
			name: "ai predicate on an unclassified event",
			expr: `event.ai.class == "llm" && event.ai.confidence >= 60`,
			ev:   dnsOnly,
		},
		{
			name: "net predicate on a dns event yields an empty destIP",
			expr: `event.net.destIP == "" && event.net.destPort == 0 && !event.net.governed`,
			ev:   dnsOnly,
			want: true,
		},
		{
			name: "list facts are empty, not null",
			expr: `event.tls.alpn.size() == 0 && event.process.argv.size() == 0 && event.ai.evidence.size() == 0`,
			ev:   dnsOnly,
			want: true,
		},
		{
			name: "map facts are empty, not null",
			expr: `event.http.headers.size() == 0 && event.pod.labels.size() == 0`,
			ev:   dnsOnly,
			want: true,
		},
		{
			name: "the dns fact that IS present still reads",
			expr: `event.dns.qname == "api.openai.com"`,
			ev:   dnsOnly,
			want: true,
		},
		{
			name: "a nil event is all zero values",
			expr: `event.kind == "" && event.pod.uid == "" && event.ai.confidence == 0`,
			ev:   nil,
			want: true,
		},
		{
			name: "facts present but empty behave like absent facts",
			expr: `event.tls.sni == "" && event.net.destIP == ""`,
			ev:   &runtimeevent.Event{Kind: runtimeevent.KindTLS, TLS: &runtimeevent.TLSFacts{}, Net: &runtimeevent.NetFacts{}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newEventPredicate(t, tt.expr)
			got, err := p.Eval(t.Context(), tt.ev)
			if err != nil {
				t.Fatalf("Eval() error = %v, want absent facts to read as zero values", err)
			}
			if got != tt.want {
				t.Errorf("Eval() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEventPredicate_MapIndexOfAbsentKeyIsAnError documents the one place where
// "absent" is an error rather than a zero value: indexing a map with a key it
// does not have is standard CEL map semantics (identical at policy time), and
// it fails CLOSED. Authors use `in` or the optional index instead, both
// asserted here so the workaround is a tested contract.
func TestEventPredicate_MapIndexOfAbsentKeyIsAnError(t *testing.T) {
	dnsOnly := &runtimeevent.Event{Kind: runtimeevent.KindDNS, DNS: &runtimeevent.DNSFacts{QName: "x"}}

	direct := newEventPredicate(t, `event.http.headers["x-api-key"] != ""`)
	got, err := direct.Eval(t.Context(), dnsOnly)
	if err == nil {
		t.Errorf("Eval() error = nil, want a no-such-key error for a direct map index")
	}
	if got {
		t.Error("Eval() = true with an error, want fail-closed false")
	}

	for _, expr := range []string{
		`"x-api-key" in event.http.headers && event.http.headers["x-api-key"] != ""`,
		`event.http.headers[?"x-api-key"].orValue("") != ""`,
	} {
		p := newEventPredicate(t, expr)
		got, err := p.Eval(t.Context(), dnsOnly)
		if err != nil {
			t.Errorf("Eval(%q) error = %v, want the guarded form to succeed", expr, err)
		}
		if got {
			t.Errorf("Eval(%q) = true, want false", expr)
		}
	}
}

// TestEventPredicate_EvalErrorFailsClosed covers the runtime-error path: a
// predicate that blows up at event time yields (false, err) plus a
// PolicyEvalErrors{stage:"predicate"} increment. It must never report a match.
func TestEventPredicate_EvalErrorFailsClosed(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	c := newTestCompiler(t)
	c.metrics = m

	// argv[3] is out of range on an event with three arguments, and index
	// errors are runtime-only: this compiles and then fails per event.
	p, err := c.compileMatchExpression(`event.process.argv[3] == "x"`)
	if err != nil {
		t.Fatalf("compileMatchExpression() error = %v", err)
	}
	p.policy = "bad-index"

	got, err := p.Eval(t.Context(), sampleEvent())
	if err == nil {
		t.Fatal("Eval() error = nil, want the runtime error surfaced")
	}
	if got {
		t.Error("Eval() = true with an error, want fail-closed false")
	}
	if !strings.Contains(err.Error(), strconv.Quote(p.Source())) {
		t.Errorf("Eval() error = %q, want it to quote the expression", err.Error())
	}
	if n := testutil.ToFloat64(m.PolicyEvalErrors.WithLabelValues("bad-index", "predicate")); n != 1 {
		t.Errorf("PolicyEvalErrors{policy:bad-index,stage:predicate} = %v, want 1", n)
	}
}

// TestEventPredicate_PanicFailsClosed covers the panic path, on both sides of
// cel-go's own recover: a hostile binding (recovered by the interpreter,
// surfaced as an eval error) and a hostile result value whose handling panics in
// THIS package (converted by utils.Guard). Neither may take the daemon down and
// neither may report a match.
func TestEventPredicate_PanicFailsClosed(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantPanic bool // errors.Is(err, utils.ErrPanic)
		wantMsg   string
	}{
		{
			name:    "panic inside a CEL binding",
			expr:    `boom()`,
			wantMsg: "deliberate panic inside a CEL binding",
		},
		{
			name:      "panic while handling the result, outside the interpreter",
			expr:      `evil()`,
			wantPanic: true,
			wantMsg:   "deliberate panic inspecting a CEL result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := metrics.New(prometheus.NewRegistry())
			p := newHostilePredicate(t, tt.expr, m)

			got, err := p.Eval(t.Context(), sampleEvent())
			if err == nil {
				t.Fatal("Eval() error = nil, want the panic converted to an error")
			}
			if got {
				t.Error("Eval() = true with an error, want fail-closed false")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Eval() error = %q, want it to carry %q", err.Error(), tt.wantMsg)
			}
			if tt.wantPanic && !errors.Is(err, utils.ErrPanic) {
				t.Errorf("Eval() error = %v, want errors.Is(err, utils.ErrPanic)", err)
			}
			if n := testutil.ToFloat64(m.PolicyEvalErrors.WithLabelValues("hostile", "predicate")); n != 1 {
				t.Errorf("PolicyEvalErrors{policy:hostile,stage:predicate} = %v, want 1", n)
			}
		})
	}
}

// hostileVal is a ref.Val declared as bool whose Type() panics. Inspecting a
// program's result happens in this package, OUTSIDE cel-go's recover, so this
// is the panic class only utils.Guard catches.
type hostileVal struct{}

func (hostileVal) ConvertToNative(reflect.Type) (any, error) { return nil, errors.New("nope") }
func (hostileVal) ConvertToType(ref.Type) ref.Val            { return types.NewErr("unsupported conversion") }
func (hostileVal) Equal(ref.Val) ref.Val                     { return types.False }
func (hostileVal) Type() ref.Type {
	panic("deliberate panic inspecting a CEL result")
}
func (hostileVal) Value() any { return nil }

// newHostilePredicate compiles expr in an event env extended with two hostile
// functions, standing in for any CEL binding reachable from user input:
//
//	boom() -- panics inside its binding, i.e. inside cel-go's interpreter;
//	evil() -- returns a bool-declared value whose inspection panics here.
func newHostilePredicate(t *testing.T, expr string, m *metrics.Metrics) *EventPredicate {
	t.Helper()
	env, err := newEventEnv(nil)
	if err != nil {
		t.Fatalf("newEventEnv() error = %v", err)
	}
	env, err = env.Extend(
		cel.Function("boom",
			cel.Overload("boom_bool", nil, types.BoolType,
				cel.FunctionBinding(func(...ref.Val) ref.Val {
					panic("deliberate panic inside a CEL binding")
				}),
			),
		),
		cel.Function("evil",
			cel.Overload("evil_bool", nil, types.BoolType,
				cel.FunctionBinding(func(...ref.Val) ref.Val { return hostileVal{} }),
			),
		),
	)
	if err != nil {
		t.Fatalf("Extend() error = %v", err)
	}
	ast, issues := env.Compile(expr)
	if err := issues.Err(); err != nil {
		t.Fatalf("Compile(%q) error = %v", expr, err)
	}
	prog, err := env.Program(ast)
	if err != nil {
		t.Fatalf("Program() error = %v", err)
	}
	return &EventPredicate{prog: prog, src: expr, policy: "hostile", metrics: m}
}

// TestEventPredicate_NilPredicateMatchesNothing pins the unset case: callers
// check `rule.Match == nil` themselves, and a nil predicate reports false
// without inventing an error to count.
func TestEventPredicate_NilPredicateMatchesNothing(t *testing.T) {
	var p *EventPredicate
	got, err := p.Eval(t.Context(), sampleEvent())
	if err != nil {
		t.Errorf("Eval() on a nil predicate error = %v, want nil", err)
	}
	if got {
		t.Error("Eval() on a nil predicate = true, want false")
	}
	if src := p.Source(); src != "" {
		t.Errorf("Source() on a nil predicate = %q, want empty", src)
	}
}

// TestEventPredicate_EvalIsRepeatableAndDoesNotMutateTheEvent pins that the
// activation is rebuilt per call (lazy.MapValue caches resolved fields, so a
// shared activation would leak one event's facts into the next).
func TestEventPredicate_EvalIsRepeatableAndDoesNotMutateTheEvent(t *testing.T) {
	p := newEventPredicate(t, `event.ai.provider == "anthropic"`)

	first := sampleEvent()
	second := sampleEvent()
	second.AI.Provider = "openai"

	for i, tc := range []struct {
		ev   *runtimeevent.Event
		want bool
	}{{first, true}, {second, false}, {first, true}, {second, false}} {
		got, err := p.Eval(t.Context(), tc.ev)
		if err != nil {
			t.Fatalf("Eval() #%d error = %v", i, err)
		}
		if got != tc.want {
			t.Errorf("Eval() #%d = %v, want %v", i, got, tc.want)
		}
	}

	// Compare through JSON: Event embeds netip.Addr and an unexported-field
	// HTTPFacts, and the marshalled form is exactly the state that reaches a
	// report, so it is the shape worth pinning as unmutated.
	if diff := cmp.Diff(mustMarshal(t, sampleEvent()), mustMarshal(t, first)); diff != "" {
		t.Errorf("Eval() mutated the event (-want +got):\n%s", diff)
	}
}

func mustMarshal(t *testing.T, ev *runtimeevent.Event) string {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	}
	return string(b)
}

// TestEventVars_ExposesOnlyTheEventVariable pins the activation shape: `event`
// and nothing else, so no accidental second variable becomes policy surface.
func TestEventVars_ExposesOnlyTheEventVariable(t *testing.T) {
	vars := EventVars(sampleEvent())
	if len(vars) != 1 {
		t.Fatalf("EventVars() has %d keys (%v), want exactly 1", len(vars), keysOf(vars))
	}
	if _, ok := vars[eventKey]; !ok {
		t.Errorf("EventVars() keys = %v, want %q", keysOf(vars), eventKey)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
