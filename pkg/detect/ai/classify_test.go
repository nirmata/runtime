package ai

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// testTime is the fixed timestamp every fixture event carries: the classifier
// has no clock of its own, and nothing in its output may depend on time.
var testTime = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func dnsEvent(qname string) *runtimeevent.Event {
	return &runtimeevent.Event{
		Kind: runtimeevent.KindDNS,
		Time: testTime,
		DNS:  &runtimeevent.DNSFacts{QName: qname, QType: 1},
	}
}

func tlsEvent(sni string, alpn ...string) *runtimeevent.Event {
	return &runtimeevent.Event{
		Kind: runtimeevent.KindTLS,
		Time: testTime,
		TLS:  &runtimeevent.TLSFacts{SNI: sni, ALPN: alpn},
	}
}

func netEvent(ip string, port uint16) *runtimeevent.Event {
	return &runtimeevent.Event{
		Kind: runtimeevent.KindNet,
		Time: testTime,
		Net: &runtimeevent.NetFacts{
			DestIP:   netip.MustParseAddr(ip),
			DestPort: port,
			Protocol: "tcp",
		},
	}
}

func httpEvent(method, path, host string, headers map[string]string, body string) *runtimeevent.Event {
	return &runtimeevent.Event{
		Kind: runtimeevent.KindHTTP,
		Time: testTime,
		HTTP: runtimeevent.NewHTTPFacts(method, path, host, headers, []byte(body)),
	}
}

// withNet attaches flow facts to an event, as a source that observed both the
// connection and its payload would.
func withNet(ev *runtimeevent.Event, ip string, port uint16) *runtimeevent.Event {
	ev.Net = &runtimeevent.NetFacts{
		DestIP:   netip.MustParseAddr(ip),
		DestPort: port,
		Protocol: "tcp",
	}
	return ev
}

func execEvent(filename string, argv ...string) *runtimeevent.Event {
	return &runtimeevent.Event{
		Kind: runtimeevent.KindExec,
		Time: testTime,
		Comm: pathBase(filename),
		Exec: &runtimeevent.ExecFacts{Filename: filename, Argv: argv, PPID: 42},
	}
}

func openEvent(path string) *runtimeevent.Event {
	return &runtimeevent.Event{
		Kind: runtimeevent.KindOpen,
		Time: testTime,
		Open: &runtimeevent.OpenFacts{Path: path},
	}
}

func TestClassifyNilInputs(t *testing.T) {
	cls := NewClassifier(nil) // nil catalog must fall back to the default
	if cls.Catalog() == nil {
		t.Fatal("NewClassifier(nil) left the catalog nil")
	}
	if got := cls.Classify(nil); got != nil {
		t.Errorf("Classify(nil) = %+v, want nil", got)
	}
	if ok := cls.Process(nil); !ok {
		t.Error("Process(nil) = false, want true")
	}
	// A default-constructed classifier (no catalog stored) must not panic.
	var zero Classifier
	if got := zero.Classify(dnsEvent("api.openai.com")); got != nil {
		t.Errorf("zero-value Classify() = %+v, want nil", got)
	}
}

func TestClassifyNonAIEventsReturnNil(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())

	tests := []struct {
		name string
		ev   *runtimeevent.Event
	}{
		{"dns for an unrelated host", dnsEvent("www.example.com")},
		{"dns for the cluster api", dnsEvent("kubernetes.default.svc.cluster.local")},
		{"sni for an unrelated host", tlsEvent("github.com", "h2")},
		{"flow to https", netEvent("140.82.121.4", 443)},
		{"flow to postgres", netEvent("10.42.0.7", 5432)},
		{"plain web request", httpEvent("GET", "/", "www.example.com", nil, "")},
		{"json api request", httpEvent("POST", "/api/v1/orders", "shop.internal",
			map[string]string{"content-type": "application/json"}, `{"sku":"x","qty":2}`)},
		{"prometheus scrape", httpEvent("GET", "/metrics", "10.42.0.3:9090", nil, "")},
		{"exec of a shell", execEvent("/bin/sh", "sh", "-c", "echo hi")},
		{"exec of a build tool", execEvent("/usr/local/bin/npm", "npm", "run", "build")},
		{"open of an unrelated config", openEvent("/etc/nginx/nginx.conf")},
		{"open of a json config outside a client dir", openEvent("/etc/mcp.json")},
		{"unknown kind", &runtimeevent.Event{Kind: runtimeevent.Kind("weird"), Time: testTime}},
		{"empty event", &runtimeevent.Event{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cls.Classify(tc.ev); got != nil {
				t.Errorf("Classify() = %+v, want nil", got)
			}
		})
	}
}

// TestClassifyClassPrecedence pins the tie-break: MCP and A2A are the more
// specific protocols, so an event carrying both an MCP signature and a generic
// LLM host match is reported as MCP, and the higher-confidence class always
// wins outright.
func TestClassifyClassPrecedence(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())

	tests := []struct {
		name       string
		ev         *runtimeevent.Event
		wantClass  runtimeevent.AIClass
		wantConf   int
		wantMethod string
	}{
		{
			name: "mcp session header beats an llm host match",
			ev: httpEvent("POST", "/mcp", "api.openai.com", map[string]string{
				"mcp-session-id": "abc",
				"content-type":   "application/json",
			}, ""),
			wantClass: runtimeevent.AIClassMCP,
			wantConf:  99,
		},
		{
			name:      "a2a well known path beats an llm host match",
			ev:        httpEvent("GET", "/.well-known/agent.json", "api.openai.com", nil, ""),
			wantClass: runtimeevent.AIClassA2A,
			// The agent-card path alone (95) outranks a bare provider host
			// match (70): the same host can serve both.
			wantConf: ScoreA2AWellKnown,
		},
		{
			name: "a fully corroborated llm request beats a weak mcp path",
			ev: httpEvent("POST", "/v1/messages", "api.anthropic.com", map[string]string{
				"anthropic-version": "2023-06-01",
			}, `{"model":"claude-sonnet-4-5","messages":[]}`),
			wantClass: runtimeevent.AIClassLLM,
			wantConf:  99,
		},
		{
			name: "streamed completions are llm, not mcp",
			ev: httpEvent("POST", "/v1/chat/completions", "api.openai.com", map[string]string{
				"accept":       "application/json, text/event-stream",
				"content-type": "application/json",
			}, `{"model":"gpt-4o","messages":[],"stream":true}`),
			wantClass: runtimeevent.AIClassLLM,
			wantConf:  99,
		},
		{
			name: "an mcp jsonrpc call to an ollama host is still mcp",
			ev: httpEvent("POST", "/mcp", "ollama:11434", map[string]string{
				"content-type": "application/json",
			}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`),
			wantClass:  runtimeevent.AIClassMCP,
			wantConf:   99,
			wantMethod: "tools/list",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cls.Classify(tc.ev)
			if got == nil {
				t.Fatal("Classify() = nil, want facts")
			}
			if got.Class != tc.wantClass {
				t.Errorf("Class = %q, want %q (facts: %+v)", got.Class, tc.wantClass, got)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("Confidence = %d, want %d", got.Confidence, tc.wantConf)
			}
			if got.JSONRPCMethod != tc.wantMethod {
				t.Errorf("JSONRPCMethod = %q, want %q", got.JSONRPCMethod, tc.wantMethod)
			}
		})
	}
}

func TestClassifyIsPure(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())
	ev := httpEvent("POST", "/v1/messages", "api.anthropic.com", map[string]string{
		"anthropic-version": "2023-06-01",
	}, `{"model":"claude-sonnet-4-5","messages":[]}`)
	before, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshalling event: %v", err)
	}

	first := cls.Classify(ev)
	second := cls.Classify(ev)

	after, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshalling event: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("Classify mutated the event:\nbefore: %s\nafter:  %s", before, after)
	}
	if diff := cmp.Diff(first, second); diff != "" {
		t.Errorf("Classify is not deterministic (-first +second):\n%s", diff)
	}
	if first == second {
		t.Error("Classify returned the same pointer twice: callers could alias shared facts")
	}
	if ev.AI != nil {
		t.Error("Classify set ev.AI; only the Process stage may write to the event")
	}
}

// TestClassifyEvidenceIsStableAcrossRuns guards against Go's randomized map
// iteration leaking into evidence order, which golden-based tests depend on.
func TestClassifyEvidenceIsStableAcrossRuns(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())
	headers := map[string]string{
		"anthropic-version":   "2023-06-01",
		"openai-organization": "org-acme",
		"x-goog-api-key":      "k",
		"content-type":        "application/json",
		"accept":              "text/event-stream",
		"user-agent":          "anthropic-python/0.39.0",
	}
	want := cls.Classify(httpEvent("POST", "/v1/messages", "api.anthropic.com", headers, "")).Evidence
	for i := 0; i < 50; i++ {
		got := cls.Classify(httpEvent("POST", "/v1/messages", "api.anthropic.com", headers, "")).Evidence
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("evidence order is unstable on run %d (-first +got):\n%s", i, diff)
		}
	}
	if !sortedAndUnique(want) {
		t.Errorf("evidence is not sorted and deduplicated: %v", want)
	}
}

func sortedAndUnique(tokens []string) bool {
	for i := 1; i < len(tokens); i++ {
		if tokens[i-1] >= tokens[i] {
			return false
		}
	}
	return true
}

// canaries are the secret-shaped strings planted in the fixtures below. None of
// them may appear anywhere in an AIFacts — not in Evidence, not in Model, not
// in any other field.
var canaries = []string{
	"sk-ant-canary-XYZ",
	"Bearer sk-ant-canary-XYZ",
	"canary-KEY-123",
	"SESSION-CANARY-999",
	"PROTOCOL-CANARY-2025",
	"COOKIE-CANARY",
	"AWS-TOKEN-CANARY",
	"PROMPT-CANARY",
	"SYSTEM-CANARY",
	"UA-CANARY",
	"eyJhbGciOiJIUzI1NiJ9.CANARY.sig",
}

// TestEvidenceNeverContainsHeaderValues is the blocking redaction test for this
// package (DESIGN §3.1/§4). Two distinct classes of leak are covered:
//
//   - Secret headers, whose values runtimeevent redacts before the classifier
//     ever sees them.
//   - Headers the classifier itself keys on — MCP-Session-Id,
//     MCP-Protocol-Version, User-Agent — whose values are NOT redacted and
//     therefore ARE visible to the classifier. Nothing but their NAME may be
//     emitted, and only this test stands between "we match on that header" and
//     "we publish its value".
//
// Body content is covered too: the only body-derived field is Model, and it is
// charset- and length-validated, so prompt text cannot reach it.
func TestEvidenceNeverContainsHeaderValues(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())

	secretHeaders := map[string]string{
		"authorization":        "Bearer sk-ant-canary-XYZ",
		"proxy-authorization":  "Basic sk-ant-canary-XYZ",
		"x-api-key":            "canary-KEY-123",
		"api-key":              "canary-KEY-123",
		"x-goog-api-key":       "canary-KEY-123",
		"cookie":               "session=COOKIE-CANARY",
		"set-cookie":           "session=COOKIE-CANARY",
		"x-amz-security-token": "AWS-TOKEN-CANARY",
		// Not secret, so NOT redacted upstream: the classifier sees these
		// values and must still never publish them.
		"mcp-session-id":       "SESSION-CANARY-999",
		"mcp-protocol-version": "PROTOCOL-CANARY-2025",
		"user-agent":           "UA-CANARY/1.0",
		"anthropic-version":    "SYSTEM-CANARY",
		"x-custom-token":       "eyJhbGciOiJIUzI1NiJ9.CANARY.sig",
	}
	const canaryBody = `{"model":"gpt-4o","messages":[{"role":"system","content":"SYSTEM-CANARY"},` +
		`{"role":"user","content":"PROMPT-CANARY"}],"metadata":{"key":"sk-ant-canary-XYZ"}}`

	events := []*runtimeevent.Event{
		httpEvent("POST", "/v1/messages", "api.anthropic.com", secretHeaders, canaryBody),
		httpEvent("POST", "/v1/chat/completions", "api.openai.com", secretHeaders, canaryBody),
		httpEvent("POST", "/mcp", "mcp.example.com", secretHeaders,
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"q":"PROMPT-CANARY"}}}`),
		httpEvent("GET", "/.well-known/agent.json", "agents.example.com", secretHeaders, ""),
		httpEvent("POST", "/api/chat", "ollama:11434", secretHeaders, canaryBody),
		execEvent("/usr/local/bin/npx", "npx", "-y", "@modelcontextprotocol/server-git", "--token", "sk-ant-canary-XYZ"),
		openEvent("/home/agent/.cursor/mcp.json"),
	}

	for _, ev := range events {
		facts := cls.Classify(ev)
		if facts == nil {
			t.Fatalf("Classify() = nil for a canary fixture (%s %s); the test would prove nothing",
				ev.Kind, ev.HTTP.Path())
		}

		// Scan the marshaled facts: any future field is covered automatically.
		blob, err := json.Marshal(facts)
		if err != nil {
			t.Fatalf("marshalling facts: %v", err)
		}
		for _, canary := range canaries {
			if strings.Contains(string(blob), canary) {
				t.Errorf("canary %q leaked into AIFacts: %s", canary, blob)
			}
		}

		// Belt and braces: no evidence token may carry a value at all, and
		// header tokens must be exactly "header:<name>".
		for _, tok := range facts.Evidence {
			prefix, value, found := strings.Cut(tok, ":")
			if !found {
				t.Errorf("evidence token %q has no prefix", tok)
				continue
			}
			if prefix != EvidenceHeader {
				continue
			}
			if _, ok := secretHeaders[value]; !ok && value != "accept" && value != "content-type" {
				t.Errorf("header evidence %q does not name a header of the request", tok)
			}
			if strings.ContainsAny(value, "=: ") {
				t.Errorf("header evidence %q looks like it carries a value", tok)
			}
		}

		// The one body-derived field is Model, and only a validated model id
		// may appear there.
		if facts.Model != "" && !ValidModelName(facts.Model) {
			t.Errorf("Model = %q is not a valid model identifier", facts.Model)
		}
		if facts.JSONRPCMethod != "" && !ValidMethodName(facts.JSONRPCMethod) {
			t.Errorf("JSONRPCMethod = %q is not a valid method name", facts.JSONRPCMethod)
		}
	}
}

func TestProcessSetsFactsAndNeverDrops(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())

	tests := []struct {
		name    string
		ev      *runtimeevent.Event
		wantAI  bool
		wantCls runtimeevent.AIClass
	}{
		{"ai event", dnsEvent("api.openai.com"), true, runtimeevent.AIClassLLM},
		{"mcp exec", execEvent("/usr/bin/uvx", "uvx", "mcp-server-sqlite"), true, runtimeevent.AIClassMCP},
		{"a2a card", httpEvent("GET", "/.well-known/agent-card.json", "peer.internal", nil, ""), true, runtimeevent.AIClassA2A},
		{"non ai event", dnsEvent("www.example.com"), false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if keep := cls.Process(tc.ev); !keep {
				t.Fatal("Process() = false: the classifier must never drop an event")
			}
			if tc.wantAI {
				if tc.ev.AI == nil {
					t.Fatal("Process() left ev.AI nil")
				}
				if tc.ev.AI.Class != tc.wantCls {
					t.Errorf("ev.AI.Class = %q, want %q", tc.ev.AI.Class, tc.wantCls)
				}
				return
			}
			if tc.ev.AI != nil {
				t.Errorf("ev.AI = %+v, want nil", tc.ev.AI)
			}
		})
	}
}

func TestProcessClearsStaleFacts(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())
	ev := dnsEvent("www.example.com")
	ev.AI = &runtimeevent.AIFacts{Class: runtimeevent.AIClassLLM, Provider: "openai", Confidence: 70}
	cls.Process(ev)
	if ev.AI != nil {
		t.Errorf("ev.AI = %+v, want nil: a fixture-supplied verdict must not survive classification", ev.AI)
	}
}

func TestProcessCountsClassifiedEvents(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	cls := NewClassifier(DefaultCatalog(), WithMetrics(m), nil)

	cls.Process(dnsEvent("api.openai.com"))
	cls.Process(dnsEvent("api.openai.com"))
	cls.Process(dnsEvent("www.example.com")) // not AI: must not count
	cls.Process(execEvent("/usr/bin/uvx", "uvx", "mcp-server-sqlite"))

	if got := testutil.ToFloat64(m.AIClassified.WithLabelValues("llm", "openai")); got != 2 {
		t.Errorf("AIClassified{llm,openai} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.AIClassified.WithLabelValues("mcp", ProviderUnknown)); got != 1 {
		t.Errorf("AIClassified{mcp,unknown} = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.AIClassified); got != 2 {
		t.Errorf("AIClassified series = %d, want 2", got)
	}
}

func TestProcessWithoutMetricsDoesNotPanic(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())
	if !cls.Process(dnsEvent("api.openai.com")) {
		t.Error("Process() = false")
	}
}

func TestSetCatalogHotReload(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())
	ev := dnsEvent("llm.acme.internal")
	if got := cls.Classify(ev); got != nil {
		t.Fatalf("Classify() = %+v before the reload, want nil", got)
	}

	custom, err := LoadCatalog([]byte(`{"providers":[{"name":"acme","hostnames":["llm.acme.internal"],"sanctioned":true}]}`))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	cls.SetCatalog(custom)

	want := &runtimeevent.AIFacts{
		Class:      runtimeevent.AIClassLLM,
		Provider:   "acme",
		Sanctioned: true,
		Confidence: ScoreDNSProvider,
		Evidence:   []string{"dns:llm.acme.internal", "provider:acme"},
	}
	if diff := cmp.Diff(want, cls.Classify(ev)); diff != "" {
		t.Errorf("Classify() after reload mismatch (-want +got):\n%s", diff)
	}

	// The reloaded catalog replaced the default, so its providers are gone.
	if got := cls.Classify(dnsEvent("api.openai.com")); got != nil {
		t.Errorf("Classify() = %+v, want nil after the catalog was replaced", got)
	}

	// A nil reload is ignored rather than blinding the classifier.
	cls.SetCatalog(nil)
	if cls.Catalog() != custom {
		t.Error("SetCatalog(nil) replaced the catalog")
	}
}

func TestClassifierName(t *testing.T) {
	if got := NewClassifier(nil).Name(); got != StageName {
		t.Errorf("Name() = %q, want %q", got, StageName)
	}
}

func TestSanctionedFlowsFromTheCatalog(t *testing.T) {
	cat, err := LoadCatalog([]byte(`{"providers":[
		{"name":"approved","hostnames":["approved.example.com"],"sanctioned":true},
		{"name":"other","hostnames":["other.example.com"]}
	]}`))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	cls := NewClassifier(cat)

	if got := cls.Classify(dnsEvent("approved.example.com")); got == nil || !got.Sanctioned {
		t.Errorf("Sanctioned = %v, want true", got)
	}
	if got := cls.Classify(dnsEvent("other.example.com")); got == nil || got.Sanctioned {
		t.Errorf("Sanctioned = %v, want false", got)
	}
}
