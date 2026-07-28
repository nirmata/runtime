package ai

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// requiredProviders are the providers DESIGN §3.2 mandates the shipped catalog
// carry. Removing one is a behavior change, not a refactor.
var requiredProviders = []string{
	"anthropic", "openai", "azure-openai", "google", "bedrock", "mistral",
	"cohere", "openrouter", "groq", "fireworks", "together", "ollama", "vllm",
}

func TestDefaultCatalogParsesAndCoversRequiredProviders(t *testing.T) {
	cat := DefaultCatalog()
	if cat == nil {
		t.Fatal("DefaultCatalog() = nil")
	}
	for _, name := range requiredProviders {
		if _, ok := cat.Provider(name); !ok {
			t.Errorf("catalog is missing required provider %q", name)
		}
	}
	if got := len(cat.Providers()); got < len(requiredProviders) {
		t.Errorf("len(Providers()) = %d, want >= %d", got, len(requiredProviders))
	}
	// Same pointer on every call: the catalog is immutable and shared.
	if DefaultCatalog() != cat {
		t.Error("DefaultCatalog() returned a different pointer on the second call")
	}
}

func TestDefaultCatalogShipsNoSanctionedOpinion(t *testing.T) {
	// Whether a provider is approved is a cluster decision, expressed by the
	// operator through the catalog ConfigMap, never by us.
	for _, p := range DefaultCatalog().Providers() {
		if p.Sanctioned {
			t.Errorf("provider %q ships marked sanctioned", p.Name)
		}
	}
}

func TestSelfHostedProvidersHavePorts(t *testing.T) {
	for _, p := range DefaultCatalog().Providers() {
		if p.SelfHosted && len(p.Ports) == 0 {
			t.Errorf("self-hosted provider %q has no ports: the port-only signal cannot fire", p.Name)
		}
		if !p.SelfHosted && len(p.Ports) > 0 {
			t.Errorf("hosted provider %q declares ports %v", p.Name, p.Ports)
		}
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		s       string
		want    bool
	}{
		{"exact", "api.openai.com", "api.openai.com", true},
		{"exact mismatch", "api.openai.com", "api.openai.co", false},
		{"leading star", "*.openai.azure.com", "mycorp.openai.azure.com", true},
		{"leading star multi label", "*.openai.azure.com", "a.b.openai.azure.com", true},
		{"leading star needs suffix", "*.openai.azure.com", "openai.azure.com", false},
		{"middle star", "bedrock-runtime.*.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com", true},
		{"middle star empty", "bedrock-runtime.*.amazonaws.com", "bedrock-runtime..amazonaws.com", true},
		{"middle star mismatch", "bedrock-runtime.*.amazonaws.com", "bedrock.us-east-1.amazonaws.com", false},
		{"prefix star", "*-aiplatform.googleapis.com", "us-central1-aiplatform.googleapis.com", true},
		{"trailing star", "ollama.*", "ollama.ai.svc.cluster.local", true},
		{"trailing star empty match", "ollama*", "ollama", true},
		{"question mark", "gpt-?", "gpt-4", true},
		{"question mark needs a char", "gpt-?", "gpt-", false},
		{"path star", "/model/*/invoke", "/model/anthropic.claude-3-5-sonnet-20241022-v2:0/invoke", true},
		{"path star does not swallow suffix", "/model/*/invoke", "/model/x/invoke-with-response-stream", false},
		{"path colon star", "/v1beta/models/*:generateContent", "/v1beta/models/gemini-2.0-flash:generateContent", true},
		{"backtracking", "*a*b", "xxaxxaxxb", true},
		{"backtracking fail", "*a*b", "xxaxxaxxc", false},
		{"star only", "*", "anything", true},
		{"star matches empty string", "*", "", true},
		{"empty pattern empty string", "", "", true},
		{"empty pattern non empty", "", "x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchGlob(tc.pattern, tc.s); got != tc.want {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "api.openai.com", "api.openai.com"},
		{"uppercase", "API.OpenAI.Com", "api.openai.com"},
		{"trailing dot", "api.openai.com.", "api.openai.com"},
		{"with port", "api.openai.com:443", "api.openai.com"},
		{"ollama port", "ollama:11434", "ollama"},
		{"padded", "  api.openai.com  ", "api.openai.com"},
		{"ipv4 with port", "10.42.0.9:8000", "10.42.0.9"},
		{"bare ipv6", "fd00::1", "fd00::1"},
		{"bracketed ipv6", "[fd00::1]", "fd00::1"},
		{"bracketed ipv6 with port", "[fd00::1]:11434", "fd00::1"},
		{"non numeric colon suffix kept", "host:notaport", "host:notaport"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeHost(tc.in); got != tc.want {
				t.Errorf("NormalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestHostPort(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want uint16
	}{
		{"no port", "api.openai.com", 0},
		{"ollama", "ollama:11434", 11434},
		{"vllm ip", "10.42.0.9:8000", 8000},
		{"https", "api.openai.com:443", 443},
		{"bare ipv6", "fd00::1", 0},
		{"bracketed ipv6 no port", "[fd00::1]", 0},
		{"bracketed ipv6 with port", "[fd00::1]:11434", 11434},
		{"not a number", "host:abc", 0},
		{"out of range", "host:99999", 0},
		{"empty", "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HostPort(tc.in); got != tc.want {
				t.Errorf("HostPort(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestCatalogMatchHost(t *testing.T) {
	cat := DefaultCatalog()
	tests := []struct {
		name     string
		host     string
		provider string // "" means no match
	}{
		{"anthropic", "api.anthropic.com", "anthropic"},
		{"openai", "api.openai.com", "openai"},
		{"openai with port", "api.openai.com:443", "openai"},
		{"openai uppercase", "API.OPENAI.COM", "openai"},
		{"openai trailing dot", "api.openai.com.", "openai"},
		{"azure openai shape", "mycorp.openai.azure.com", "azure-openai"},
		{"azure cognitive shape", "acme-eu.cognitiveservices.azure.com", "azure-openai"},
		{"azure ai services shape", "acme.services.ai.azure.com", "azure-openai"},
		{"google gemini", "generativelanguage.googleapis.com", "google"},
		{"vertex regional shape", "us-central1-aiplatform.googleapis.com", "google"},
		{"vertex global", "aiplatform.googleapis.com", "google"},
		{"bedrock regional shape", "bedrock-runtime.us-east-1.amazonaws.com", "bedrock"},
		{"bedrock agent runtime", "bedrock-agent-runtime.eu-west-1.amazonaws.com", "bedrock"},
		{"mistral", "api.mistral.ai", "mistral"},
		{"cohere", "api.cohere.com", "cohere"},
		{"openrouter", "openrouter.ai", "openrouter"},
		{"groq", "api.groq.com", "groq"},
		{"fireworks", "api.fireworks.ai", "fireworks"},
		{"together", "api.together.xyz", "together"},
		{"ollama service", "ollama", "ollama"},
		{"ollama fqdn", "ollama.ai-team.svc.cluster.local", "ollama"},
		{"vllm service", "vllm", "vllm"},
		{"unrelated aws", "s3.us-east-1.amazonaws.com", ""},
		{"unrelated google", "storage.googleapis.com", ""},
		{"unrelated azure", "acme.blob.core.windows.net", ""},
		{"plain host", "example.com", ""},
		{"ip literal", "104.18.7.192", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := cat.MatchHost(tc.host)
			if tc.provider == "" {
				if ok {
					t.Fatalf("MatchHost(%q) matched %q, want no match", tc.host, p.Name)
				}
				return
			}
			if !ok {
				t.Fatalf("MatchHost(%q) did not match, want %q", tc.host, tc.provider)
			}
			if p.Name != tc.provider {
				t.Errorf("MatchHost(%q) = %q, want %q", tc.host, p.Name, tc.provider)
			}
		})
	}
}

func TestCatalogLLMEndpoint(t *testing.T) {
	cat := DefaultCatalog()
	tests := []struct {
		name string
		path string
		kind string // "" means no match
	}{
		{"anthropic messages", "/v1/messages", "messages"},
		{"anthropic count tokens", "/v1/messages/count_tokens", "messages.count_tokens"},
		{"anthropic complete", "/v1/complete", "complete"},
		{"openai chat", "/v1/chat/completions", "chat.completions"},
		{"openai chat with query", "/v1/chat/completions?stream=true", "chat.completions"},
		{"openai chat trailing slash", "/v1/chat/completions/", "chat.completions"},
		{"openai responses", "/v1/responses", "responses"},
		{"openai embeddings", "/v1/embeddings", "embeddings"},
		{"groq openai compat", "/openai/v1/chat/completions", "chat.completions"},
		{"azure deployment chat", "/openai/deployments/gpt-4o/chat/completions", "chat.completions"},
		{"azure deployment embeddings", "/openai/deployments/ada/embeddings", "embeddings"},
		{"gemini generateContent", "/v1beta/models/gemini-2.0-flash:generateContent", "generateContent"},
		{"gemini stream", "/v1beta/models/gemini-1.5-pro:streamGenerateContent", "streamGenerateContent"},
		{"gemini count tokens", "/v1beta/models/gemini-1.5-pro:countTokens", "countTokens"},
		{"vertex publisher model", "/v1/projects/acme/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent", "generateContent"},
		{"vertex predict", "/v1/projects/acme/locations/us-central1/publishers/google/models/text-bison:predict", "predict"},
		{"vertex endpoint predict", "/v1/projects/acme/locations/us-central1/endpoints/1234:predict", "predict"},
		{"bedrock invoke", "/model/anthropic.claude-3-5-sonnet-20241022-v2:0/invoke", "bedrock.invoke"},
		{"bedrock invoke stream", "/model/meta.llama3-70b-instruct-v1:0/invoke-with-response-stream", "bedrock.invoke-stream"},
		{"bedrock converse", "/model/amazon.titan-text-lite-v1/converse", "bedrock.converse"},
		{"ollama generate", "/api/generate", "ollama.generate"},
		{"ollama chat", "/api/chat", "ollama.chat"},
		{"cohere v2 chat", "/v2/chat", "cohere.chat"},
		{"not an endpoint", "/healthz", ""},
		{"mcp path is not llm", "/mcp", ""},
		{"a2a path is not llm", "/.well-known/agent.json", ""},
		{"root", "/", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, ok := cat.LLMEndpoint(tc.path)
			if tc.kind == "" {
				if ok {
					t.Fatalf("LLMEndpoint(%q) = %q, want no match", tc.path, kind)
				}
				return
			}
			if !ok {
				t.Fatalf("LLMEndpoint(%q) did not match, want %q", tc.path, tc.kind)
			}
			if kind != tc.kind {
				t.Errorf("LLMEndpoint(%q) = %q, want %q", tc.path, kind, tc.kind)
			}
		})
	}
}

func TestCatalogMatchHeader(t *testing.T) {
	cat := DefaultCatalog()
	tests := []struct {
		name     string
		header   string
		provider string
	}{
		{"anthropic version", "anthropic-version", "anthropic"},
		{"anthropic version mixed case", "Anthropic-Version", "anthropic"},
		{"anthropic beta", "anthropic-beta", "anthropic"},
		{"openai org", "openai-organization", "openai"},
		{"openai project", "openai-project", "openai"},
		{"google api key name", "x-goog-api-key", "google"},
		{"bedrock accept", "x-amzn-bedrock-accept", "bedrock"},
		// Secret-but-generic headers must NOT identify a provider: their
		// values are redacted and their names say nothing (any REST API uses
		// authorization / x-api-key).
		{"authorization is not a provider signal", "authorization", ""},
		{"x-api-key is not a provider signal", "x-api-key", ""},
		{"content type", "content-type", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := cat.MatchHeader(tc.header)
			if tc.provider == "" {
				if ok {
					t.Fatalf("MatchHeader(%q) = %q, want no match", tc.header, got)
				}
				return
			}
			if !ok || got != tc.provider {
				t.Errorf("MatchHeader(%q) = (%q, %v), want (%q, true)", tc.header, got, ok, tc.provider)
			}
		})
	}
}

func TestCatalogMatchPort(t *testing.T) {
	cat := DefaultCatalog()
	tests := []struct {
		name     string
		port     uint16
		provider string
	}{
		{"ollama", 11434, "ollama"},
		{"vllm", 8000, "vllm"},
		{"lmstudio", 1234, "lmstudio"},
		{"https", 443, ""},
		{"http", 80, ""},
		{"zero", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := cat.MatchPort(tc.port)
			if tc.provider == "" {
				if ok {
					t.Fatalf("MatchPort(%d) = %q, want no match", tc.port, p.Name)
				}
				return
			}
			if !ok || p.Name != tc.provider {
				t.Errorf("MatchPort(%d) = (%q, %v), want (%q, true)", tc.port, p.Name, ok, tc.provider)
			}
		})
	}
}

func TestCatalogMatchPathProvider(t *testing.T) {
	cat := DefaultCatalog()
	tests := []struct {
		name     string
		path     string
		provider string
	}{
		{"anthropic messages", "/v1/messages", "anthropic"},
		{"bedrock model", "/model/x/invoke", "bedrock"},
		{"azure deployments", "/openai/deployments/gpt-4o/chat/completions", "azure-openai"},
		{"gemini models", "/v1beta/models/gemini:generateContent", "google"},
		{"ollama chat", "/api/chat", "ollama"},
		// The OpenAI-compatible path is the lingua franca of self-hosted
		// servers (vLLM, LM Studio, llama.cpp), so it must NOT be attributed
		// to OpenAI on path shape alone.
		{"openai compatible chat is not attributed", "/v1/chat/completions", ""},
		{"unknown", "/healthz", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := cat.MatchPathProvider(tc.path)
			if tc.provider == "" {
				if ok {
					t.Fatalf("MatchPathProvider(%q) = %q, want no match", tc.path, p.Name)
				}
				return
			}
			if !ok || p.Name != tc.provider {
				t.Errorf("MatchPathProvider(%q) = (%q, %v), want (%q, true)", tc.path, p.Name, ok, tc.provider)
			}
		})
	}
}

func TestLoadCatalog(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr string // substring; "" means success
	}{
		{
			name: "minimal valid",
			data: `{"providers":[{"name":"acme","hostnames":["llm.acme.internal"]}]}`,
		},
		{
			name:    "not json",
			data:    `nope`,
			wantErr: "parsing ai provider catalog",
		},
		{
			name:    "no providers",
			data:    `{"providers":[]}`,
			wantErr: "no providers",
		},
		{
			name:    "provider without name",
			data:    `{"providers":[{"hostnames":["x"]}]}`,
			wantErr: "has no name",
		},
		{
			name:    "provider without hostnames",
			data:    `{"providers":[{"name":"acme"}]}`,
			wantErr: "has no hostnames",
		},
		{
			name:    "duplicate provider",
			data:    `{"providers":[{"name":"acme","hostnames":["a"]},{"name":"acme","hostnames":["b"]}]}`,
			wantErr: `duplicate provider "acme"`,
		},
		{
			name:    "endpoint without kind",
			data:    `{"providers":[{"name":"acme","hostnames":["a"]}],"llmEndpoints":[{"pattern":"/v1/x"}]}`,
			wantErr: "needs both pattern and kind",
		},
		{
			// A typo in an operator-supplied ConfigMap must fail loudly, not
			// silently drop half the catalog.
			name:    "unknown field",
			data:    `{"providers":[{"name":"acme","hostnames":["a"]}],"provderz":[]}`,
			wantErr: "unknown field",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cat, err := LoadCatalog([]byte(tc.data))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadCatalog() = nil error, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("LoadCatalog() error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadCatalog() error = %v", err)
			}
			if cat == nil {
				t.Fatal("LoadCatalog() = nil catalog with nil error")
			}
		})
	}
}

func TestLoadCatalogRoundTripsProviderFields(t *testing.T) {
	const data = `{"providers":[{"name":"Acme","hostnames":["LLM.acme.internal","*.acme.internal"],` +
		`"pathPrefixes":["/infer"],"headerNames":["X-Acme-Model"],"ports":[9000],"selfHosted":true,"sanctioned":true}]}`
	cat, err := LoadCatalog([]byte(data))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	want := Provider{
		Name:         "acme",
		Hostnames:    []string{"LLM.acme.internal", "*.acme.internal"},
		PathPrefixes: []string{"/infer"},
		HeaderNames:  []string{"X-Acme-Model"},
		Ports:        []uint16{9000},
		SelfHosted:   true,
		Sanctioned:   true,
	}
	got, ok := cat.Provider("acme")
	if !ok {
		t.Fatal(`Provider("acme") not found: names must be normalized to lower case`)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Provider mismatch (-want +got):\n%s", diff)
	}
	// Lookups honour the loaded data, case-insensitively.
	if p, ok := cat.MatchHost("llm.acme.internal"); !ok || p.Name != "acme" {
		t.Errorf(`MatchHost("llm.acme.internal") = (%q, %v), want ("acme", true)`, p.Name, ok)
	}
	if p, ok := cat.MatchHost("a.acme.internal"); !ok || p.Name != "acme" {
		t.Errorf(`MatchHost("a.acme.internal") = (%q, %v), want ("acme", true)`, p.Name, ok)
	}
	if pn, ok := cat.MatchHeader("x-acme-model"); !ok || pn != "acme" {
		t.Errorf(`MatchHeader("x-acme-model") = (%q, %v), want ("acme", true)`, pn, ok)
	}
	if p, ok := cat.MatchPort(9000); !ok || p.Name != "acme" {
		t.Errorf("MatchPort(9000) = (%q, %v), want (\"acme\", true)", p.Name, ok)
	}
	if !got.Sanctioned {
		t.Error("Sanctioned did not survive the load")
	}
}

func TestNilCatalogNeverPanics(t *testing.T) {
	// A nil catalog can only arise from a programming error, but every lookup
	// must degrade to "no match" rather than take the daemon down.
	var cat *Catalog
	if _, ok := cat.MatchHost("api.openai.com"); ok {
		t.Error("nil catalog matched a host")
	}
	if _, ok := cat.LLMEndpoint("/v1/messages"); ok {
		t.Error("nil catalog matched an endpoint")
	}
	if _, ok := cat.MatchHeader("anthropic-version"); ok {
		t.Error("nil catalog matched a header")
	}
	if _, ok := cat.MatchPort(11434); ok {
		t.Error("nil catalog matched a port")
	}
	if _, ok := cat.MatchPathProvider("/v1/messages"); ok {
		t.Error("nil catalog matched a path")
	}
	if _, ok := cat.Provider("openai"); ok {
		t.Error("nil catalog resolved a provider")
	}
	if cat.IsMCPMethod("tools/call") || cat.IsMCPPath("/mcp") ||
		cat.IsMCPServerPackage("mcp-server-git") || cat.IsMCPConfigPath("/root/.mcp.json") ||
		cat.IsA2APath("/.well-known/agent.json") || cat.IsA2AMethod("message/send") {
		t.Error("nil catalog matched an MCP/A2A rule")
	}
	if _, ok := cat.DetectMCPStdio("/usr/bin/npx", []string{"npx", "mcp-server-git"}); ok {
		t.Error("nil catalog detected a stdio server")
	}
	if got := cat.Providers(); got != nil {
		t.Errorf("nil catalog Providers() = %v, want nil", got)
	}
	if diff := cmp.Diff(MCPRules{}, cat.MCP()); diff != "" {
		t.Errorf("nil catalog MCP() mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(A2ARules{}, cat.A2A()); diff != "" {
		t.Errorf("nil catalog A2A() mismatch (-want +got):\n%s", diff)
	}
}

func TestProvidersReturnsACopy(t *testing.T) {
	cat := DefaultCatalog()
	ps := cat.Providers()
	if len(ps) == 0 {
		t.Fatal("no providers")
	}
	ps[0].Name = "mutated"
	if again := cat.Providers(); again[0].Name == "mutated" {
		t.Error("Providers() exposed the catalog's own slice")
	}
}
