package ai

import (
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

func TestBodyShape(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		shape string
		ok    bool
	}{
		{
			name:  "openai chat completions",
			body:  `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}`,
			shape: "model+messages", ok: true,
		},
		{
			name:  "anthropic messages",
			body:  `{"model":"claude-sonnet-4-5","max_tokens":1024,"messages":[]}`,
			shape: "model+messages", ok: true,
		},
		{
			name:  "gemini generateContent",
			body:  `{"model":"gemini-2.0-flash","contents":[{"parts":[{"text":"hi"}]}]}`,
			shape: "model+contents", ok: true,
		},
		{
			name:  "legacy completion",
			body:  `{"model":"gpt-3.5-turbo-instruct","prompt":"once upon a time"}`,
			shape: "model+prompt", ok: true,
		},
		{
			name:  "embeddings",
			body:  `{"model":"text-embedding-3-small","input":"hello"}`,
			shape: "model+input", ok: true,
		},
		{
			// Bedrock carries the model in the path, so the body alone must
			// still be recognizable.
			name:  "bedrock anthropic native",
			body:  `{"anthropic_version":"bedrock-2023-05-31","max_tokens":512,"messages":[]}`,
			shape: "anthropic_version", ok: true,
		},
		{
			name:  "messages plus max tokens without model",
			body:  `{"messages":[{"role":"user","content":"hi"}],"max_tokens":100}`,
			shape: "messages+max_tokens", ok: true,
		},
		{
			name: "model alone is not an inference body",
			body: `{"model":"gpt-4o"}`,
		},
		{
			name: "messages alone is not an inference body",
			body: `{"messages":[]}`,
		},
		{
			name: "unrelated json",
			body: `{"user":"bob","action":"login"}`,
		},
		{
			name: "not json",
			body: `model=gpt-4o&messages=hi`,
		},
		{
			name: "empty",
			body: ``,
		},
		{
			name: "json array",
			body: `[{"model":"gpt-4o","messages":[]}]`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shape, ok := BodyShape(tc.body)
			if ok != tc.ok {
				t.Fatalf("BodyShape() ok = %v, want %v (shape %q)", ok, tc.ok, shape)
			}
			if shape != tc.shape {
				t.Errorf("BodyShape() = %q, want %q", shape, tc.shape)
			}
		})
	}
}

// TestClassifyLLMHostedProvidersFromMetadata covers the signals that survive
// TLS: DNS question names and ClientHello SNI, for every hosted provider shape
// including the Azure / Bedrock / Vertex wildcards.
func TestClassifyLLMHostedProvidersFromMetadata(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())

	tests := []struct {
		name string
		host string
		want string // provider; "" means not AI
	}{
		{"anthropic", "api.anthropic.com", "anthropic"},
		{"openai", "api.openai.com", "openai"},
		{"azure openai", "acme-prod.openai.azure.com", "azure-openai"},
		{"azure cognitive services", "acme.cognitiveservices.azure.com", "azure-openai"},
		{"gemini", "generativelanguage.googleapis.com", "google"},
		{"vertex regional", "europe-west4-aiplatform.googleapis.com", "google"},
		{"bedrock", "bedrock-runtime.us-west-2.amazonaws.com", "bedrock"},
		{"mistral", "api.mistral.ai", "mistral"},
		{"cohere", "api.cohere.com", "cohere"},
		{"openrouter", "openrouter.ai", "openrouter"},
		{"groq", "api.groq.com", "groq"},
		{"fireworks", "api.fireworks.ai", "fireworks"},
		{"together", "api.together.xyz", "together"},
		{"xai", "api.x.ai", "xai"},
		{"deepseek", "api.deepseek.com", "deepseek"},
		{"perplexity", "api.perplexity.ai", "perplexity"},
		{"huggingface", "api-inference.huggingface.co", "huggingface"},
		{"ollama in cluster", "ollama.ai-team.svc.cluster.local", "ollama"},
		{"unrelated host", "www.example.com", ""},
		{"unrelated aws host", "sqs.us-east-1.amazonaws.com", ""},
		{"cluster dns", "kubernetes.default.svc.cluster.local", ""},
	}

	for _, tc := range tests {
		t.Run("dns "+tc.name, func(t *testing.T) {
			got := cls.Classify(dnsEvent(tc.host))
			if tc.want == "" {
				if got != nil {
					t.Fatalf("Classify() = %+v, want nil", got)
				}
				return
			}
			want := &runtimeevent.AIFacts{
				Class:      runtimeevent.AIClassLLM,
				Provider:   tc.want,
				Confidence: ScoreDNSProvider,
				Evidence: []string{
					"dns:" + strings.ToLower(tc.host),
					"provider:" + tc.want,
				},
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Classify() mismatch (-want +got):\n%s", diff)
			}
		})

		t.Run("sni "+tc.name, func(t *testing.T) {
			got := cls.Classify(tlsEvent(tc.host, "h2"))
			if tc.want == "" {
				if got != nil {
					t.Fatalf("Classify() = %+v, want nil", got)
				}
				return
			}
			want := &runtimeevent.AIFacts{
				Class:      runtimeevent.AIClassLLM,
				Provider:   tc.want,
				Transport:  TransportHTTPS,
				Confidence: ScoreSNIProvider,
				Evidence: []string{
					"alpn:h2",
					"provider:" + tc.want,
					"sni:" + strings.ToLower(tc.host),
				},
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Classify() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClassifyLLMMetadataEdges(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())

	tests := []struct {
		name string
		ev   *runtimeevent.Event
		want *runtimeevent.AIFacts
	}{
		{
			name: "dns question is case and dot insensitive",
			ev:   dnsEvent("API.OpenAI.COM."),
			want: &runtimeevent.AIFacts{
				Class:      runtimeevent.AIClassLLM,
				Provider:   "openai",
				Confidence: 70,
				Evidence:   []string{"dns:api.openai.com", "provider:openai"},
			},
		},
		{
			name: "sni without alpn",
			ev:   tlsEvent("api.anthropic.com"),
			want: &runtimeevent.AIFacts{
				Class:      runtimeevent.AIClassLLM,
				Provider:   "anthropic",
				Transport:  TransportHTTPS,
				Confidence: 70,
				Evidence:   []string{"provider:anthropic", "sni:api.anthropic.com"},
			},
		},
		{
			name: "multiple alpn protocols are recorded but do not score",
			ev:   tlsEvent("api.openai.com", "h2", "http/1.1"),
			want: &runtimeevent.AIFacts{
				Class:      runtimeevent.AIClassLLM,
				Provider:   "openai",
				Transport:  TransportHTTPS,
				Confidence: 70,
				Evidence:   []string{"alpn:h2", "alpn:http/1.1", "provider:openai", "sni:api.openai.com"},
			},
		},
		{
			// The ECH / IP-literal evasion path: no SNI, nothing to match.
			name: "tls without sni is not classifiable",
			ev:   tlsEvent(""),
			want: nil,
		},
		{
			name: "net flow to the ollama port",
			ev:   netEvent("10.42.0.9", 11434),
			want: &runtimeevent.AIFacts{
				Class:      runtimeevent.AIClassLLM,
				Provider:   "ollama",
				Confidence: ScorePortSelfHosted,
				Evidence:   []string{"port:11434", "provider:ollama"},
			},
		},
		{
			name: "net flow to the vllm port",
			ev:   netEvent("10.42.0.9", 8000),
			want: &runtimeevent.AIFacts{
				Class:      runtimeevent.AIClassLLM,
				Provider:   "vllm",
				Confidence: ScorePortSelfHosted,
				Evidence:   []string{"port:8000", "provider:vllm"},
			},
		},
		{
			name: "net flow to https is not classifiable",
			ev:   netEvent("104.18.7.192", 443),
			want: nil,
		},
		{
			name: "dns facts missing on a dns event",
			ev:   &runtimeevent.Event{Kind: runtimeevent.KindDNS},
			want: nil,
		},
		{
			name: "tls facts missing on a tls event",
			ev:   &runtimeevent.Event{Kind: runtimeevent.KindTLS},
			want: nil,
		},
		{
			name: "net facts missing on a net event",
			ev:   &runtimeevent.Event{Kind: runtimeevent.KindNet},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, cls.Classify(tc.ev)); diff != "" {
				t.Errorf("Classify() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestClassifyLLMFromPlaintextHTTP is the high-fidelity half: path shape,
// provider header names, body shape and self-hosted ports, including the
// self-hosted-on-a-nonstandard-port case that has no recognizable hostname.
func TestClassifyLLMFromPlaintextHTTP(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())

	tests := []struct {
		name string
		ev   *runtimeevent.Event
		want *runtimeevent.AIFacts
	}{
		{
			name: "anthropic messages with provider header",
			ev: httpEvent("POST", "/v1/messages", "api.anthropic.com", map[string]string{
				"anthropic-version": "2023-06-01",
				"authorization":     "Bearer sk-ant-secret",
				"content-type":      "application/json",
			}, `{"model":"claude-sonnet-4-5","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "anthropic",
				Model:        "claude-sonnet-4-5",
				EndpointKind: "messages",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"body-shape:model+messages",
					"header:anthropic-version",
					"host:api.anthropic.com",
					"http-path:/v1/messages",
					"provider:anthropic",
				},
			},
		},
		{
			name: "openai chat completions",
			ev: httpEvent("POST", "/v1/chat/completions", "api.openai.com", map[string]string{
				"openai-organization": "org-acme",
				"content-type":        "application/json",
			}, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "openai",
				Model:        "gpt-4o",
				EndpointKind: "chat.completions",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"body-shape:model+messages",
					"header:openai-organization",
					"host:api.openai.com",
					"http-path:/v1/chat/completions",
					"provider:openai",
				},
			},
		},
		{
			name: "azure openai deployment path",
			ev: httpEvent("POST", "/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21",
				"acme.openai.azure.com", map[string]string{
					"api-key":      "secret",
					"content-type": "application/json",
				}, `{"messages":[{"role":"user","content":"hi"}],"max_tokens":50}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "azure-openai",
				EndpointKind: "chat.completions",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"body-shape:messages+max_tokens",
					"host:acme.openai.azure.com",
					"http-path:/openai/deployments/gpt-4o/chat/completions",
					"provider:azure-openai",
				},
			},
		},
		{
			name: "bedrock invoke",
			ev: httpEvent("POST", "/model/anthropic.claude-3-5-sonnet-20241022-v2:0/invoke",
				"bedrock-runtime.us-east-1.amazonaws.com", map[string]string{
					"x-amzn-bedrock-accept": "application/json",
					"authorization":         "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/...",
				}, `{"anthropic_version":"bedrock-2023-05-31","max_tokens":512,"messages":[]}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "bedrock",
				EndpointKind: "bedrock.invoke",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"body-shape:anthropic_version",
					"header:x-amzn-bedrock-accept",
					"host:bedrock-runtime.us-east-1.amazonaws.com",
					"http-path:/model/anthropic.claude-3-5-sonnet-20241022-v2:0/invoke",
					"provider:bedrock",
				},
			},
		},
		{
			name: "vertex generateContent",
			ev: httpEvent("POST", "/v1/projects/acme/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent",
				"us-central1-aiplatform.googleapis.com", map[string]string{
					"content-type": "application/json",
				}, `{"contents":[{"parts":[{"text":"hi"}]}]}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "google",
				EndpointKind: "generateContent",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"host:us-central1-aiplatform.googleapis.com",
					"http-path:/v1/projects/acme/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent",
					"provider:google",
				},
			},
		},
		{
			name: "gemini generateContent with api key header name",
			ev: httpEvent("POST", "/v1beta/models/gemini-2.0-flash:generateContent",
				"generativelanguage.googleapis.com", map[string]string{
					"x-goog-api-key": "AIzaSyCanary",
				}, `{"contents":[{"parts":[{"text":"hi"}]}]}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "google",
				EndpointKind: "generateContent",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"header:x-goog-api-key",
					"host:generativelanguage.googleapis.com",
					"http-path:/v1beta/models/gemini-2.0-flash:generateContent",
					"provider:google",
				},
			},
		},
		{
			name: "self hosted ollama on 11434",
			ev: httpEvent("POST", "/api/chat", "ollama:11434", map[string]string{
				"content-type": "application/json",
			}, `{"model":"llama3.1:8b","messages":[{"role":"user","content":"hi"}]}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "ollama",
				Model:        "llama3.1:8b",
				EndpointKind: "ollama.chat",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"body-shape:model+messages",
					"host:ollama",
					"http-path:/api/chat",
					"port:11434",
					"provider:ollama",
				},
			},
		},
		{
			name: "self hosted vllm on 8000 by ip",
			ev: httpEvent("POST", "/v1/chat/completions", "10.42.0.9:8000", map[string]string{
				"content-type": "application/json",
			}, `{"model":"mistralai/Mistral-7B-Instruct-v0.3","messages":[]}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "vllm",
				Model:        "mistralai/Mistral-7B-Instruct-v0.3",
				EndpointKind: "chat.completions",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"body-shape:model+messages",
					"host:10.42.0.9",
					"http-path:/v1/chat/completions",
					"port:8000",
					"provider:vllm",
				},
			},
		},
		{
			// The truest shadow-AI case: an OpenAI-compatible server on an
			// arbitrary port with no recognizable hostname. Body shape carries
			// the detection, and the provider is honestly reported as
			// self-hosted rather than guessed to be OpenAI from the path.
			name: "openai compatible server on an arbitrary port",
			ev: httpEvent("POST", "/v1/chat/completions", "inference.internal:9999", map[string]string{
				"content-type": "application/json",
			}, `{"model":"qwen2.5-coder","messages":[{"role":"user","content":"hi"}]}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     ProviderSelfHosted,
				Model:        "qwen2.5-coder",
				EndpointKind: "chat.completions",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"body-shape:model+messages",
					"host:inference.internal",
					"http-path:/v1/chat/completions",
				},
			},
		},
		{
			name: "ip literal with an anthropic path is attributed by path shape",
			ev: httpEvent("POST", "/v1/messages", "104.18.7.192", nil,
				`{"model":"claude-3-haiku","messages":[]}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "anthropic",
				Model:        "claude-3-haiku",
				EndpointKind: "messages",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"body-shape:model+messages",
					"host:104.18.7.192",
					"http-path:/v1/messages",
					"provider:anthropic",
				},
			},
		},
		{
			name: "path only, no body available",
			ev:   httpEvent("POST", "/v1/chat/completions", "", nil, ""),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     ProviderUnknown,
				EndpointKind: "chat.completions",
				Transport:    TransportHTTP,
				Confidence:   ScoreHTTPPath,
				Evidence:     []string{"http-path:/v1/chat/completions"},
			},
		},
		{
			name: "host only, unremarkable path",
			ev:   httpEvent("GET", "/", "api.openai.com", nil, ""),
			want: &runtimeevent.AIFacts{
				Class:      runtimeevent.AIClassLLM,
				Provider:   "openai",
				Transport:  TransportHTTP,
				Confidence: ScoreHostProvider,
				Evidence:   []string{"host:api.openai.com", "provider:openai"},
			},
		},
		{
			name: "streaming request reports the sse transport",
			ev: httpEvent("POST", "/v1/chat/completions", "api.openai.com", map[string]string{
				"accept":       "text/event-stream",
				"content-type": "application/json",
			}, `{"model":"gpt-4o","messages":[],"stream":true}`),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "openai",
				Model:        "gpt-4o",
				EndpointKind: "chat.completions",
				Transport:    TransportSSE,
				Confidence:   99,
				Evidence: []string{
					"body-shape:model+messages",
					"host:api.openai.com",
					"http-path:/v1/chat/completions",
					"provider:openai",
				},
			},
		},
		{
			name: "net facts supply the port when the host header omits it",
			ev: withNet(httpEvent("POST", "/v1/completions", "inference", map[string]string{
				"content-type": "application/json",
			}, `{"model":"gpt2","prompt":"hi"}`), "10.42.0.9", 11434),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassLLM,
				Provider:     "ollama",
				Model:        "gpt2",
				EndpointKind: "completions",
				Transport:    TransportHTTP,
				Confidence:   99,
				Evidence: []string{
					"body-shape:model+prompt",
					"host:inference",
					"http-path:/v1/completions",
					"port:11434",
					"provider:ollama",
				},
			},
		},
		{
			name: "ordinary web traffic is not ai traffic",
			ev: httpEvent("GET", "/index.html", "www.example.com", map[string]string{
				"user-agent": "curl/8.4.0",
			}, ""),
			want: nil,
		},
		{
			name: "kubernetes api traffic is not ai traffic",
			ev: httpEvent("POST", "/apis/apps/v1/namespaces/default/deployments", "kubernetes.default.svc",
				map[string]string{"content-type": "application/json"},
				`{"kind":"Deployment","metadata":{"name":"web"}}`),
			want: nil,
		},
		{
			name: "http facts missing on an http event",
			ev:   &runtimeevent.Event{Kind: runtimeevent.KindHTTP},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, cls.Classify(tc.ev)); diff != "" {
				t.Errorf("Classify() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClassifyLLMIgnoresOtherKinds(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())
	// exec and open observations belong to the MCP classifier; an LLM verdict
	// must not be invented from a filename.
	for _, ev := range []*runtimeevent.Event{
		execEvent("/usr/bin/python3", "python3", "app.py"),
		openEvent("/usr/lib/python3/site-packages/openai/__init__.py"),
	} {
		if got := classifyLLM(cls.Catalog(), ev); got != nil {
			t.Errorf("classifyLLM(%s) = %+v, want nil", ev.Kind, got)
		}
	}
}
