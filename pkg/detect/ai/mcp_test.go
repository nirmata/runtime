package ai

import (
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

func TestIsMCPMethod(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   bool
	}{
		{"initialize", "initialize", true},
		{"tools list", "tools/list", true},
		{"tools call", "tools/call", true},
		{"resources read", "resources/read", true},
		{"resources subscribe", "resources/subscribe", true},
		{"prompts get", "prompts/get", true},
		{"sampling create message", "sampling/createMessage", true},
		{"roots list", "roots/list", true},
		{"notifications initialized", "notifications/initialized", true},
		{"notifications nested", "notifications/roots/list_changed", true},
		{"completion complete", "completion/complete", true},
		{"logging set level", "logging/setLevel", true},
		{"elicitation create", "elicitation/create", true},
		{"a2a method is not mcp", "message/send", false},
		{"a2a tasks is not mcp", "tasks/get", false},
		{"unrelated rpc", "eth_getBalance", false},
		{"prefix without slash", "tools", false},
		{"initialized alone", "initialized", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMCPMethod(tc.method); got != tc.want {
				t.Errorf("IsMCPMethod(%q) = %v, want %v", tc.method, got, tc.want)
			}
		})
	}
}

func TestIsMCPServerPackage(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want bool
	}{
		{"official scope", "@modelcontextprotocol/server-git", true},
		{"official scope filesystem", "@modelcontextprotocol/server-filesystem", true},
		{"official scope uppercase", "@ModelContextProtocol/Server-Git", true},
		{"mcp scope", "@mcp/postgres", true},
		{"pypi style", "mcp-server-sqlite", true},
		{"module style", "mcp_server_time", true},
		{"mcp remote bridge", "mcp-remote", true},
		{"docker image", "mcp/sqlite", true},
		{"suffix dash", "kubectl-mcp", true},
		{"suffix underscore", "github_mcp", true},
		{"suffix server", "postgres-mcp-server", true},
		{"node dist path", "/app/node_modules/@modelcontextprotocol/server-git/dist/index.js", true},
		{"nested pypi path", "/venv/lib/python3.12/site-packages/mcp_server_fetch/__main__.py", true},
		// Flags are not packages: "--no-mcp" must not match the "-mcp" suffix.
		{"long flag", "--no-mcp", false},
		{"short flag", "-mcp", false},
		{"plain word", "mcp", false},
		{"unrelated npm package", "@types/node", false},
		{"unrelated binary", "/usr/bin/curl", false},
		{"empty", "", false},
		{"whitespace", "   ", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMCPServerPackage(tc.arg); got != tc.want {
				t.Errorf("IsMCPServerPackage(%q) = %v, want %v", tc.arg, got, tc.want)
			}
		})
	}
}

func TestIsMCPConfigPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"project config", "/workspace/.mcp.json", true},
		{"home project config", "/home/agent/.mcp.json", true},
		{"claude desktop", "/home/agent/Library/Application Support/Claude/claude_desktop_config.json", true},
		{"cursor", "/home/agent/.cursor/mcp.json", true},
		{"vscode", "/home/agent/.vscode/mcp.json", true},
		{"xdg config", "/home/agent/.config/zed/mcp.json", true},
		{"windsurf", "/root/.windsurf/mcp.json", true},
		{"mixed case", "/home/agent/.CURSOR/MCP.JSON", true},
		// A bare mcp.json outside a known client directory is too generic.
		{"generic path", "/etc/mcp.json", false},
		{"servers json needs a client dir", "/srv/servers.json", false},
		{"servers json in a client dir", "/home/agent/.continue/servers.json", true},
		{"unrelated json", "/etc/kubernetes/kubelet.conf", false},
		{"unrelated dotfile", "/home/agent/.bashrc", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMCPConfigPath(tc.path); got != tc.want {
				t.Errorf("IsMCPConfigPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestDetectMCPStdio is the stdio-launcher table: the highest-value,
// lowest-cost signal in the whole plan (proposal §2.1 class 2b), because it
// needs no network observation at all.
func TestDetectMCPStdio(t *testing.T) {
	cat := DefaultCatalog()
	tests := []struct {
		name     string
		filename string
		argv     []string
		wantPkg  string
		wantOK   bool
	}{
		{
			name:     "npx with the official scope",
			filename: "/usr/local/bin/npx",
			argv:     []string{"npx", "-y", "@modelcontextprotocol/server-git", "--repository", "/repo"},
			wantPkg:  "@modelcontextprotocol/server-git", wantOK: true,
		},
		{
			name:     "npm exec",
			filename: "/usr/local/bin/npm",
			argv:     []string{"npm", "exec", "--", "@modelcontextprotocol/server-filesystem", "/data"},
			wantPkg:  "@modelcontextprotocol/server-filesystem", wantOK: true,
		},
		{
			name:     "uvx",
			filename: "/usr/local/bin/uvx",
			argv:     []string{"uvx", "mcp-server-sqlite", "--db-path", "/data/app.db"},
			wantPkg:  "mcp-server-sqlite", wantOK: true,
		},
		{
			name:     "uv run",
			filename: "/usr/local/bin/uv",
			argv:     []string{"uv", "run", "mcp-server-fetch"},
			wantPkg:  "mcp-server-fetch", wantOK: true,
		},
		{
			name:     "pipx run",
			filename: "/usr/bin/pipx",
			argv:     []string{"pipx", "run", "mcp-server-fetch"},
			wantPkg:  "mcp-server-fetch", wantOK: true,
		},
		{
			name:     "python -m module",
			filename: "/usr/bin/python3",
			argv:     []string{"python3", "-m", "mcp_server_time", "--local-timezone", "UTC"},
			wantPkg:  "mcp_server_time", wantOK: true,
		},
		{
			name:     "python -m dotted package",
			filename: "/usr/bin/python",
			argv:     []string{"python", "-m", "mcp.server.stdio"},
			wantPkg:  "mcp.server.stdio", wantOK: true,
		},
		{
			name:     "node dist entrypoint",
			filename: "/usr/bin/node",
			argv:     []string{"node", "/app/node_modules/@modelcontextprotocol/server-github/dist/index.js"},
			wantPkg:  "/app/node_modules/@modelcontextprotocol/server-github/dist/index.js", wantOK: true,
		},
		{
			name:     "docker run image",
			filename: "/usr/bin/docker",
			argv:     []string{"docker", "run", "-i", "--rm", "mcp/sqlite"},
			wantPkg:  "mcp/sqlite", wantOK: true,
		},
		{
			name:     "direct exec of the server binary",
			filename: "/usr/local/bin/mcp-server-git",
			argv:     []string{"mcp-server-git"},
			wantPkg:  "mcp-server-git", wantOK: true,
		},
		{
			name:     "direct exec of a suffixed binary",
			filename: "/usr/local/bin/github-mcp",
			argv:     nil,
			wantPkg:  "github-mcp", wantOK: true,
		},
		{
			name:     "flags that merely mention mcp do not match",
			filename: "/usr/bin/myagent",
			argv:     []string{"myagent", "--no-mcp", "--mcp-disabled"},
			wantOK:   false,
		},
		{
			name:     "unrelated npx invocation",
			filename: "/usr/local/bin/npx",
			argv:     []string{"npx", "prettier", "--write", "."},
			wantOK:   false,
		},
		{
			name:     "unrelated python module",
			filename: "/usr/bin/python3",
			argv:     []string{"python3", "-m", "http.server"},
			wantOK:   false,
		},
		{
			name:     "-m at the end of argv",
			filename: "/usr/bin/python3",
			argv:     []string{"python3", "-m"},
			wantOK:   false,
		},
		{
			name:     "shell",
			filename: "/bin/sh",
			argv:     []string{"sh", "-c", "echo hi"},
			wantOK:   false,
		},
		{
			name:     "no argv at all",
			filename: "/usr/bin/curl",
			argv:     nil,
			wantOK:   false,
		},
		{
			name:     "empty everything",
			filename: "",
			argv:     []string{"", "  "},
			wantOK:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkg, ok := cat.DetectMCPStdio(tc.filename, tc.argv)
			if ok != tc.wantOK {
				t.Fatalf("DetectMCPStdio() ok = %v, want %v (pkg %q)", ok, tc.wantOK, pkg)
			}
			if pkg != tc.wantPkg {
				t.Errorf("DetectMCPStdio() pkg = %q, want %q", pkg, tc.wantPkg)
			}
		})
	}
}

func TestCatalogIsMCPPath(t *testing.T) {
	cat := DefaultCatalog()
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"mcp", "/mcp", true},
		{"mcp with suffix", "/mcp/v1", true},
		{"sse", "/sse", true},
		{"messages", "/messages", true},
		{"query stripped", "/mcp?session=1", true},
		{"anthropic messages is not an mcp path", "/v1/messages", false},
		{"root", "/", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cat.IsMCPPath(tc.path); got != tc.want {
				t.Errorf("IsMCPPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestClassifyMCPStreamableHTTP exercises the MCP classifier directly, so that
// "not MCP" cases can assert nil even when another class legitimately claims
// the event (cross-class precedence is covered by
// TestClassifyClassPrecedence).
func TestClassifyMCPStreamableHTTP(t *testing.T) {
	cat := DefaultCatalog()

	tests := []struct {
		name string
		ev   *runtimeevent.Event
		want *runtimeevent.AIFacts
	}{
		{
			name: "every signal at once",
			ev: httpEvent("POST", "/mcp", "mcp.example.com", map[string]string{
				"mcp-session-id":       "1866f6a2",
				"mcp-protocol-version": "2025-06-18",
				"accept":               "application/json, text/event-stream",
				"content-type":         "application/json",
			}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`),
			want: &runtimeevent.AIFacts{
				Class:         runtimeevent.AIClassMCP,
				Provider:      ProviderUnknown,
				EndpointKind:  EndpointMCPStreamableHTTP,
				JSONRPCMethod: "tools/call",
				Transport:     TransportSSE,
				Confidence:    99,
				Evidence: []string{
					"header:accept",
					"header:content-type",
					"header:mcp-protocol-version",
					"header:mcp-session-id",
					"host:mcp.example.com",
					"http-method:post",
					"http-path:/mcp",
					"jsonrpc-method:tools/call",
				},
			},
		},
		{
			// MCP-Session-Id is essentially conclusive on its own.
			name: "session header alone",
			ev: httpEvent("POST", "/rpc", "tools.internal", map[string]string{
				"mcp-session-id": "1866f6a2",
			}, ""),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPStreamableHTTP,
				Transport:    TransportHTTP,
				Confidence:   ScoreMCPHeader,
				Evidence: []string{
					"header:mcp-session-id",
					"host:tools.internal",
				},
			},
		},
		{
			name: "protocol version header alone",
			ev: httpEvent("GET", "/rpc", "tools.internal", map[string]string{
				"mcp-protocol-version": "2025-06-18",
			}, ""),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPStreamableHTTP,
				Transport:    TransportHTTP,
				Confidence:   ScoreMCPHeader,
				Evidence: []string{
					"header:mcp-protocol-version",
					"host:tools.internal",
				},
			},
		},
		{
			name: "streamable signature alone",
			ev: httpEvent("POST", "/rpc", "tools.internal", map[string]string{
				"accept":       "application/json, text/event-stream",
				"content-type": "application/json",
			}, ""),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPStreamableHTTP,
				Transport:    TransportSSE,
				Confidence:   ScoreMCPStreamable,
				Evidence: []string{
					"header:accept",
					"header:content-type",
					"host:tools.internal",
					"http-method:post",
				},
			},
		},
		{
			name: "jsonrpc method alone",
			ev: httpEvent("POST", "/rpc", "tools.internal", map[string]string{
				"content-type": "application/json",
			}, `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{}}`),
			want: &runtimeevent.AIFacts{
				Class:         runtimeevent.AIClassMCP,
				Provider:      ProviderUnknown,
				EndpointKind:  EndpointMCPStreamableHTTP,
				JSONRPCMethod: "resources/read",
				Transport:     TransportHTTP,
				Confidence:    ScoreJSONRPCMethod,
				Evidence: []string{
					"host:tools.internal",
					"jsonrpc-method:resources/read",
				},
			},
		},
		{
			name: "initialize handshake",
			ev: httpEvent("POST", "/mcp", "mcp.example.com", map[string]string{
				"content-type": "application/json",
			}, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`),
			want: &runtimeevent.AIFacts{
				Class:         runtimeevent.AIClassMCP,
				Provider:      ProviderUnknown,
				EndpointKind:  EndpointMCPStreamableHTTP,
				JSONRPCMethod: "initialize",
				Transport:     TransportHTTP,
				Confidence:    99,
				Evidence: []string{
					"host:mcp.example.com",
					"http-path:/mcp",
					"jsonrpc-method:initialize",
				},
			},
		},
		{
			name: "conventional path alone is a weak signal",
			ev:   httpEvent("GET", "/sse", "tools.internal", nil, ""),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPStreamableHTTP,
				Transport:    TransportHTTP,
				Confidence:   ScoreMCPPath,
				Evidence: []string{
					"host:tools.internal",
					"http-path:/sse",
				},
			},
		},
		{
			// Streaming LLM requests carry the same Accept/Content-Type pair as
			// MCP streamable HTTP; a known inference endpoint suppresses the
			// signature so every streamed completion is not reported as MCP.
			name: "streaming llm request is not mcp",
			ev: httpEvent("POST", "/v1/chat/completions", "api.openai.com", map[string]string{
				"accept":       "text/event-stream",
				"content-type": "application/json",
			}, `{"model":"gpt-4o","messages":[],"stream":true}`),
			want: nil,
		},
		{
			name: "a2a jsonrpc method is not mcp",
			ev: httpEvent("POST", "/rpc", "peer.internal", map[string]string{
				"content-type": "application/json",
			}, `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}`),
			want: nil,
		},
		{
			name: "plain json post is not mcp",
			ev: httpEvent("POST", "/api/orders", "shop.internal", map[string]string{
				"content-type": "application/json",
			}, `{"sku":"x"}`),
			want: nil,
		},
		{
			name: "sse without json content type is not mcp",
			ev: httpEvent("GET", "/events", "app.internal", map[string]string{
				"accept": "text/event-stream",
			}, ""),
			want: nil,
		},
		{
			name: "http facts missing",
			ev:   &runtimeevent.Event{Kind: runtimeevent.KindHTTP},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, classifyMCP(cat, tc.ev)); diff != "" {
				t.Errorf("classifyMCP() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClassifyMCPStdioFromExec(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())

	tests := []struct {
		name string
		ev   *runtimeevent.Event
		want *runtimeevent.AIFacts
	}{
		{
			name: "npx launcher",
			ev:   execEvent("/usr/local/bin/npx", "npx", "-y", "@modelcontextprotocol/server-git", "--repository", "/repo"),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPStdio,
				Transport:    TransportStdio,
				Confidence:   ScoreExecMCPPackage,
				Evidence: []string{
					"argv:@modelcontextprotocol/server-git",
					"comm:npx",
				},
			},
		},
		{
			name: "uvx launcher",
			ev:   execEvent("/usr/local/bin/uvx", "uvx", "mcp-server-sqlite", "--db-path", "/data/app.db"),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPStdio,
				Transport:    TransportStdio,
				Confidence:   ScoreExecMCPPackage,
				Evidence: []string{
					"argv:mcp-server-sqlite",
					"comm:uvx",
				},
			},
		},
		{
			name: "docker run",
			ev:   execEvent("/usr/bin/docker", "docker", "run", "-i", "--rm", "mcp/sqlite"),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPStdio,
				Transport:    TransportStdio,
				Confidence:   ScoreExecMCPPackage,
				Evidence: []string{
					"argv:mcp/sqlite",
					"comm:docker",
				},
			},
		},
		{
			// No known launcher: the evidence carries the package only.
			name: "direct exec of a server binary",
			ev:   execEvent("/usr/local/bin/mcp-server-git", "mcp-server-git", "--repository", "/repo"),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPStdio,
				Transport:    TransportStdio,
				Confidence:   ScoreExecMCPPackage,
				Evidence:     []string{"argv:mcp-server-git"},
			},
		},
		{
			name: "unrelated exec",
			ev:   execEvent("/usr/bin/curl", "curl", "-sS", "https://api.openai.com/v1/models"),
			want: nil,
		},
		{
			name: "exec facts missing",
			ev:   &runtimeevent.Event{Kind: runtimeevent.KindExec},
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

func TestClassifyMCPConfigDiscoveryFromOpen(t *testing.T) {
	cls := NewClassifier(DefaultCatalog())

	tests := []struct {
		name string
		ev   *runtimeevent.Event
		want *runtimeevent.AIFacts
	}{
		{
			name: "cursor config",
			ev:   openEvent("/home/agent/.cursor/mcp.json"),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPConfig,
				Confidence:   ScoreMCPConfigOpen,
				Evidence:     []string{"file:/home/agent/.cursor/mcp.json"},
			},
		},
		{
			name: "project config",
			ev:   openEvent("/workspace/.mcp.json"),
			want: &runtimeevent.AIFacts{
				Class:        runtimeevent.AIClassMCP,
				Provider:     ProviderUnknown,
				EndpointKind: EndpointMCPConfig,
				Confidence:   ScoreMCPConfigOpen,
				Evidence:     []string{"file:/workspace/.mcp.json"},
			},
		},
		{
			name: "unrelated open",
			ev:   openEvent("/etc/passwd"),
			want: nil,
		},
		{
			name: "open facts missing",
			ev:   &runtimeevent.Event{Kind: runtimeevent.KindOpen},
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

func TestPathBase(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"absolute", "/usr/local/bin/npx", "npx"},
		{"relative", "bin/npx", "npx"},
		{"bare", "npx", "npx"},
		{"trailing slash", "/usr/bin/", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathBase(tc.in); got != tc.want {
				t.Errorf("pathBase(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
