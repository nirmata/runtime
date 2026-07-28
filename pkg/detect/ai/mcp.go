package ai

import (
	"strings"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
)

// MCP endpoint kinds.
const (
	EndpointMCPStreamableHTTP = "mcp.streamable-http"
	EndpointMCPStdio          = "mcp.stdio"
	EndpointMCPConfig         = "mcp.config"
)

// IsMCPMethod reports whether method is a JSON-RPC method in the MCP
// namespace ("tools/", "resources/", "prompts/", "sampling/", "roots/",
// "notifications/", "completion/", "logging/", "elicitation/", or
// "initialize"). It uses the embedded default catalog; use the Catalog method
// to honour a hot-reloaded catalog.
func IsMCPMethod(method string) bool { return DefaultCatalog().IsMCPMethod(method) }

// IsMCPServerPackage reports whether arg names a stdio MCP server package.
func IsMCPServerPackage(arg string) bool { return DefaultCatalog().IsMCPServerPackage(arg) }

// IsMCPConfigPath reports whether path is an MCP client configuration file.
func IsMCPConfigPath(path string) bool { return DefaultCatalog().IsMCPConfigPath(path) }

// IsMCPMethod reports whether method sits in the MCP method namespace.
func (c *Catalog) IsMCPMethod(method string) bool {
	if c == nil || method == "" {
		return false
	}
	for _, m := range c.mcp.Methods {
		if method == m {
			return true
		}
	}
	for _, p := range c.mcp.MethodPrefixes {
		if strings.HasPrefix(method, p) {
			return true
		}
	}
	return false
}

// IsMCPPath reports whether path is a conventional MCP endpoint path. This is
// a weak signal on its own (see ScoreMCPPath).
func (c *Catalog) IsMCPPath(path string) bool {
	if c == nil {
		return false
	}
	p := NormalizePath(path)
	if p == "" {
		return false
	}
	for _, pre := range c.mcp.PathPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// IsMCPServerPackage reports whether arg names a stdio MCP server package
// ("@modelcontextprotocol/server-git", "mcp-server-sqlite", "kubectl-mcp",
// "mcp/sqlite", or any path containing "modelcontextprotocol"). Flags are
// never packages, so "--no-mcp" cannot match the "-mcp" suffix rule.
func (c *Catalog) IsMCPServerPackage(arg string) bool {
	if c == nil {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(arg))
	if a == "" || strings.HasPrefix(a, "-") {
		return false
	}
	for _, p := range c.mcp.PackagePrefixes {
		if strings.HasPrefix(a, strings.ToLower(p)) {
			return true
		}
	}
	for _, s := range c.mcp.PackageSuffixes {
		if strings.HasSuffix(a, strings.ToLower(s)) {
			return true
		}
	}
	for _, s := range c.mcp.PackageContains {
		if strings.Contains(a, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// IsMCPConfigPath reports whether path is an MCP client configuration file:
// a distinctive basename anywhere (".mcp.json", "claude_desktop_config.json")
// or a generic one inside a known client config directory
// (".cursor/mcp.json", "~/.config/<client>/mcp.json").
func (c *Catalog) IsMCPConfigPath(path string) bool {
	if c == nil {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return false
	}
	b := pathBase(p)
	for _, f := range c.mcp.ConfigFiles {
		if b == f {
			return true
		}
	}
	for _, f := range c.mcp.ConfigDirFiles {
		if b != f {
			continue
		}
		for _, d := range c.mcp.ConfigDirs {
			if strings.Contains(p, d) {
				return true
			}
		}
	}
	return false
}

// isMCPLauncher reports whether name is a process that commonly starts stdio
// MCP servers. Used for evidence only: it never contributes confidence.
func (c *Catalog) isMCPLauncher(name string) bool {
	if c == nil {
		return false
	}
	name = strings.ToLower(name)
	for _, l := range c.mcp.Launchers {
		if name == l {
			return true
		}
	}
	return false
}

// DetectMCPStdio inspects an exec observation for a local (stdio) MCP server
// launch and returns the package token that matched.
//
// It covers the launcher shapes seen in the wild: `npx -y
// @modelcontextprotocol/server-git`, `uvx mcp-server-sqlite`, `pipx run
// mcp-server-fetch`, `python -m mcp_server_time`, `node
// .../@modelcontextprotocol/server-git/dist/index.js`, `docker run mcp/sqlite`,
// and a direct exec of the server binary itself.
func (c *Catalog) DetectMCPStdio(filename string, argv []string) (string, bool) {
	if c == nil {
		return "", false
	}
	if b := pathBase(filename); c.IsMCPServerPackage(b) {
		return b, true
	}
	if c.IsMCPServerPackage(filename) {
		return filename, true
	}
	for i, a := range argv {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			// `python -m <module>`: the module name follows the flag.
			if a == "-m" && i+1 < len(argv) && c.isPythonMCPModule(argv[i+1]) {
				return strings.TrimSpace(argv[i+1]), true
			}
			continue
		}
		if c.IsMCPServerPackage(a) {
			return a, true
		}
		if b := pathBase(a); c.IsMCPServerPackage(b) {
			return b, true
		}
	}
	return "", false
}

// isPythonMCPModule reports whether mod is an MCP python module name.
func (c *Catalog) isPythonMCPModule(mod string) bool {
	mod = strings.ToLower(strings.TrimSpace(mod))
	if mod == "" {
		return false
	}
	for _, p := range c.mcp.PythonModulePrefixes {
		if strings.HasPrefix(mod, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// classifyMCP looks for MCP traffic in ev, over HTTP (streamable), exec
// (stdio) or file open (client configuration discovery).
func classifyMCP(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	switch ev.Kind {
	case runtimeevent.KindHTTP:
		return mcpFromHTTP(cat, ev)
	case runtimeevent.KindExec:
		return mcpFromExec(cat, ev)
	case runtimeevent.KindOpen:
		return mcpFromOpen(cat, ev)
	default:
		return nil
	}
}

func mcpFromHTTP(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	h := ev.HTTP
	if h == nil {
		return nil
	}
	var sig signals

	// MCP-Session-Id / MCP-Protocol-Version are essentially conclusive. Only
	// the presence of the header, and its name, are ever used.
	for _, name := range cat.mcp.HeaderNames {
		if h.Header(name) != "" {
			sig.add(ScoreMCPHeader, Token(EvidenceHeader, name))
		}
	}

	var method string
	if m, ok := SniffJSONRPCMethod(h.BodyPreview(), SniffLimit); ok && cat.IsMCPMethod(m) {
		method = m
		sig.add(ScoreJSONRPCMethod, Token(EvidenceJSONRPC, m))
	}

	// The streamable-HTTP signature: POST + Accept: text/event-stream +
	// Content-Type: application/json. Streaming LLM requests carry the very
	// same pair, so a known inference endpoint suppresses this signal rather
	// than every streamed completion being reported as MCP.
	if strings.EqualFold(h.Method(), "POST") && acceptsEventStream(h) && hasJSONContentType(h) {
		if _, isLLM := cat.LLMEndpoint(h.Path()); !isLLM {
			sig.add(ScoreMCPStreamable,
				Token(EvidenceMethod, "post"),
				Token(EvidenceHeader, "accept"),
				Token(EvidenceHeader, "content-type"),
			)
		}
	}

	if cat.IsMCPPath(h.Path()) {
		sig.add(ScoreMCPPath, Token(EvidencePath, NormalizePath(h.Path())))
	}

	if sig.empty() {
		return nil
	}
	if host := NormalizeHost(h.Host()); host != "" {
		sig.add(0, Token(EvidenceHost, host))
	}

	return &runtimeevent.AIFacts{
		Class:         runtimeevent.AIClassMCP,
		Provider:      ProviderUnknown,
		EndpointKind:  EndpointMCPStreamableHTTP,
		JSONRPCMethod: method,
		Transport:     httpTransport(h),
		Confidence:    sig.confidence(),
		Evidence:      sig.tokens(),
	}
}

func mcpFromExec(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	if ev.Exec == nil {
		return nil
	}
	pkg, ok := cat.DetectMCPStdio(ev.Exec.Filename, ev.Exec.Argv)
	if !ok {
		return nil
	}
	var sig signals
	sig.add(ScoreExecMCPPackage, Token(EvidenceArgv, pkg))
	if launcher := pathBase(ev.Exec.Filename); cat.isMCPLauncher(launcher) {
		sig.add(0, Token(EvidenceComm, launcher))
	}
	return &runtimeevent.AIFacts{
		Class:        runtimeevent.AIClassMCP,
		Provider:     ProviderUnknown,
		EndpointKind: EndpointMCPStdio,
		Transport:    TransportStdio,
		Confidence:   sig.confidence(),
		Evidence:     sig.tokens(),
	}
}

func mcpFromOpen(cat *Catalog, ev *runtimeevent.Event) *runtimeevent.AIFacts {
	if ev.Open == nil || !cat.IsMCPConfigPath(ev.Open.Path) {
		return nil
	}
	var sig signals
	sig.add(ScoreMCPConfigOpen, Token(EvidenceFile, ev.Open.Path))
	return &runtimeevent.AIFacts{
		Class:        runtimeevent.AIClassMCP,
		Provider:     ProviderUnknown,
		EndpointKind: EndpointMCPConfig,
		Confidence:   sig.confidence(),
		Evidence:     sig.tokens(),
	}
}

// pathBase returns the last '/'-separated element of p.
func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
