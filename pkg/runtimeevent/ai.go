package runtimeevent

// AIClass is the family of AI traffic an event belongs to.
type AIClass string

const (
	// AIClassLLM is direct inference-API traffic (hosted or self-hosted).
	AIClassLLM AIClass = "llm"
	// AIClassMCP is Model Context Protocol traffic (streamable HTTP or stdio).
	AIClassMCP AIClass = "mcp"
	// AIClassA2A is Agent-to-Agent protocol traffic.
	AIClassA2A AIClass = "a2a"
)

// AIFacts is the classifier's verdict for an Event, attached as Event.AI by
// pkg/detect/ai. It is derived state: nothing here is read from the kernel.
//
// Evidence tokens carry names, hosts, paths, ports and protocol method names
// ONLY — never a header value, never body content. That is a hard contract of
// the classifier (see pkg/detect/ai and DESIGN §3.1/§4): every field of this
// struct ends up in an OpenReports Report or an AIInventory, so a value that
// cannot be represented here cannot leak.
type AIFacts struct {
	// Class is the traffic family: llm, mcp or a2a.
	Class AIClass `json:"class"`
	// Provider is the catalog provider name ("anthropic", "openai",
	// "azure-openai", ...), "self-hosted" for an unrecognised
	// OpenAI-compatible endpoint, or empty when unknown.
	Provider string `json:"provider,omitempty"`
	// Model is the requested model, only ever available when a plaintext
	// body preview was observed.
	Model string `json:"model,omitempty"`
	// EndpointKind names the API shape: "messages", "chat.completions",
	// "generateContent", "mcp.streamable-http", "mcp.stdio",
	// "a2a.agent-card", "a2a.jsonrpc", ...
	EndpointKind string `json:"endpointKind,omitempty"`
	// JSONRPCMethod is the sniffed JSON-RPC method name, when present.
	JSONRPCMethod string `json:"jsonrpcMethod,omitempty"`
	// Transport is "https", "http", "stdio" or "sse"; empty when the
	// observation carries no transport information (DNS, file open).
	Transport string `json:"transport,omitempty"`
	// Confidence is 0-100. See pkg/detect/ai/confidence.go for the table.
	Confidence int `json:"confidence"`
	// Evidence holds the signals that produced this verdict, as
	// "<prefix>:<name>" tokens: "dns:api.openai.com", "sni:api.openai.com",
	// "http-path:/v1/messages", "header:anthropic-version", "port:11434",
	// "argv:@modelcontextprotocol/server-git", "body-shape:model+messages".
	// Header tokens name the header and never its value.
	Evidence []string `json:"evidence,omitempty"`
	// Sanctioned reports whether the matched provider is marked sanctioned
	// in the provider catalog.
	Sanctioned bool `json:"sanctioned,omitempty"`
}

// Clone returns a deep copy so sinks can retain facts without aliasing the
// evidence slice of a live event.
func (f *AIFacts) Clone() *AIFacts {
	if f == nil {
		return nil
	}
	out := *f
	if f.Evidence != nil {
		out.Evidence = make([]string, len(f.Evidence))
		copy(out.Evidence, f.Evidence)
	}
	return &out
}
