// Package ai classifies normalized runtime events as AI traffic: hosted and
// self-hosted LLM APIs, MCP (streamable HTTP and local stdio) and A2A.
//
// Everything in this package is PURE: no I/O, no network, no clock, no
// goroutines. Classification is a function of the event plus a data-driven
// provider catalog, which makes the whole detection surface table-testable and
// hot-reloadable from a ConfigMap.
//
// Two contracts are load-bearing and enforced by tests:
//
//  1. Evidence tokens name headers, hosts, paths, ports and protocol method
//     names ONLY. A header VALUE — or any body content beyond a bounded,
//     charset-validated model name — must never appear in an AIFacts field.
//  2. Body inspection is a bounded sniff, never a full JSON parse: the
//     classifier reads at most SniffLimit bytes of an already-capped
//     HTTPFacts body preview and rejects anything that does not look like a
//     short, well-shaped identifier.
package ai

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

//go:embed catalog.json
var embeddedCatalog embed.FS

// Provider is one AI endpoint family in the catalog.
type Provider struct {
	// Name is the stable provider identity used by policy
	// ("provider:<name>"), findings, and the inventory.
	Name string `json:"name"`
	// Hostnames are glob patterns ("api.openai.com", "*.openai.azure.com",
	// "bedrock-runtime.*.amazonaws.com"). '*' matches any run of characters.
	Hostnames []string `json:"hostnames"`
	// PathPrefixes attribute a request to this provider by path shape when
	// the hostname is unknown (IP-literal or private DNS).
	PathPrefixes []string `json:"pathPrefixes,omitempty"`
	// HeaderNames are provider-distinctive request header NAMES.
	HeaderNames []string `json:"headerNames,omitempty"`
	// Ports are the conventional plaintext ports of self-hosted deployments.
	Ports []uint16 `json:"ports,omitempty"`
	// SelfHosted marks in-cluster / on-host inference servers.
	SelfHosted bool `json:"selfHosted,omitempty"`
	// Sanctioned lets an operator mark a provider as approved via the
	// catalog ConfigMap. The shipped catalog marks nothing sanctioned:
	// kyverno-runtime has no opinion about which providers a cluster allows.
	Sanctioned bool `json:"sanctioned,omitempty"`
}

// EndpointPattern maps an HTTP path glob to an endpoint kind.
type EndpointPattern struct {
	Pattern string `json:"pattern"`
	Kind    string `json:"kind"`
}

// MCPRules holds the MCP recognition tables.
type MCPRules struct {
	MethodPrefixes []string `json:"methodPrefixes,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	PathPrefixes   []string `json:"pathPrefixes,omitempty"`
	HeaderNames    []string `json:"headerNames,omitempty"`
	// PackagePrefixes/Suffixes/Contains recognize stdio server packages in
	// exec argv.
	PackagePrefixes []string `json:"packagePrefixes,omitempty"`
	PackageSuffixes []string `json:"packageSuffixes,omitempty"`
	PackageContains []string `json:"packageContains,omitempty"`
	// PythonModulePrefixes match the argument after "python -m".
	PythonModulePrefixes []string `json:"pythonModulePrefixes,omitempty"`
	// Launchers are the process names that commonly start stdio servers.
	Launchers []string `json:"launchers,omitempty"`
	// ConfigFiles are basenames that identify an MCP client config anywhere.
	ConfigFiles []string `json:"configFiles,omitempty"`
	// ConfigDirFiles are basenames that only count inside a ConfigDirs path.
	ConfigDirFiles []string `json:"configDirFiles,omitempty"`
	ConfigDirs     []string `json:"configDirs,omitempty"`
}

// A2ARules holds the A2A recognition tables.
type A2ARules struct {
	PathPrefixes   []string `json:"pathPrefixes,omitempty"`
	MethodPrefixes []string `json:"methodPrefixes,omitempty"`
	Methods        []string `json:"methods,omitempty"`
}

// catalogFile is the on-disk / ConfigMap shape of the catalog.
type catalogFile struct {
	Providers    []Provider        `json:"providers"`
	LLMEndpoints []EndpointPattern `json:"llmEndpoints"`
	MCP          MCPRules          `json:"mcp"`
	A2A          A2ARules          `json:"a2a"`
}

// Catalog is an immutable, precomputed view of the provider data. Build it
// with DefaultCatalog or LoadCatalog and treat it as read-only: hot reload
// swaps the pointer (see Classifier.SetCatalog) rather than mutating it, so
// concurrent classification needs no locking.
type Catalog struct {
	providers []Provider

	// hostExact maps a literal hostname to its provider index; hostGlobs
	// keeps the patterns containing wildcards, in catalog order.
	hostExact map[string]int
	hostGlobs []hostGlob

	// headerIndex maps a lowercased header name to a provider name.
	headerIndex map[string]string
	// portIndex maps a self-hosted port to a provider index.
	portIndex map[uint16]int
	// pathPrefixes are (prefix, provider index) pairs in catalog order.
	pathPrefixes []pathPrefix

	llmEndpoints []EndpointPattern

	mcp MCPRules
	a2a A2ARules
}

type hostGlob struct {
	pattern string
	idx     int
}

type pathPrefix struct {
	prefix string
	idx    int
}

var defaultCatalog = sync.OnceValues(func() (*Catalog, error) {
	data, err := embeddedCatalog.ReadFile("catalog.json")
	if err != nil {
		return nil, fmt.Errorf("reading embedded catalog: %w", err)
	}
	return LoadCatalog(data)
})

// DefaultCatalog returns the catalog embedded in the binary. The returned
// value is shared and immutable.
//
// It panics only if the embedded catalog.json — compile-time data owned by
// this repository, never user input — fails to parse; TestDefaultCatalog
// makes that unreachable in a released binary.
func DefaultCatalog() *Catalog {
	cat, err := defaultCatalog()
	if err != nil {
		panic("ai: embedded catalog.json is invalid: " + err.Error())
	}
	return cat
}

// LoadCatalog parses a catalog payload (the ai-provider-catalog ConfigMap key)
// and precomputes its lookup tables. A provider with no name or no hostnames,
// or an endpoint with no pattern or kind, is rejected: a silently ignored
// catalog entry would read as "no AI traffic".
func LoadCatalog(data []byte) (*Catalog, error) {
	var f catalogFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parsing ai provider catalog: %w", err)
	}
	if len(f.Providers) == 0 {
		return nil, fmt.Errorf("parsing ai provider catalog: no providers")
	}

	c := &Catalog{
		providers:   make([]Provider, 0, len(f.Providers)),
		hostExact:   make(map[string]int, len(f.Providers)*2),
		headerIndex: make(map[string]string),
		portIndex:   make(map[uint16]int),
	}

	seen := make(map[string]struct{}, len(f.Providers))
	for i, p := range f.Providers {
		p.Name = strings.ToLower(strings.TrimSpace(p.Name))
		if p.Name == "" {
			return nil, fmt.Errorf("parsing ai provider catalog: provider %d has no name", i)
		}
		if _, dup := seen[p.Name]; dup {
			return nil, fmt.Errorf("parsing ai provider catalog: duplicate provider %q", p.Name)
		}
		seen[p.Name] = struct{}{}
		if len(p.Hostnames) == 0 {
			return nil, fmt.Errorf("parsing ai provider catalog: provider %q has no hostnames", p.Name)
		}

		idx := len(c.providers)
		for _, h := range p.Hostnames {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if strings.ContainsAny(h, "*?") {
				c.hostGlobs = append(c.hostGlobs, hostGlob{pattern: h, idx: idx})
				continue
			}
			if _, ok := c.hostExact[h]; !ok {
				c.hostExact[h] = idx
			}
		}
		for _, h := range p.HeaderNames {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if _, ok := c.headerIndex[h]; !ok {
				c.headerIndex[h] = p.Name
			}
		}
		for _, port := range p.Ports {
			if port == 0 {
				continue
			}
			if _, ok := c.portIndex[port]; !ok {
				c.portIndex[port] = idx
			}
		}
		for _, pre := range p.PathPrefixes {
			pre = strings.TrimSpace(pre)
			if pre == "" {
				continue
			}
			c.pathPrefixes = append(c.pathPrefixes, pathPrefix{prefix: pre, idx: idx})
		}
		c.providers = append(c.providers, p)
	}

	for i, e := range f.LLMEndpoints {
		e.Pattern = strings.TrimSpace(e.Pattern)
		e.Kind = strings.TrimSpace(e.Kind)
		if e.Pattern == "" || e.Kind == "" {
			return nil, fmt.Errorf("parsing ai provider catalog: llmEndpoints[%d] needs both pattern and kind", i)
		}
		c.llmEndpoints = append(c.llmEndpoints, e)
	}

	c.mcp = normalizeMCP(f.MCP)
	c.a2a = normalizeA2A(f.A2A)
	return c, nil
}

func normalizeMCP(r MCPRules) MCPRules {
	r.HeaderNames = lowerAll(r.HeaderNames)
	r.Launchers = lowerAll(r.Launchers)
	r.ConfigFiles = lowerAll(r.ConfigFiles)
	r.ConfigDirFiles = lowerAll(r.ConfigDirFiles)
	r.ConfigDirs = lowerAll(r.ConfigDirs)
	return r
}

// normalizeA2A trims but does NOT lowercase: A2A method names are
// case-sensitive ("agent/getAuthenticatedExtendedCard").
func normalizeA2A(r A2ARules) A2ARules {
	r.PathPrefixes = trimAll(r.PathPrefixes)
	r.MethodPrefixes = trimAll(r.MethodPrefixes)
	r.Methods = trimAll(r.Methods)
	return r
}

func trimAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func lowerAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Providers returns a copy of the provider list, in catalog order.
func (c *Catalog) Providers() []Provider {
	if c == nil {
		return nil
	}
	out := make([]Provider, len(c.providers))
	copy(out, c.providers)
	return out
}

// Provider looks a provider up by name.
func (c *Catalog) Provider(name string) (Provider, bool) {
	if c == nil {
		return Provider{}, false
	}
	name = strings.ToLower(strings.TrimSpace(name))
	for _, p := range c.providers {
		if p.Name == name {
			return p, true
		}
	}
	return Provider{}, false
}

// MCP returns the MCP recognition rules. The returned slices belong to the
// catalog and must be treated as read-only.
func (c *Catalog) MCP() MCPRules {
	if c == nil {
		return MCPRules{}
	}
	return c.mcp
}

// A2A returns the A2A recognition rules. The returned slices belong to the
// catalog and must be treated as read-only.
func (c *Catalog) A2A() A2ARules {
	if c == nil {
		return A2ARules{}
	}
	return c.a2a
}

// NormalizeHost lowercases a host, drops a trailing dot and strips any port or
// IPv6 brackets, so "API.OpenAI.com:443" and "api.openai.com." both match.
func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	if h, ok := stripBracketedHost(host); ok {
		host = h
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 && strings.IndexByte(host, ':') == i {
		// Exactly one colon: host:port, not a bare IPv6 literal.
		if _, err := strconv.ParseUint(host[i+1:], 10, 16); err == nil {
			host = host[:i]
		}
	}
	return strings.TrimSuffix(host, ".")
}

// HostPort returns the port embedded in a Host header value, or 0.
func HostPort(host string) uint16 {
	host = strings.TrimSpace(host)
	if host == "" {
		return 0
	}
	if i := strings.LastIndexByte(host, ']'); i >= 0 {
		if i+1 < len(host) && host[i+1] == ':' {
			return parsePort(host[i+2:])
		}
		return 0
	}
	i := strings.LastIndexByte(host, ':')
	if i < 0 || strings.IndexByte(host, ':') != i {
		return 0
	}
	return parsePort(host[i+1:])
}

func parsePort(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// stripBracketedHost extracts the literal from "[::1]" / "[::1]:8000".
func stripBracketedHost(host string) (string, bool) {
	if !strings.HasPrefix(host, "[") {
		return "", false
	}
	i := strings.IndexByte(host, ']')
	if i < 0 {
		return "", false
	}
	return host[1:i], true
}

// MatchHost resolves a hostname (or SNI, or DNS question name) to a provider.
func (c *Catalog) MatchHost(host string) (Provider, bool) {
	if c == nil {
		return Provider{}, false
	}
	h := NormalizeHost(host)
	if h == "" {
		return Provider{}, false
	}
	if idx, ok := c.hostExact[h]; ok {
		return c.providers[idx], true
	}
	for _, g := range c.hostGlobs {
		if MatchGlob(g.pattern, h) {
			return c.providers[g.idx], true
		}
	}
	return Provider{}, false
}

// NormalizePath strips a query string / fragment and a single trailing slash.
func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

// LLMEndpoint maps a request path to an inference endpoint kind. Patterns are
// globs matched against the whole (query-stripped) path, so "/v1/messages" is
// exact while "/model/*/invoke" and "/v1beta/models/*:generateContent" accept
// any model identifier.
func (c *Catalog) LLMEndpoint(path string) (string, bool) {
	if c == nil {
		return "", false
	}
	p := NormalizePath(path)
	if p == "" {
		return "", false
	}
	for _, e := range c.llmEndpoints {
		if MatchGlob(e.Pattern, p) {
			return e.Kind, true
		}
	}
	return "", false
}

// MatchHeader resolves a provider-distinctive request header NAME to a
// provider name. Only the name is ever consulted; header values do not enter
// this package.
func (c *Catalog) MatchHeader(name string) (string, bool) {
	if c == nil {
		return "", false
	}
	p, ok := c.headerIndex[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// MatchPort resolves a conventional self-hosted inference port to a provider.
func (c *Catalog) MatchPort(port uint16) (Provider, bool) {
	if c == nil || port == 0 {
		return Provider{}, false
	}
	if idx, ok := c.portIndex[port]; ok {
		return c.providers[idx], true
	}
	return Provider{}, false
}

// MatchPathProvider attributes a request to a provider by path shape, for the
// IP-literal / private-DNS case where the hostname says nothing.
func (c *Catalog) MatchPathProvider(path string) (Provider, bool) {
	if c == nil {
		return Provider{}, false
	}
	p := NormalizePath(path)
	if p == "" {
		return Provider{}, false
	}
	for _, pre := range c.pathPrefixes {
		if strings.HasPrefix(p, pre.prefix) {
			return c.providers[pre.idx], true
		}
	}
	return Provider{}, false
}

// MatchGlob reports whether s matches pattern, where '*' matches any run of
// characters (including none) and '?' matches exactly one character. The
// implementation is iterative with backtracking, so it neither recurses nor
// compiles a regexp on a hot path, and it cannot panic on any input.
func MatchGlob(pattern, s string) bool {
	var (
		p, i       int
		star       = -1
		startMatch int
	)
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star = p
			startMatch = i
			p++
		case star >= 0:
			// Backtrack: let the last '*' consume one more character.
			p = star + 1
			startMatch++
			i = startMatch
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
