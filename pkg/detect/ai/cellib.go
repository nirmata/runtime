package ai

import (
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// LibraryName is the CEL library name of the `ai` lib.
const LibraryName = "kyverno.ai"

// celLib exposes the provider catalog to CEL as a small set of pure functions
// on the `ai` namespace, so a policy author never has to inline provider
// regexes: provider coverage stays data (a hot-reloadable ConfigMap) rather
// than being copied into every RuntimePolicy.
//
// Every binding is a pure catalog lookup: no I/O, no allocation beyond the
// result, no panic on any input (a non-string argument yields a CEL error, not
// a crash). The lib is safe to register in the per-event environment, which is
// the whole point of keeping it separate from `http`/`resource`/`json`.
type celLib struct {
	cat *Catalog
}

// Lib returns the cel.EnvOption registering the `ai` functions:
//
//	ai.isProvider(host, provider) -> bool
//	ai.provider(host)             -> string   ("" when unknown)
//	ai.isLLMPath(path)            -> bool
//	ai.isMCPMethod(method)        -> bool
//	ai.isA2AMethod(method)        -> bool
//	ai.isMCPServerPackage(arg)    -> bool
//
// A nil catalog falls back to the embedded default: a missing catalog must
// never silently turn every lookup into false.
func Lib(cat *Catalog) cel.EnvOption {
	if cat == nil {
		cat = DefaultCatalog()
	}
	return cel.Lib(&celLib{cat: cat})
}

func (*celLib) LibraryName() string { return LibraryName }

func (l *celLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("ai.isProvider",
			cel.Overload("ai_isProvider_string_string_bool",
				[]*cel.Type{types.StringType, types.StringType}, types.BoolType,
				cel.BinaryBinding(l.isProvider),
			),
		),
		cel.Function("ai.provider",
			cel.Overload("ai_provider_string_string",
				[]*cel.Type{types.StringType}, types.StringType,
				cel.UnaryBinding(l.provider),
			),
		),
		cel.Function("ai.isLLMPath",
			cel.Overload("ai_isLLMPath_string_bool",
				[]*cel.Type{types.StringType}, types.BoolType,
				cel.UnaryBinding(l.isLLMPath),
			),
		),
		cel.Function("ai.isMCPMethod",
			cel.Overload("ai_isMCPMethod_string_bool",
				[]*cel.Type{types.StringType}, types.BoolType,
				cel.UnaryBinding(l.isMCPMethod),
			),
		),
		cel.Function("ai.isA2AMethod",
			cel.Overload("ai_isA2AMethod_string_bool",
				[]*cel.Type{types.StringType}, types.BoolType,
				cel.UnaryBinding(l.isA2AMethod),
			),
		),
		cel.Function("ai.isMCPServerPackage",
			cel.Overload("ai_isMCPServerPackage_string_bool",
				[]*cel.Type{types.StringType}, types.BoolType,
				cel.UnaryBinding(l.isMCPServerPackage),
			),
		),
	}
}

func (*celLib) ProgramOptions() []cel.ProgramOption { return nil }

// isProvider reports whether host belongs to the named catalog provider.
func (l *celLib) isProvider(hostVal, providerVal ref.Val) ref.Val {
	host, err := celString(hostVal)
	if err != nil {
		return err
	}
	want, err := celString(providerVal)
	if err != nil {
		return err
	}
	p, ok := l.cat.MatchHost(host)
	if !ok {
		return types.False
	}
	return types.Bool(p.Name == strings.ToLower(strings.TrimSpace(want)))
}

// provider resolves a host to its catalog provider name, "" when unknown.
func (l *celLib) provider(hostVal ref.Val) ref.Val {
	host, err := celString(hostVal)
	if err != nil {
		return err
	}
	p, ok := l.cat.MatchHost(host)
	if !ok {
		return types.String("")
	}
	return types.String(p.Name)
}

// isLLMPath reports whether path matches a known inference endpoint shape.
func (l *celLib) isLLMPath(pathVal ref.Val) ref.Val {
	path, err := celString(pathVal)
	if err != nil {
		return err
	}
	_, ok := l.cat.LLMEndpoint(path)
	return types.Bool(ok)
}

// isMCPMethod reports whether method sits in the MCP JSON-RPC namespace.
func (l *celLib) isMCPMethod(methodVal ref.Val) ref.Val {
	method, err := celString(methodVal)
	if err != nil {
		return err
	}
	return types.Bool(l.cat.IsMCPMethod(method))
}

// isA2AMethod reports whether method sits in the A2A JSON-RPC namespace.
func (l *celLib) isA2AMethod(methodVal ref.Val) ref.Val {
	method, err := celString(methodVal)
	if err != nil {
		return err
	}
	return types.Bool(l.cat.IsA2AMethod(method))
}

// isMCPServerPackage reports whether arg names a stdio MCP server package.
func (l *celLib) isMCPServerPackage(argVal ref.Val) ref.Val {
	arg, err := celString(argVal)
	if err != nil {
		return err
	}
	return types.Bool(l.cat.IsMCPServerPackage(arg))
}

// celString extracts a Go string from a CEL value, returning a CEL error value
// (never a panic) when the argument is not a string.
func celString(v ref.Val) (string, ref.Val) {
	s, ok := v.(types.String)
	if !ok {
		return "", types.MaybeNoSuchOverloadErr(v)
	}
	return string(s), nil
}
