package compiler

import (
	"fmt"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/detect/ai"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/dynamic"
)

var (
	variablesKey = "variables"
)

type CompiledRuntimePolicy struct {
	ReevalInterval *time.Duration
	UID            string
	Name           string
	mode           string

	variables map[string]cel.Program
	selector  *metav1.LabelSelector

	// these are the hardcoded values in the api spec
	compiledNets  []*compiledBehavior
	compiledOpens []*compiledBehavior
	compiledExecs []*compiledBehavior
	compiledAIs   []*compiledAIBehavior
}

type compiledBehavior struct {
	denyProg  cel.Program
	allowProg cel.Program
	pair      *AllowDenyPair
}

// compiledAIBehavior is a compiled `ai` behavior. Its allow/deny targets reuse
// compiledBehavior verbatim -- the same policy-time list(string) machinery as
// network/exec/open, so `values` ∪ `expression` semantics are identical for the
// author -- while `match` compiles into a per-event predicate.
type compiledAIBehavior struct {
	behavior      *compiledBehavior
	classes       []string
	match         *EventPredicate
	minConfidence int32
	severity      string
}

type compiler struct {
	env *cel.Env
	// eventEnv is the I/O-free per-event env used by `match` expressions.
	eventEnv *cel.Env
	metrics  *metrics.Metrics
}

// Option configures a Compiler.
type Option func(*compilerOptions)

type compilerOptions struct {
	catalog *ai.Catalog
	metrics *metrics.Metrics
}

// WithCatalog sets the AI provider catalog backing the `ai` CEL lib in the
// per-event environment. A nil catalog (or no option) uses the embedded
// default.
func WithCatalog(cat *ai.Catalog) Option {
	return func(o *compilerOptions) { o.catalog = cat }
}

// WithMetrics records per-event predicate failures in
// PolicyEvalErrors{stage:"predicate"}.
func WithMetrics(m *metrics.Metrics) Option {
	return func(o *compilerOptions) { o.metrics = m }
}

func NewCompiler(client dynamic.Interface, opts ...Option) (Compiler, error) {
	var o compilerOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	base, err := newEnv(client)
	if err != nil {
		return nil, err
	}

	provider := newVariablesProvider(base.CELTypeProvider())
	env, err := base.Extend(
		cel.Variable(variablesKey, VariablesType),
		cel.CustomTypeProvider(provider),
	)
	if err != nil {
		return nil, err
	}

	eventEnv, err := newEventEnv(o.catalog)
	if err != nil {
		return nil, err
	}
	return &compiler{env: env, eventEnv: eventEnv, metrics: o.metrics}, nil
}

func (c *compiler) Compile(rp v1alpha1.RuntimePolicy) (*CompiledRuntimePolicy, error) {
	variables, err := c.compileVariables(rp, c.env, c.env.CELTypeProvider())
	if err != nil {
		return nil, err
	}

	compiledNets := []*compiledBehavior{}
	compiledOpens := []*compiledBehavior{}
	compiledExecs := []*compiledBehavior{}
	compiledAIs := []*compiledAIBehavior{}

	// we use the path to propagate errors with context on which field's compilation errored
	path := field.NewPath("spec").Child("behaviors")

	for i, b := range rp.Spec.Behaviors {
		if b.Network != nil {
			errPath := path.Index(i).Child("network")
			// hardcoded network targets are validated at compile time so an
			// unsupported literal is rejected loudly instead of being dropped
			// silently when it reaches the BPF maps.
			if errs := validateNetworkBehavior(errPath, b.Network); len(errs) != 0 {
				return nil, errs.ToAggregate()
			}
			compiledNet, err := c.compileBehavior(b.Network)
			if err != nil {
				return nil, field.Invalid(errPath, b.Network, err.Error())
			}

			compiledNets = append(compiledNets, compiledNet)
		}
		if b.Exec != nil {
			compiledExec, err := c.compileBehavior(b.Exec)
			if err != nil {
				errPath := path.Index(i).Child("exec")
				return nil, field.Invalid(errPath, b.Exec, err.Error())
			}

			compiledExecs = append(compiledExecs, compiledExec)
		}
		if b.Open != nil {
			compiledOpen, err := c.compileBehavior(b.Open)
			if err != nil {
				errPath := path.Index(i).Child("open")
				return nil, field.Invalid(errPath, b.Open, err.Error())
			}

			compiledOpens = append(compiledOpens, compiledOpen)
		}
		if b.AI != nil {
			errPath := path.Index(i).Child("ai")
			compiledAI, err := c.compileAIBehavior(errPath, b.AI, rp.Name)
			if err != nil {
				return nil, err
			}

			compiledAIs = append(compiledAIs, compiledAI)
		}
	}

	evalIntval := time.Duration(0)
	if rp.Spec.EvaluationInterval != nil {
		evalIntval = rp.Spec.EvaluationInterval.Duration
	}

	mode := ""
	if rp.Spec.Mode != nil {
		mode = string(*rp.Spec.Mode)
	}

	return &CompiledRuntimePolicy{
		UID:            string(rp.UID),
		Name:           rp.Name,
		ReevalInterval: &evalIntval,
		selector:       rp.Spec.PodSelector,
		mode:           mode,
		compiledNets:   compiledNets,
		compiledOpens:  compiledOpens,
		compiledExecs:  compiledExecs,
		compiledAIs:    compiledAIs,
		variables:      variables,
	}, nil
}

// compileAIBehavior compiles an `ai` behavior. Allow/deny go through the
// existing policy-time machinery (compileBehavior); only `match` uses the
// per-event env. An `ai` behavior in an `enforce` policy compiles normally --
// the DOWNGRADE to monitor semantics belongs to the detection engine, which
// also raises the AIEnforcementImplemented=False condition, so the policy is
// never silently ignored here.
func (c *compiler) compileAIBehavior(path *field.Path, b *v1alpha1.AIBehavior, policy string) (*compiledAIBehavior, error) {
	// AI targets are destination identities (hostname globs, "provider:x",
	// "mcp-server:y", IPv4/CIDR), so validateNetworkBehavior deliberately does
	// NOT apply: rejecting a hostname here would reject the common case.
	behavior, err := c.compileBehavior(&v1alpha1.Behavior{Allow: b.Allow, Deny: b.Deny})
	if err != nil {
		return nil, field.Invalid(path, b, err.Error())
	}

	compiled := &compiledAIBehavior{
		behavior: behavior,
		severity: b.Severity,
	}
	for _, class := range b.Classes {
		compiled.classes = append(compiled.classes, string(class))
	}
	if b.MinConfidence != nil {
		compiled.minConfidence = *b.MinConfidence
	}
	if b.Match != "" {
		predicate, err := c.compileMatchExpression(b.Match)
		if err != nil {
			return nil, field.Invalid(path.Child("match"), b.Match, err.Error())
		}
		predicate.policy = policy
		compiled.match = predicate
	}
	return compiled, nil
}

// compileMatchExpression compiles a per-event boolean predicate. It asserts a
// bool output type, mirroring compileBehavior's list(string) assertion: an
// expression that type-checks to something else is a policy rejection, not a
// surprise at event time.
func (c *compiler) compileMatchExpression(expr string) (*EventPredicate, error) {
	if c.eventEnv == nil {
		return nil, fmt.Errorf("per-event CEL environment is not configured")
	}
	ast, issues := c.eventEnv.Compile(expr)
	if err := issues.Err(); err != nil {
		return nil, err
	}
	if !ast.OutputType().IsExactType(types.BoolType) {
		return nil, fmt.Errorf("invalid return type %s for match expression, expected bool", ast.OutputType())
	}
	prog, err := c.eventEnv.Program(ast)
	if err != nil {
		return nil, err
	}
	return &EventPredicate{prog: prog, src: expr, metrics: c.metrics}, nil
}

func (c *compiler) compileBehavior(b *v1alpha1.Behavior) (*compiledBehavior, error) {
	cp := &compiledBehavior{
		pair: &AllowDenyPair{
			Allow: []string{},
			Deny:  []string{},
		},
	}

	if b.Deny != nil {
		// go over the hardcoded values and add them to the pair
		cp.pair.Deny = append(cp.pair.Deny, b.Deny.Values...)
		if b.Deny.Expression != "" {
			ast, compileErr := c.env.Compile(b.Deny.Expression)
			if compileErr != nil {
				return nil, compileErr.Err()
			}
			// ensure that the output type is a list of string
			if !ast.OutputType().IsExactType(types.NewListType(types.StringType)) {
				return nil, fmt.Errorf("invalid return type for array")
			}
			prog, err := c.env.Program(ast)
			if err != nil {
				return nil, err
			}

			cp.denyProg = prog
		}
	}
	if b.Allow != nil {
		cp.pair.Allow = append(cp.pair.Allow, b.Allow.Values...)
		if b.Allow.Expression != "" {
			ast, compileErr := c.env.Compile(b.Allow.Expression)
			if compileErr != nil {
				return nil, compileErr.Err()
			}
			if !ast.OutputType().IsExactType(types.NewListType(types.StringType)) {
				return nil, fmt.Errorf("invalid return type for array")
			}
			prog, err := c.env.Program(ast)
			if err != nil {
				return nil, err
			}

			cp.allowProg = prog
		}
	}

	return cp, nil
}

func (c *compiler) compileVariables(rp v1alpha1.RuntimePolicy, env *cel.Env, provider types.Provider) (map[string]cel.Program, error) {
	varsProvider, ok := provider.(*variablesProvider)
	if !ok {
		return nil, fmt.Errorf("invalid variables type provider")
	}

	path := field.NewPath("spec").Child("variables")
	variables := make(map[string]cel.Program, len(rp.Spec.Variables))

	for i, variable := range rp.Spec.Variables {
		path := path.Index(i).Child("expression")
		ast, issues := env.Compile(variable.Expression)
		if err := issues.Err(); err != nil {
			return nil, field.Invalid(path, variable.Expression, err.Error())
		}
		varsProvider.registerField(variable.Name, ast.OutputType())
		prog, err := env.Program(ast)
		if err != nil {
			return nil, field.Invalid(path, variable.Expression, err.Error())
		}
		variables[variable.Name] = prog
	}

	return variables, nil
}
