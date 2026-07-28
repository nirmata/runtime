package compiler

import (
	"fmt"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

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
}

type compiledBehavior struct {
	denyProg  cel.Program
	allowProg cel.Program
	pair      *AllowDenyPair
}

type compiler struct {
	env *cel.Env
}

func NewCompiler(client dynamic.Interface) (Compiler, error) {
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
	return &compiler{env: env}, nil
}

// Compile compiles a user-authored RuntimePolicy. Every panic raised while
// compiling user input (a CEL library binding, a malformed expression tree) is
// converted into an error by utils.Guard: a bad policy must never take the
// privileged daemon down (#40).
func (c *compiler) Compile(rp v1alpha1.RuntimePolicy) (*CompiledRuntimePolicy, error) {
	var compiled *CompiledRuntimePolicy
	err := utils.Guard(fmt.Sprintf("compiling RuntimePolicy %q", rp.Name), func() error {
		var err error
		compiled, err = c.compile(rp)
		return err
	})
	if err != nil {
		return nil, err
	}
	return compiled, nil
}

func (c *compiler) compile(rp v1alpha1.RuntimePolicy) (*CompiledRuntimePolicy, error) {
	variables, err := c.compileVariables(rp, c.env, c.env.CELTypeProvider())
	if err != nil {
		return nil, err
	}

	compiledNets := []*compiledBehavior{}
	compiledOpens := []*compiledBehavior{}
	compiledExecs := []*compiledBehavior{}

	// we use the path to propagate errors with context on which field's compilation errored
	path := field.NewPath("spec").Child("behaviors")

	for i, b := range rp.Spec.Behaviors {
		if b.Network != nil {
			errPath := path.Index(i).Child("network")
			// hardcoded network targets are validated at compile time so an
			// unsupported literal is rejected loudly instead of being dropped
			// silently when it reaches the BPF maps (#41).
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
		variables:      variables,
	}, nil
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
