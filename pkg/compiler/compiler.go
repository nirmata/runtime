package compiler

import (
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type CompiledRuntimePolicy struct {
	ReevalInterval *time.Duration
	UID            string

	variables map[string]cel.Program
	prog      cel.Program
	selector  *metav1.LabelSelector

	// todo: think of how allow and deny works in the codebase

	// these are the hardcoded values in the api spec
	compiledNets  []*compiledBehavior
	compiledOpens []*compiledBehavior
	compiledExecs []*compiledBehavior
}

type compiledBehavior struct {
	defaultDeny bool
	denyProg    cel.Program
	allowProg   cel.Program
	pair        *AllowDenyPair
}

type compiler struct {
	env *cel.Env
}

func NewCompiler() (Compiler, error) {
	base, err := NewEnv()
	if err != nil {
		return nil, err
	}

	provider := newVariablesProvider(base.CELTypeProvider())
	env, err := base.Extend(
		cel.CustomTypeProvider(provider),
	)
	return &compiler{env: env}, nil
}

func (c *compiler) Compile(rp v1alpha1.RuntimePolicy) (*CompiledRuntimePolicy, error) {
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
			compiledNet, err := c.compileBehavior(b.Network)
			if err != nil {
				errPath := path.Index(i).Child("network")
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

	return &CompiledRuntimePolicy{
		compiledNets:  compiledNets,
		compiledOpens: compiledOpens,
		compiledExecs: compiledExecs,
		variables:     variables,
	}, nil
}

func (c *compiler) compileBehavior(b *v1alpha1.Behavior) (*compiledBehavior, error) {
	cp := &compiledBehavior{}

	{
		// go over the hardcoded values and add them to the pair
		for _, v := range b.Deny.Values {
			cp.pair.Deny = append(cp.pair.Deny, v)
		}
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
	{
		for _, v := range b.Allow.Values {
			cp.pair.Allow = append(cp.pair.Allow, v)
		}
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
