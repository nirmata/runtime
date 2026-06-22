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
	prog   cel.Program
	values []string
}

type compiler struct{}

func NewCompiler() Compiler {
	return &compiler{}
}

func (c *compiler) Compile(rp v1alpha1.RuntimePolicy) (*CompiledRuntimePolicy, error) {
	// todo: i seriously never understood this path stuff. i am done with it
	// path := field.NewPath("spec")
	// todo: do we need to initialize this stuff every time we wanna compile. why can't we just init once ?
	base, err := NewEnv()
	if err != nil {
		return nil, err
	}
	// todo: cel libraries context initialization

	provider := newVariablesProvider(base.CELTypeProvider())
	env, err := base.Extend(
		cel.CustomTypeProvider(provider),
	)
	variables, err := c.compileVariables(rp, env, provider)
	if err != nil {
		return nil, err
	}

	compiledNets := []*compiledBehavior{}
	compiledOpens := []*compiledBehavior{}
	compiledExecs := []*compiledBehavior{}

	for _, b := range rp.Spec.Behaviors {
		if b.Network != nil {
			compiledNet, err := c.compileBehavior(env, b.Network)
			if err != nil {
				return nil, err
			}

			compiledNets = append(compiledNets, compiledNet)
		}
		if b.Exec != nil {
			compiledExec, err := c.compileBehavior(env, b.Exec)
			if err != nil {
				return nil, err
			}

			compiledExecs = append(compiledExecs, compiledExec)
		}
		if b.Open != nil {
			compiledOpen, err := c.compileBehavior(env, b.Open)
			if err != nil {
				return nil, err
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

// returns the hardcoded values, the
func (c *compiler) compileBehavior(e *cel.Env, b *v1alpha1.Behavior) (*compiledBehavior, error) {
	ret := []string{}
	// go over the hardcoded values
	for _, v := range b.Deny.Values {
		ret = append(ret, v)
	}
	ast, compileErr := e.Compile(b.Deny.Expression)
	if compileErr != nil {
		return nil, compileErr.Err()
	}
	// ensure that the output type is a list of string
	if !ast.OutputType().IsExactType(types.NewListType(types.StringType)) {
		return nil, fmt.Errorf("invalid return type for array")
	}
	prog, err := e.Program(ast)
	if err != nil {
		return nil, err
	}

	return &compiledBehavior{prog: prog, values: ret}, nil
}

func (c *compiler) compileVariables(rp v1alpha1.RuntimePolicy, env *cel.Env, provider *variablesProvider) (map[string]cel.Program, error) {
	path := field.NewPath("spec").Child("variables")
	variables := make(map[string]cel.Program, len(rp.Spec.Variables))

	for i, variable := range rp.Spec.Variables {
		path := path.Index(i).Child("expression")
		ast, issues := env.Compile(variable.Expression)
		if err := issues.Err(); err != nil {
			return nil, field.Invalid(path, variable.Expression, err.Error())
		}
		provider.RegisterField(variable.Name, ast.OutputType())
		prog, err := env.Program(ast)
		if err != nil {
			return nil, field.Invalid(path, variable.Expression, err.Error())
		}
		variables[variable.Name] = prog
	}

	return variables, nil
}
