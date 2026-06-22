package compiler

import (
	"time"

	"github.com/google/cel-go/cel"
	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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
	denyIps  []string
	denyOpen []string
	denyExec []string
}

func (c *CompiledRuntimePolicy) Evaluate() (*EvaluationResult, error) {
	selector, err := metav1.LabelSelectorAsSelector(c.selector)
	if err != nil {
		return nil, err
	}

	return &EvaluationResult{
		UID:      c.UID,
		IPs:      c.denyIps,
		Open:     c.denyOpen,
		Selector: selector,
	}, nil
}

type EvaluationResult struct {
	UID      string
	IPs      []string // the evaluated list of IPs to ban
	Open     []string // list of files to prevent opening
	Selector labels.Selector
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

	provider := newVariablesProvider(base.CELTypeProvider())
	env, err := base.Extend(
		cel.CustomTypeProvider(provider),
	)
	variables, err := c.compileVariables(rp, env, provider)
	if err != nil {
		return nil, err
	}

	denyIps := []string{}
	denyOpen := []string{}
	denyExec := []string{}

	for _, b := range rp.Spec.Behaviors {
		if b.Network != nil {
			for _, ip := range b.Network.Deny.Values {
				denyIps = append(denyIps, ip)
			}
		}
		if b.Exec != nil {
			for _, fileName := range b.Exec.Deny.Values {
				denyExec = append(denyExec, fileName)
			}
		}
		if b.Open != nil {
			for _, fileName := range b.Open.Deny.Values {
				denyOpen = append(denyOpen, fileName)
			}
		}
	}

	return &CompiledRuntimePolicy{
		variables: variables,
	}, nil
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
