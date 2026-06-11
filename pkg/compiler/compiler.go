package compiler

import (
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type CompiledRuntimeBehavior struct {
	ReevalInterval *time.Duration
	UID            string

	variables map[string]cel.Program
	prog      cel.Program
	rb        v1alpha1.RuntimeBehavior // this field is here temporarily because we don't have proper cel compile and eval yet
}

func (c *CompiledRuntimeBehavior) Evaluate() (*EvaluationResult, error) {
	if c.rb.Spec.Allow == nil || c.rb.Spec.Allow.Deny == nil {
		return nil, fmt.Errorf("temporary error because we just get the hardcoded ip list for now")
	}

	selector, err := metav1.LabelSelectorAsSelector(c.rb.Spec.WorkloadSelector)
	if err != nil {
		return nil, err
	}

	return &EvaluationResult{
		IPs:      c.rb.Spec.Allow.Deny.Network,
		Open:     c.rb.Spec.Allow.Open,
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

func (c *compiler) Compile(rb v1alpha1.RuntimeBehavior) (*CompiledRuntimeBehavior, error) {
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
	variables, err := c.compileVariables(rb, env, provider)
	if err != nil {
		return nil, err
	}
	// todo: match conditions ?

	// denyIps := []string{}
	// denyExec := []string{}

	for _, b := range rb.Spec.Behaviors {
		// they should all compile the same way and a single behavior should be only allowed to have one of them
		// gosh.. i miss rust enums so much
		if b.Network != nil {

		}
		if b.Exec != nil {

		}
		if b.Open != nil {

		}
	}

	return &CompiledRuntimeBehavior{
		rb:        rb,
		variables: variables,
	}, nil
}

func (c *compiler) compileVariables(rb v1alpha1.RuntimeBehavior, env *cel.Env, provider *variablesProvider) (map[string]cel.Program, error) {
	path := field.NewPath("spec").Child("variables")
	variables := make(map[string]cel.Program, len(rb.Spec.Variables))

	for i, variable := range rb.Spec.Variables {
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
