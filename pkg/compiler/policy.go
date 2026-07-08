package compiler

import (
	"context"
	"fmt"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/cel/lazy"
)

const varsKey = "variables"

type EvaluationResult struct {
	UID      string
	IPs      *AllowDenyPair
	Open     *AllowDenyPair
	Exec     *AllowDenyPair
	Selector labels.Selector
}

type AllowDenyPair struct {
	// todo: there should be something in that type that indicates that a default deny was found
	Allow []string
	Deny  []string
}

func (c *CompiledRuntimePolicy) Evaluate(ctx context.Context) (*EvaluationResult, error) {
	selector, err := metav1.LabelSelectorAsSelector(c.selector)
	if err != nil {
		return nil, err
	}

	vars := lazy.NewMapValue(VariablesType)

	data := make(map[string]any)
	data[varsKey] = vars

	for name, variable := range c.variables {
		vars.Append(name, func(*lazy.MapValue) ref.Val {
			out, _, err := variable.ContextEval(ctx, data)
			if out != nil {
				return out
			}
			if err != nil {
				return types.WrapErr(err)
			}
			return nil
		})
	}
	// iterate on each of the compiled types, extract the hardcoded values and evaluate the
	// expression and append it to the return
	net := &AllowDenyPair{}
	open := &AllowDenyPair{}
	exec := &AllowDenyPair{}

	for _, compiledNet := range c.compiledNets {
		err := evalCompiledBehavior(ctx, net, compiledNet, data)
		if err != nil {
			return nil, err
		}
	}

	for _, compiledOpen := range c.compiledOpens {
		err := evalCompiledBehavior(ctx, open, compiledOpen, data)
		if err != nil {
			return nil, err
		}
	}

	for _, compiledExec := range c.compiledExecs {
		err := evalCompiledBehavior(ctx, exec, compiledExec, data)
		if err != nil {
			return nil, err
		}
	}

	return &EvaluationResult{
		UID:      c.UID,
		IPs:      net,
		Open:     open,
		Exec:     exec,
		Selector: selector,
	}, nil
}

func evalCompiledBehavior(ctx context.Context, accum *AllowDenyPair, b *compiledBehavior, data map[string]any) error {
	if b.denyProg != nil {
		out, _, err := b.denyProg.ContextEval(ctx, data)
		if err != nil {
			return err
		}
		exprIps, ok := out.Value().([]string)
		if !ok {
			return fmt.Errorf("invalid program return type. expected array of string")
		}
		accum.Deny = append(accum.Deny, exprIps...)
	}
	accum.Deny = append(accum.Deny, b.pair.Deny...)
	if b.allowProg != nil {
		out, _, err := b.allowProg.ContextEval(ctx, data)
		if err != nil {
			return err
		}
		exprIps, ok := out.Value().([]string)
		if !ok {
			return fmt.Errorf("invalid program return type. expected array of string")
		}
		accum.Allow = append(accum.Allow, exprIps...)
	}
	accum.Allow = append(accum.Allow, b.pair.Allow...)

	return nil
}
