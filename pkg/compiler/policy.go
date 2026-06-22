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
	denyIps := []string{}
	denyOpen := []string{}
	denyExec := []string{}

	for _, compiledNet := range c.compiledNets {
		// todo: program context
		out, _, err := compiledNet.prog.ContextEval(context.Background(), data)
		if err != nil {
			return nil, err
		}
		exprIps, ok := out.Value().([]string)
		if !ok {
			return nil, fmt.Errorf("invalid program return type. expected array of string")
		}

		denyIps = append(denyIps, exprIps...)
		denyIps = append(denyIps, compiledNet.values...)
	}

	for _, compiledOpen := range c.compiledOpens {
		out, _, err := compiledOpen.prog.ContextEval(context.Background(), data)
		if err != nil {
			return nil, err
		}
		exprFiles, ok := out.Value().([]string)
		if !ok {
			return nil, fmt.Errorf("invalid program return type. expected array of string")
		}

		denyOpen = append(denyOpen, exprFiles...)
		denyOpen = append(denyOpen, compiledOpen.values...)
	}

	for _, compiledExec := range c.compiledExecs {
		out, _, err := compiledExec.prog.ContextEval(context.Background(), data)
		if err != nil {
			return nil, err
		}
		exprFiles, ok := out.Value().([]string)
		if !ok {
			return nil, fmt.Errorf("invalid program return type. expected array of string")
		}

		denyExec = append(denyExec, exprFiles...)
		denyExec = append(denyOpen, compiledExec.values...)
	}

	return &EvaluationResult{
		UID:      c.UID,
		IPs:      denyIps,
		Open:     denyOpen,
		Selector: selector,
	}, nil
}

type EvaluationResult struct {
	UID      string
	IPs      []string // the evaluated list of IPs to ban
	Open     []string // list of files to prevent opening
	Exec     []string
	Selector labels.Selector
}
