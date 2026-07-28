package compiler

import (
	"context"
	"fmt"
	"reflect"

	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/cel/lazy"
)

const varsKey = "variables"

type EvaluationResult struct {
	UID string
	// Name is the RuntimePolicy name, needed by consumers that report
	// findings and conditions against the policy (monitor, reporter).
	Name     string
	IPs      *AllowDenyPair
	Open     *AllowDenyPair
	Exec     *AllowDenyPair
	Selector labels.Selector
	Mode     string
}

type AllowDenyPair struct {
	// todo: maybe move default deny detection to be directly on the pair and check it
	// at compile time ?
	Allow []string
	Deny  []string
}

func (p *AllowDenyPair) HasEntries() bool {
	if p == nil {
		return false
	}
	return len(p.Allow) != 0 || len(p.Deny) != 0
}

// given a pair p, and a target..return another pair that represents what's in the target
// but not p.
func (p *AllowDenyPair) DiffPair(target *AllowDenyPair) *AllowDenyPair {
	if target == nil {
		return &AllowDenyPair{}
	}
	if p == nil {
		return target
	}

	newAllowInTarget := utils.DiffSlice(p.Allow, target.Allow)
	newDenyInTarget := utils.DiffSlice(p.Deny, target.Deny)

	return &AllowDenyPair{Allow: newAllowInTarget, Deny: newDenyInTarget}
}

// Evaluate runs the policy's compiled CEL programs. Evaluation executes
// user-authored expressions (including third-party CEL library bindings), so
// the whole body runs behind utils.Guard: a panicking binding becomes an
// error instead of taking the daemon down (#40).
func (c *CompiledRuntimePolicy) Evaluate(ctx context.Context) (*EvaluationResult, error) {
	var result *EvaluationResult
	err := utils.Guard(fmt.Sprintf("evaluating RuntimePolicy %q", c.Name), func() error {
		var err error
		result, err = c.evaluate(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *CompiledRuntimePolicy) evaluate(ctx context.Context) (*EvaluationResult, error) {
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
		Name:     c.Name,
		IPs:      net,
		Open:     open,
		Exec:     exec,
		Selector: selector,
		Mode:     c.mode,
	}, nil
}

func evalCompiledBehavior(ctx context.Context, accum *AllowDenyPair, b *compiledBehavior, data map[string]any) error {
	if b.denyProg != nil {
		out, _, err := b.denyProg.ContextEval(ctx, data)
		if err != nil {
			return err
		}
		exprIps, err := toStringSlice(out)
		if err != nil {
			return err
		}
		accum.Deny = append(accum.Deny, exprIps...)
	}
	accum.Deny = append(accum.Deny, b.pair.Deny...)
	if b.allowProg != nil {
		out, _, err := b.allowProg.ContextEval(ctx, data)
		if err != nil {
			return err
		}
		exprIps, err := toStringSlice(out)
		if err != nil {
			return err
		}
		accum.Allow = append(accum.Allow, exprIps...)
	}
	accum.Allow = append(accum.Allow, b.pair.Allow...)

	return nil
}

func toStringSlice(out ref.Val) ([]string, error) {
	native, err := out.ConvertToNative(reflect.TypeFor[[]string]())
	if err != nil {
		return nil, fmt.Errorf("invalid program return type. expected array of string: %w", err)
	}
	exprIps, ok := native.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid program return type. expected array of string")
	}
	return exprIps, nil
}
