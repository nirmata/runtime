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
	UID      string
	Name     string
	IPs      *AllowDenyPair
	Open     *AllowDenyPair
	Exec     *AllowDenyPair
	Selector labels.Selector
	Mode     string
	// AI holds one rule per `ai` behavior, in spec order. Nil/empty means the
	// policy carries no AI detection rules.
	AI []*AIRule
}

// AIRule is one evaluated `ai` behavior: the policy-time part of an AI
// detection rule (target lists and gates), plus the compiled per-event
// predicate the detection engine evaluates for each classified event.
type AIRule struct {
	// Classes restricts the rule to these traffic classes ("llm", "mcp",
	// "a2a"); empty means all classes.
	Classes []string
	// Allow and Deny are destination identities: hostname globs,
	// "provider:<name>", "mcp-server:<package>", IPv4 literals/CIDRs, or the
	// "*" default-deny sentinel. Each is the union of the behavior's
	// hardcoded values and its evaluated expression, exactly like the
	// network/exec/open behaviors.
	Allow []string
	Deny  []string
	// Match is the compiled `match` predicate, nil when the behavior sets
	// none. A nil Match means "no additional condition", so callers must check
	// for nil rather than relying on Eval (which reports false).
	Match *EventPredicate
	// MinConfidence gates findings by classifier confidence (0-100).
	MinConfidence int32
	// Severity is the severity of findings emitted for this rule.
	Severity string
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

// Evaluate runs the policy's compiled CEL programs.
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

	var aiRules []*AIRule
	for _, compiledAI := range c.compiledAIs {
		// AI targets reuse the behavior accumulator, so `values` and
		// `expression` union exactly as they do for the other behaviors.
		// Start from empty rather than nil slices, matching compileBehavior, so
		// a consumer never has to distinguish "no entries" from "unset".
		targets := &AllowDenyPair{Allow: []string{}, Deny: []string{}}
		if err := evalCompiledBehavior(ctx, targets, compiledAI.behavior, data); err != nil {
			return nil, err
		}
		aiRules = append(aiRules, &AIRule{
			// Copy so a consumer cannot mutate the compiled policy's state.
			Classes:       append([]string(nil), compiledAI.classes...),
			Allow:         targets.Allow,
			Deny:          targets.Deny,
			Match:         compiledAI.match,
			MinConfidence: compiledAI.minConfidence,
			Severity:      compiledAI.severity,
		})
	}

	return &EvaluationResult{
		UID:      c.UID,
		Name:     c.Name,
		IPs:      net,
		Open:     open,
		Exec:     exec,
		Selector: selector,
		Mode:     c.mode,
		AI:       aiRules,
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
