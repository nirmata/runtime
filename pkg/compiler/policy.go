package compiler

import (
	"context"
	"fmt"
	"reflect"
	"slices"

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

	// UnresolvedServices holds the Service DNS values whose Service is absent
	// from cache, as authored.
	UnresolvedServices []string
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

	// Resolution happens here rather than in Compile because the resolver's
	// answer changes as Services and their endpoints change.
	var unresolved []string
	net.Allow, unresolved = c.resolveServiceValues(net.Allow, unresolved)
	net.Deny, unresolved = c.resolveServiceValues(net.Deny, unresolved)

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
		UID:                c.UID,
		Name:               c.Name,
		IPs:                net,
		Open:               open,
		Exec:               exec,
		Selector:           selector,
		Mode:               c.mode,
		UnresolvedServices: unresolved,
	}, nil
}

// resolveServiceValues replaces each cluster Service DNS value with that
// Service's current addresses, keeping every other value in place. The name has
// to disappear from the result: egressfilter.ParseTargets would otherwise also
// intern it for DNS snooping and program the same Service by two mechanisms.
func (c *CompiledRuntimePolicy) resolveServiceValues(side []string, unresolved []string) ([]string, []string) {
	if !slices.ContainsFunc(side, isServiceValue) {
		return side, unresolved
	}

	out := make([]string, 0, len(side))
	for i, value := range side {
		parsed, err := ParseNetworkValue(value)
		if err != nil || parsed.Service == nil {
			out = append(out, value)
			continue
		}
		addrs, found := c.resolver.ResolveService(parsed.Service.Namespace, parsed.Service.Name)
		if !found {
			if !slices.Contains(unresolved, value) {
				unresolved = append(unresolved, value)
			}
			continue
		}
		for _, addr := range slices.Sorted(slices.Values(addrs)) {
			// An address a later value carries verbatim is left to that value.
			if slices.Contains(out, addr) || slices.Contains(side[i+1:], addr) {
				continue
			}
			out = append(out, addr)
		}
	}
	return out, unresolved
}

func isServiceValue(value string) bool {
	parsed, err := ParseNetworkValue(value)
	return err == nil && parsed.Service != nil
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
