package compiler

import (
	"fmt"
	"math"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	apiservercel "k8s.io/apiserver/pkg/cel"
)

const eventKey = "event"

func declField(name string, t *apiservercel.DeclType) *apiservercel.DeclField {
	return apiservercel.NewDeclField(name, t, false, nil, nil)
}

// The declared schema and filterActivation below are the two halves of one
// table and mirror the wire JSON of runtimeevent.Event. Event.CgroupID is
// excluded: it is a node-internal identifier with no meaning to a policy
// author.
var (
	podDeclType = apiservercel.NewObjectType("nirmata.event.pod", map[string]*apiservercel.DeclField{
		"namespace":      declField("namespace", apiservercel.StringType),
		"name":           declField("name", apiservercel.StringType),
		"uid":            declField("uid", apiservercel.StringType),
		"container":      declField("container", apiservercel.StringType),
		"containerID":    declField("containerID", apiservercel.StringType),
		"ownerKind":      declField("ownerKind", apiservercel.StringType),
		"ownerName":      declField("ownerName", apiservercel.StringType),
		"nodeName":       declField("nodeName", apiservercel.StringType),
		"serviceAccount": declField("serviceAccount", apiservercel.StringType),
		"labels":         declField("labels", apiservercel.NewMapType(apiservercel.StringType, apiservercel.StringType, math.MaxInt64)),
	})

	openDeclType = apiservercel.NewObjectType("nirmata.event.open", map[string]*apiservercel.DeclField{
		"path": declField("path", apiservercel.StringType),
	})

	execDeclType = apiservercel.NewObjectType("nirmata.event.exec", map[string]*apiservercel.DeclField{
		"filename": declField("filename", apiservercel.StringType),
		"argv":     declField("argv", apiservercel.NewListType(apiservercel.StringType, math.MaxInt64)),
	})

	netDeclType = apiservercel.NewObjectType("nirmata.event.net", map[string]*apiservercel.DeclField{
		"destIP": declField("destIP", apiservercel.StringType),
		"domain": declField("domain", apiservercel.StringType),
	})

	dnsDeclType = apiservercel.NewObjectType("nirmata.event.dns", map[string]*apiservercel.DeclField{
		"qname": declField("qname", apiservercel.StringType),
	})

	protocolDeclType = apiservercel.NewObjectType("nirmata.event.protocol", map[string]*apiservercel.DeclField{
		"protocol": declField("protocol", apiservercel.StringType),
		"alpn":     declField("alpn", apiservercel.StringType),
	})

	eventDeclType = apiservercel.NewObjectType("nirmata.event", map[string]*apiservercel.DeclField{
		"kind":         declField("kind", apiservercel.StringType),
		"time":         declField("time", apiservercel.TimestampType),
		"comm":         declField("comm", apiservercel.StringType),
		"pid":          declField("pid", apiservercel.IntType),
		"count":        declField("count", apiservercel.IntType),
		"kernelDenied": declField("kernelDenied", apiservercel.BoolType),
		"wouldDeny":    declField("wouldDeny", apiservercel.BoolType),
		"pod":          declField("pod", podDeclType),
		"open":         declField("open", openDeclType),
		"exec":         declField("exec", execDeclType),
		"net":          declField("net", netDeclType),
		"dns":          declField("dns", dnsDeclType),
		"protocol":     declField("protocol", protocolDeclType),
	})
)

// filterActivation converts an event into the CEL activation a monitorFilter
// expression sees.
//
// A facts key is set only when the matching pointer is non-nil, which is what
// makes has(event.open) answer the kind question and what makes dereferencing
// the wrong arm an eval error rather than a zero value.
func filterActivation(ev runtimeevent.Event) map[string]any {
	event := map[string]any{
		"kind":         string(ev.Kind),
		"time":         ev.Time,
		"comm":         ev.Comm,
		"pid":          int64(ev.PID),
		"count":        int64(ev.Count),
		"kernelDenied": ev.KernelDenied,
		"wouldDeny":    ev.WouldDeny,
		"pod": map[string]any{
			"namespace":      ev.Pod.Namespace,
			"name":           ev.Pod.Name,
			"uid":            ev.Pod.UID,
			"container":      ev.Pod.Container,
			"containerID":    ev.Pod.ContainerID,
			"ownerKind":      ev.Pod.OwnerKind,
			"ownerName":      ev.Pod.OwnerName,
			"nodeName":       ev.Pod.NodeName,
			"serviceAccount": ev.Pod.ServiceAccount,
			"labels":         ev.Pod.Labels,
		},
	}

	if ev.Open != nil {
		event["open"] = map[string]any{"path": ev.Open.Path}
	}
	if ev.Exec != nil {
		event["exec"] = map[string]any{
			"filename": ev.Exec.Filename,
			"argv":     ev.Exec.Argv,
		}
	}
	if ev.Net != nil {
		// An unset netip.Addr stringifies to "invalid IP", which would compare
		// and match like an address.
		destIP := ""
		if ev.Net.DestIP.IsValid() {
			destIP = ev.Net.DestIP.String()
		}
		event["net"] = map[string]any{"destIP": destIP, "domain": ev.Net.Domain}
	}
	if ev.DNS != nil {
		event["dns"] = map[string]any{"qname": ev.DNS.QName}
	}
	if ev.Protocol != nil {
		event["protocol"] = map[string]any{"protocol": ev.Protocol.Protocol, "alpn": ev.Protocol.ALPN}
	}

	return map[string]any{eventKey: event}
}

// MonitorFilter is a policy's compiled monitorFilter expressions, in spec order.
type MonitorFilter struct {
	expressions []filterExpression
}

type filterExpression struct {
	name string
	prog cel.Program
}

// FilterDecision is the outcome of running a filter over one event. Expression
// names the expression that decided, empty when every expression passed. A
// non-nil Err always comes with Report true: the filter picks what an operator
// sees, so a broken expression must widen what is reported rather than hide it.
type FilterDecision struct {
	Report     bool
	Expression string
	Err        error
}

// Decide reports whether ev should become a finding. A nil filter reports
// everything.
func (f *MonitorFilter) Decide(ev runtimeevent.Event) FilterDecision {
	if f == nil {
		return FilterDecision{Report: true}
	}

	activation := filterActivation(ev)
	for _, expr := range f.expressions {
		out, _, err := expr.prog.Eval(activation)
		if err != nil {
			return FilterDecision{Report: true, Expression: expr.name, Err: err}
		}
		result, ok := out.Value().(bool)
		if !ok {
			return FilterDecision{Report: true, Expression: expr.name, Err: fmt.Errorf("expression returned %s, want bool", out.Type().TypeName())}
		}
		if !result {
			return FilterDecision{Report: false, Expression: expr.name}
		}
	}
	return FilterDecision{Report: true}
}

// compileMonitorFilter compiles spec.monitorFilter, and rejects it outright in
// enforce mode.
//
// An enforce finding records that the kernel did block something, so there is
// nothing counterfactual to narrow and suppressing one destroys an audit
// record. RuntimePolicySpec carries the same rule so the API server refuses the
// object; this is the backstop for a cluster whose CRD predates it, and the two
// messages are meant to read identically.
func (c *compiler) compileMonitorFilter(rp v1alpha1.RuntimePolicy, mode string) (*MonitorFilter, error) {
	mf := rp.Spec.MonitorFilter
	if mf == nil {
		return nil, nil
	}

	path := field.NewPath("spec", "monitorFilter")
	if mode == ModeEnforce {
		return nil, field.Forbidden(path, "a monitorFilter narrows what a monitor-mode policy reports; an enforce-mode policy reports only operations the kernel actually denied, and those are never suppressed")
	}

	exprPath := path.Child("expressions")
	if len(mf.Expressions) == 0 {
		return nil, field.Required(exprPath, "a monitorFilter with no expressions reports every finding, which is what omitting the field already does")
	}

	seen := make(map[string]struct{}, len(mf.Expressions))
	expressions := make([]filterExpression, 0, len(mf.Expressions))
	for i, e := range mf.Expressions {
		if _, dup := seen[e.Name]; dup {
			return nil, field.Duplicate(exprPath.Index(i).Child("name"), e.Name)
		}
		seen[e.Name] = struct{}{}

		// The name rather than the index is what a status condition and the
		// eval-error metric identify an expression by, so it belongs in the
		// compile error too.
		valuePath := exprPath.Index(i).Child("expression")
		reject := func(detail string) error {
			return field.Invalid(valuePath, e.Expression, fmt.Sprintf("expression %q: %s", e.Name, detail))
		}
		ast, issues := c.filterEnv.Compile(e.Expression)
		if err := issues.Err(); err != nil {
			return nil, reject(err.Error())
		}
		if !ast.OutputType().IsExactType(types.BoolType) {
			return nil, reject(fmt.Sprintf("must evaluate to bool, got %s", ast.OutputType()))
		}
		prog, err := c.filterEnv.Program(ast)
		if err != nil {
			return nil, reject(err.Error())
		}
		expressions = append(expressions, filterExpression{name: e.Name, prog: prog})
	}

	return &MonitorFilter{expressions: expressions}, nil
}
