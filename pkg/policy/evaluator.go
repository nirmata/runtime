package policy

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	sdkcelcompiler "github.com/kyverno/sdk/cel/compiler"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

type Evaluator struct {
	envMu      sync.Mutex
	env        *cel.Env
	programMu  sync.RWMutex
	programs   map[string]cel.Program
	cacheHits  atomic.Uint64
	cacheMiss  atomic.Uint64
	loggerName string
}

type RuntimeEvaluationResult struct {
	Findings    []v1alpha1.RuleFinding
	Actions     []v1alpha1.ActionRecord
	Summaries   []string
	MatchedRule int
}

func NewEvaluator() *Evaluator {
	return &Evaluator{
		programs:   make(map[string]cel.Program),
		loggerName: "policy-evaluator",
	}
}

func (e *Evaluator) MatchesPolicy(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod, namespaceLabels map[string]string) (bool, error) {
	if err := policy.Spec.Validate(); err != nil {
		return false, err
	}
	if policy.Spec.NamespaceSelector != nil {
		nsSel, err := metav1.LabelSelectorAsSelector(policy.Spec.NamespaceSelector)
		if err != nil {
			return false, err
		}
		if !nsSel.Matches(labels.Set(namespaceLabels)) {
			return false, nil
		}
	}
	return true, nil
}

func (e *Evaluator) Evaluate(policy *v1alpha1.RuntimePolicy, pod *corev1.Pod) []string {
	return nil
}

func (e *Evaluator) EvaluateRuntime(policy *v1alpha1.RuntimePolicy, events []runtimeevents.Event) RuntimeEvaluationResult {
	logger := log.Log.WithName(e.loggerName)
	result := RuntimeEvaluationResult{
		Findings:  make([]v1alpha1.RuleFinding, 0),
		Actions:   make([]v1alpha1.ActionRecord, 0),
		Summaries: make([]string, 0),
	}
	logger.V(1).Info("evaluating runtime policy", "policy", policy.Name, "validations", len(policy.Spec.Validations), "events", len(events))

	for _, validation := range policy.Spec.Validations {
		for _, ev := range events {
			if !validationAppliesToEvent(validation, ev) {
				logger.V(2).Info("validation skipped due to event type mismatch", "validation", validation.Name, "validationEvent", validation.Event, "eventType", ev.Type)
				continue
			}

			activation := buildCELActivation(ev)

			ok, err := e.evaluateConditionList(validation.MatchConditions, activation)
			if err != nil || !ok {
				if err != nil {
					logger.V(1).Info("validation match conditions failed", "validation", validation.Name, "eventType", ev.Type, "error", err.Error())
				}
				continue
			}

			ok, err = e.evaluateConditionList(validation.Conditions, activation)
			if err != nil || !ok {
				if err != nil {
					logger.V(1).Info("validation conditions failed", "validation", validation.Name, "eventType", ev.Type, "error", err.Error())
				}
				continue
			}

			severity := validation.Severity
			if strings.TrimSpace(severity) == "" {
				severity = "warning"
			}
			msg := strings.TrimSpace(validation.Message)
			if msg == "" {
				msg = fmt.Sprintf("runtime validation %s matched event %s", validation.Name, ev.Type)
			}

			finding := v1alpha1.RuleFinding{
				RuleName:  validation.Name,
				EventType: ev.Type,
				Severity:  severity,
				Message:   msg,
				Fields:    cloneFields(ev.Fields),
			}
			result.Findings = append(result.Findings, finding)
			result.Summaries = append(result.Summaries, fmt.Sprintf("validation %s matched on event %s", validation.Name, ev.Type))
			result.MatchedRule++
			logger.V(1).Info("validation matched", "validation", validation.Name, "eventType", ev.Type, "severity", severity)

			now := metav1.NewTime(time.Now().UTC())
			for _, a := range validation.Actions {
				actionMsg := strings.TrimSpace(a.Message)
				if actionMsg == "" {
					actionMsg = fmt.Sprintf("action %s requested by validation %s", a.Type, validation.Name)
				}
				result.Actions = append(result.Actions, v1alpha1.ActionRecord{Type: a.Type, Message: actionMsg, Timestamp: now})
			}
		}
	}
	logger.V(1).Info("runtime policy evaluation completed", "policy", policy.Name, "findings", len(result.Findings), "cacheHits", e.cacheHits.Load(), "cacheMisses", e.cacheMiss.Load())

	return result
}

func validationAppliesToEvent(validation v1alpha1.RuntimeValidation, ev runtimeevents.Event) bool {
	if strings.TrimSpace(validation.Event) == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(validation.Event), strings.TrimSpace(ev.Type))
}

func (e *Evaluator) evaluateConditionList(conditions []v1alpha1.RuntimeCELCondition, activation map[string]any) (bool, error) {
	if len(conditions) == 0 {
		return true, nil
	}
	for _, cond := range conditions {
		expr := strings.TrimSpace(cond.Expression)
		if expr == "" {
			return false, nil
		}
		// Backward compatibility: older examples used `event != null`, but the
		// event variable is modeled as a non-null map in this evaluator.
		compactExpr := strings.ReplaceAll(expr, " ", "")
		if compactExpr == "event!=null" {
			continue
		}
		ok, err := e.evaluateCELBoolean(expr, activation)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func (e *Evaluator) evaluateCELBoolean(expression string, activation map[string]any) (bool, error) {
	prog, err := e.compileCELProgram(expression)
	if err != nil {
		return false, err
	}
	out, _, err := prog.Eval(activation)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("output is expected to be bool")
	}
	return b, nil
}

func (e *Evaluator) compileCELProgram(expression string) (cel.Program, error) {
	e.programMu.RLock()
	if prog, ok := e.programs[expression]; ok {
		e.programMu.RUnlock()
		e.cacheHits.Add(1)
		return prog, nil
	}
	e.programMu.RUnlock()

	env, err := e.getOrCreateEnv()
	if err != nil {
		return nil, err
	}

	ast, issues := env.Compile(expression)
	if err := issues.Err(); err != nil {
		return nil, err
	}
	if !ast.OutputType().IsExactType(types.BoolType) {
		return nil, fmt.Errorf("output is expected to be bool")
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, err
	}

	e.programMu.Lock()
	e.programs[expression] = prog
	e.programMu.Unlock()
	e.cacheMiss.Add(1)

	return prog, nil
}

// EnsureCompiled pre-compiles all CEL expressions in a policy so syntax/type
// errors are surfaced during watch setup rather than on first event.
func (e *Evaluator) EnsureCompiled(policy *v1alpha1.RuntimePolicy) error {
	if policy == nil {
		return nil
	}
	for _, validation := range policy.Spec.Validations {
		for _, cond := range validation.MatchConditions {
			expr := strings.TrimSpace(cond.Expression)
			if expr == "" {
				continue
			}
			compactExpr := strings.ReplaceAll(expr, " ", "")
			if compactExpr == "event!=null" {
				continue
			}
			if _, err := e.compileCELProgram(expr); err != nil {
				return fmt.Errorf("validation %q match condition compile failed: %w", validation.Name, err)
			}
		}
		for _, cond := range validation.Conditions {
			expr := strings.TrimSpace(cond.Expression)
			if expr == "" {
				continue
			}
			compactExpr := strings.ReplaceAll(expr, " ", "")
			if compactExpr == "event!=null" {
				continue
			}
			if _, err := e.compileCELProgram(expr); err != nil {
				return fmt.Errorf("validation %q condition compile failed: %w", validation.Name, err)
			}
		}
	}
	return nil
}

func (e *Evaluator) getOrCreateEnv() (*cel.Env, error) {
	e.envMu.Lock()
	defer e.envMu.Unlock()
	if e.env != nil {
		return e.env, nil
	}

	base, err := sdkcelcompiler.NewBaseEnv()
	if err != nil {
		return nil, err
	}
	env, err := base.Extend(
		cel.Variable("event", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("fields", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("metadata", cel.MapType(cel.StringType, cel.StringType)),
	)
	if err != nil {
		return nil, err
	}
	e.env = env
	return e.env, nil
}

func buildCELActivation(ev runtimeevents.Event) map[string]any {
	eventMap := map[string]string{
		"type":      ev.Type,
		"source":    ev.Source,
		"podName":   ev.PodName,
		"namespace": ev.Namespace,
		"timestamp": ev.Timestamp.UTC().Format(time.RFC3339Nano),
	}
	for k, v := range ev.Fields {
		eventMap[k] = v
	}
	addEventFieldAliases(eventMap)

	metadata := map[string]string{
		"podName":   ev.PodName,
		"namespace": ev.Namespace,
	}

	return map[string]any{
		"event":    eventMap,
		"fields":   cloneFields(ev.Fields),
		"metadata": metadata,
	}
}

func addEventFieldAliases(eventMap map[string]string) {
	if eventMap == nil {
		return
	}

	// Common open-path aliases used by sample policies and different gadget outputs.
	aliasIfMissing(eventMap, "file.path", firstNonEmpty(eventMap["file.path"], eventMap["path"], eventMap["fullPath"], eventMap["fname"], eventMap["filename"]))
	aliasIfMissing(eventMap, "path", firstNonEmpty(eventMap["path"], eventMap["file.path"], eventMap["fullPath"], eventMap["fname"], eventMap["filename"]))
	aliasIfMissing(eventMap, "fullPath", firstNonEmpty(eventMap["fullPath"], eventMap["file.path"], eventMap["path"], eventMap["fname"], eventMap["filename"]))
	aliasIfMissing(eventMap, "fname", firstNonEmpty(eventMap["fname"], eventMap["file.path"], eventMap["path"], eventMap["fullPath"], eventMap["filename"]))
	aliasIfMissing(eventMap, "filename", firstNonEmpty(eventMap["filename"], eventMap["fname"], eventMap["file.path"], eventMap["path"], eventMap["fullPath"]))

	// Common process-name aliases for exec style policies.
	aliasIfMissing(eventMap, "process.name", firstNonEmpty(eventMap["process.name"], eventMap["comm"], eventMap["proc.comm"], eventMap["filename"]))
	aliasIfMissing(eventMap, "comm", firstNonEmpty(eventMap["comm"], eventMap["process.name"], eventMap["proc.comm"]))
}

func aliasIfMissing(values map[string]string, key, value string) {
	if values[key] != "" || value == "" {
		return
	}
	values[key] = value
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func cloneFields(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
