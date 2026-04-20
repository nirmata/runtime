package policy

import (
	"testing"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevents"
)

func TestEvaluateRuntimeUseCases(t *testing.T) {
	e := NewEvaluator()

	tests := []struct {
		name       string
		validation v1alpha1.RuntimeValidation
		event      runtimeevents.Event
		wantAction string
	}{
		{
			name: "network security unauthorized connection",
			validation: v1alpha1.RuntimeValidation{
				Name:     "block-external-db",
				Event:    "connect",
				Message:  "unauthorized network connection",
				Severity: "high",
				Conditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["destination.ip"] != "10.0.0.1" && event["destination.ip"] != "10.0.0.2"`,
				}, {
					Expression: `event["destination.port"] == "5432"`,
				}},
				Actions: []v1alpha1.RuntimeActionRef{{Type: "terminate", Message: "terminate compromised pod"}},
			},
			event:      runtimeevents.Event{Type: "connect", Fields: map[string]string{"destination.ip": "8.8.8.8", "destination.port": "5432"}},
			wantAction: "terminate",
		},
		{
			name: "filesystem monitoring sensitive path",
			validation: v1alpha1.RuntimeValidation{
				Name:  "monitor-credential-access",
				Event: "open",
				MatchConditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["file.path"].contains("/etc/kubernetes/pki") || event["file.path"].endsWith(".key")`,
				}},
				Actions: []v1alpha1.RuntimeActionRef{{Type: "log_event"}},
			},
			event:      runtimeevents.Event{Type: "open", Fields: map[string]string{"file.path": "/etc/kubernetes/pki/apiserver.key"}},
			wantAction: "log_event",
		},
		{
			name: "process execution shell detect",
			validation: v1alpha1.RuntimeValidation{
				Name:  "detect-shell",
				Event: "exec",
				Conditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["process.name"] == "/bin/sh" || event["process.name"] == "/bin/bash"`,
				}},
				Actions: []v1alpha1.RuntimeActionRef{{Type: "kill_process"}},
			},
			event:      runtimeevents.Event{Type: "exec", Fields: map[string]string{"process.name": "/bin/sh"}},
			wantAction: "kill_process",
		},
		{
			name: "compliance and auditing",
			validation: v1alpha1.RuntimeValidation{
				Name:  "audit-all-runtime",
				Event: "open",
				Conditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `event["pod.labels.audit-enabled"] == "true"`,
				}},
				Actions: []v1alpha1.RuntimeActionRef{{Type: "generate_report"}},
			},
			event:      runtimeevents.Event{Type: "open", Fields: map[string]string{"pod.labels.audit-enabled": "true"}},
			wantAction: "generate_report",
		},
		{
			name: "threat detection and response",
			validation: v1alpha1.RuntimeValidation{
				Name:  "detect-anomaly",
				Event: "connect",
				Conditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `double(event["anomaly.baseline_deviation"]) > 3.0`,
				}},
				Actions: []v1alpha1.RuntimeActionRef{{Type: "escalate_incident"}},
			},
			event:      runtimeevents.Event{Type: "connect", Fields: map[string]string{"anomaly.baseline_deviation": "4.2"}},
			wantAction: "escalate_incident",
		},
		{
			name: "system performance and behavior",
			validation: v1alpha1.RuntimeValidation{
				Name:  "slow-tcpconnect",
				Event: "tcpconnect",
				Conditions: []v1alpha1.RuntimeCELCondition{{
					Expression: `double(event["latency"]) > 10000.0`,
				}},
				Actions: []v1alpha1.RuntimeActionRef{{Type: "notify_ops"}},
			},
			event:      runtimeevents.Event{Type: "tcpconnect", Fields: map[string]string{"latency": "25000"}},
			wantAction: "notify_ops",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &v1alpha1.RuntimePolicy{Spec: v1alpha1.RuntimePolicySpec{Validations: []v1alpha1.RuntimeValidation{tt.validation}}}
			result := e.EvaluateRuntime(policy, []runtimeevents.Event{tt.event})

			if len(result.Findings) == 0 {
				t.Fatalf("expected at least one finding")
			}
			if len(result.Actions) == 0 {
				t.Fatalf("expected at least one action")
			}
			if result.Actions[0].Type != tt.wantAction {
				t.Fatalf("expected action %q, got %q", tt.wantAction, result.Actions[0].Type)
			}
		})
	}
}
