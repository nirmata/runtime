package policy

import (
	"context"
	"testing"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

func TestSignatureEngine_RegisterRule(t *testing.T) {
	engine := NewSignatureEngine()

	// Verify built-in rules are registered
	rules := engine.GetRules()
	if len(rules) == 0 {
		t.Fatal("expected built-in rules, got none")
	}

	// Check specific rule exists
	credAccessRule := engine.GetRule("cred-access-ssh-key")
	if credAccessRule == nil {
		t.Fatal("expected cred-access-ssh-key rule to be registered")
	}

	if credAccessRule.ID != "cred-access-ssh-key" {
		t.Errorf("expected rule ID cred-access-ssh-key, got %s", credAccessRule.ID)
	}

	if credAccessRule.Severity != v1alpha1.SeverityCritical {
		t.Errorf("expected CRITICAL severity for SSH key access, got %s", credAccessRule.Severity)
	}
}

func TestSignatureEngine_EvaluateSignatures_SSHKeyAccess(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	// Simulate reading SSH key
	matches := engine.EvaluateSignatures(ctx, "", "/root/.ssh/id_rsa", "", "", nil)

	if len(matches) == 0 {
		t.Fatal("expected SSH key access to trigger signature match")
	}

	found := false
	for _, match := range matches {
		if match.RuleID == "cred-access-ssh-key" {
			found = true
			if match.Severity != v1alpha1.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", match.Severity)
			}
		}
	}

	if !found {
		t.Error("expected cred-access-ssh-key match not found")
	}
}

func TestSignatureEngine_EvaluateSignatures_ShadowFileAccess(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	// Simulate reading /etc/shadow
	matches := engine.EvaluateSignatures(ctx, "", "/etc/shadow", "", "", nil)

	if len(matches) == 0 {
		t.Fatal("expected shadow file access to trigger signature match")
	}

	found := false
	for _, match := range matches {
		if match.RuleID == "cred-access-shadow" {
			found = true
			if match.Severity != v1alpha1.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", match.Severity)
			}
		}
	}

	if !found {
		t.Error("expected cred-access-shadow match not found")
	}
}

func TestSignatureEngine_EvaluateSignatures_APIKeyAccess(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	tests := []struct {
		name     string
		path     string
		wantRule string
	}{
		{"AWS credentials", "~/.aws/credentials", "cred-access-keys"},
		{"Docker config", "~/.docker/config.json", "cred-access-keys"},
		{"Kube config", "~/.kube/config", "cred-access-keys"},
		{".env file", ".env", "cred-access-keys"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := engine.EvaluateSignatures(ctx, "", tt.path, "", "", nil)

			found := false
			for _, match := range matches {
				if match.RuleID == tt.wantRule {
					found = true
					if match.Severity != v1alpha1.SeverityError {
						t.Errorf("expected ERROR severity, got %s", match.Severity)
					}
					break
				}
			}

			if !found {
				t.Errorf("expected %s rule match for %s", tt.wantRule, tt.path)
			}
		})
	}
}

func TestSignatureEngine_EvaluateSignatures_ShellExecution(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	tests := []struct {
		name    string
		command string
	}{
		{"bash execution", "/bin/bash -c whoami"},
		{"python execution", "/usr/bin/python script.py"},
		{"sh execution", "/bin/sh -i"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := engine.EvaluateSignatures(ctx, tt.command, "", "", "", nil)

			found := false
			for _, match := range matches {
				if match.RuleID == "execution-shell" {
					found = true
					if match.Severity != v1alpha1.SeverityError {
						t.Errorf("expected ERROR severity, got %s", match.Severity)
					}
					break
				}
			}

			if !found {
				t.Errorf("expected execution-shell match for %s", tt.command)
			}
		})
	}
}

func TestSignatureEngine_EvaluateSignatures_PublicNetworkConnection(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	tests := []struct {
		name        string
		destination string
	}{
		{"Google DNS", "8.8.8.8:53"},
		{"Cloudflare DNS", "1.1.1.1:53"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := engine.EvaluateSignatures(ctx, "", "", tt.destination, "", nil)

			found := false
			for _, match := range matches {
				if match.RuleID == "exfil-public-network" {
					found = true
					if match.Severity != v1alpha1.SeverityWarning {
						t.Errorf("expected WARNING severity, got %s", match.Severity)
					}
					break
				}
			}

			if !found {
				t.Errorf("expected exfil-public-network match for %s", tt.destination)
			}
		})
	}
}

func TestSignatureEngine_EvaluateSignatures_DOMTraversal(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	// Simulate /proc filesystem enumeration
	matches := engine.EvaluateSignatures(ctx, "", "/proc/1234/status", "", "", nil)

	found := false
	for _, match := range matches {
		if match.RuleID == "discovery-proc" {
			found = true
			if match.Severity != v1alpha1.SeverityWarning {
				t.Errorf("expected WARNING severity, got %s", match.Severity)
			}
			break
		}
	}

	if !found {
		t.Error("expected discovery-proc match for /proc enumeration")
	}
}

func TestSignatureEngine_EvaluateSignatures_DefenseEvasion(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	tests := []struct {
		name    string
		command string
	}{
		{"iptables disable", "iptables -F"},
		{"auditctl disable", "auditctl -D"},
		{"ufw disable", "ufw disable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := engine.EvaluateSignatures(ctx, tt.command, "", "", "", nil)

			found := false
			for _, match := range matches {
				if match.RuleID == "defense-evasion-disable" {
					found = true
					if match.Severity != v1alpha1.SeverityError {
						t.Errorf("expected ERROR severity, got %s", match.Severity)
					}
					break
				}
			}

			if !found {
				t.Errorf("expected defense-evasion-disable match for %s", tt.command)
			}
		})
	}
}

func TestSignatureEngine_EvaluateSignatures_SuspiciousDNS(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	tests := []struct {
		name   string
		domain string
	}{
		{"ngrok", "attacker.ngrok.io"},
		{"duckdns", "my-reverse-shell.duckdns.org"},
		{"pastebin", "my-paste.pastebin.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := engine.EvaluateSignatures(ctx, "", "", "", tt.domain, nil)

			found := false
			for _, match := range matches {
				if match.RuleID == "lateral-dns-suspicious" {
					found = true
					if match.Severity != v1alpha1.SeverityWarning {
						t.Errorf("expected WARNING severity, got %s", match.Severity)
					}
					break
				}
			}

			if !found {
				t.Errorf("expected lateral-dns-suspicious match for %s", tt.domain)
			}
		})
	}
}

func TestSignatureEngine_EvaluateSignatures_RuleFiltering(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	// Simulate SSH key access but filter to exclude the rule
	enabledRules := []string{"execution-shell"}
	matches := engine.EvaluateSignatures(ctx, "", "/root/.ssh/id_rsa", "", "", enabledRules)

	for _, match := range matches {
		if match.RuleID == "cred-access-ssh-key" {
			t.Error("cred-access-ssh-key should have been filtered out")
		}
	}
}

func TestSignatureEngine_EvaluateSignatures_AllRulesEnabled(t *testing.T) {
	engine := NewSignatureEngine()
	ctx := context.Background()

	// Passing nil enabledRules should enable all rules
	matches := engine.EvaluateSignatures(ctx, "", "/root/.ssh/id_rsa", "", "", nil)

	found := false
	for _, match := range matches {
		if match.RuleID == "cred-access-ssh-key" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected cred-access-ssh-key match when all rules enabled")
	}
}

func TestSignatureEngine_GetRule(t *testing.T) {
	engine := NewSignatureEngine()

	rule := engine.GetRule("cred-access-ssh-key")
	if rule == nil {
		t.Fatal("expected to find cred-access-ssh-key rule")
	}

	if rule.Name != "SSH Private Key Access" {
		t.Errorf("expected 'SSH Private Key Access', got %s", rule.Name)
	}

	nonexistent := engine.GetRule("nonexistent-rule")
	if nonexistent != nil {
		t.Error("expected nil for nonexistent rule")
	}
}

func TestSignatureEngine_GetRules(t *testing.T) {
	engine := NewSignatureEngine()

	rules := engine.GetRules()
	if len(rules) != 8 {
		t.Errorf("expected 8 built-in rules, got %d", len(rules))
	}

	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		ruleIDs[rule.ID] = true
	}

	expectedRules := []string{
		"cred-access-ssh-key",
		"cred-access-shadow",
		"cred-access-keys",
		"execution-shell",
		"exfil-public-network",
		"discovery-proc",
		"defense-evasion-disable",
		"lateral-dns-suspicious",
	}

	for _, expected := range expectedRules {
		if !ruleIDs[expected] {
			t.Errorf("expected rule %s not found", expected)
		}
	}
}
