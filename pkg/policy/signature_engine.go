package policy

import (
	"context"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

// SignatureRule defines a known attack pattern.
type SignatureRule struct {
	// ID is the unique identifier for this rule.
	ID string
	// Name is a human-readable name.
	Name string
	// Description explains what this rule detects.
	Description string
	// Severity indicates how critical a match is.
	Severity v1alpha1.RuntimeSeverity
	// Patterns are the specific behaviors that trigger this rule.
	Patterns []SignaturePattern
}

// SignaturePattern defines a specific behavior that indicates an attack.
type SignaturePattern struct {
	// EventType is the type of runtime event (exec, open, connect, dns).
	EventType string
	// Match is a predicate function that evaluates the event.
	Match func(exec, open, network, dns string) bool
}

// SignatureEngine detects known attack patterns in runtime events.
type SignatureEngine struct {
	rules map[string]*SignatureRule
}

// NewSignatureEngine creates a new signature detection engine with built-in rules.
func NewSignatureEngine() *SignatureEngine {
	engine := &SignatureEngine{
		rules: make(map[string]*SignatureRule),
	}
	engine.registerBuiltinRules()
	return engine
}

// registerBuiltinRules registers known attack pattern signatures.
func (se *SignatureEngine) registerBuiltinRules() {
	// Rule: Credential Access - SSH Private Key
	se.registerRule(&SignatureRule{
		ID:          "cred-access-ssh-key",
		Name:        "SSH Private Key Access",
		Description: "Detects attempts to read SSH private keys",
		Severity:    v1alpha1.SeverityCritical,
		Patterns: []SignaturePattern{
			{
				EventType: "open",
				Match: func(exec, open, network, dns string) bool {
					return strings.Contains(open, "/.ssh/") || strings.Contains(open, "/id_rsa") || strings.Contains(open, "/id_ed25519")
				},
			},
		},
	})

	// Rule: Credential Access - Shadow/Passwd Files
	se.registerRule(&SignatureRule{
		ID:          "cred-access-shadow",
		Name:        "System Password File Access",
		Description: "Detects attempts to read /etc/shadow or /etc/passwd",
		Severity:    v1alpha1.SeverityCritical,
		Patterns: []SignaturePattern{
			{
				EventType: "open",
				Match: func(exec, open, network, dns string) bool {
					return strings.Contains(open, "/etc/shadow") || strings.Contains(open, "/etc/passwd")
				},
			},
		},
	})

	// Rule: Credential Access - API Keys/Secrets in Common Locations
	se.registerRule(&SignatureRule{
		ID:          "cred-access-keys",
		Name:        "API Key Access",
		Description: "Detects access to common API key/credential locations",
		Severity:    v1alpha1.SeverityError,
		Patterns: []SignaturePattern{
			{
				EventType: "open",
				Match: func(exec, open, network, dns string) bool {
					locations := []string{
						"/.aws/credentials", "/.aws/config",
						"/.docker/config.json",
						"/.kube/config",
						"/.ssh/authorized_keys",
						"/.npmrc", "/.npm",
						".env", ".secrets", ".token",
					}
					for _, loc := range locations {
						if strings.Contains(open, loc) {
							return true
						}
					}
					return false
				},
			},
		},
	})

	// Rule: Execution - Shell Spawning
	se.registerRule(&SignatureRule{
		ID:          "execution-shell",
		Name:        "Shell Spawning",
		Description: "Detects unexpected shell or interpreter execution (potential reverse shell or command injection)",
		Severity:    v1alpha1.SeverityError,
		Patterns: []SignaturePattern{
			{
				EventType: "exec",
				Match: func(exec, open, network, dns string) bool {
					shells := []string{"/bin/sh", "/bin/bash", "/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby"}
					for _, shell := range shells {
						if strings.Contains(exec, shell) {
							return true
						}
					}
					return false
				},
			},
		},
	})

	// Rule: Exfiltration - Public Network Connection from Container
	se.registerRule(&SignatureRule{
		ID:          "exfil-public-network",
		Name:        "Public Network Egress",
		Description: "Detects outbound connections to public IP addresses (potential data exfiltration)",
		Severity:    v1alpha1.SeverityWarning,
		Patterns: []SignaturePattern{
			{
				EventType: "connect",
				Match: func(exec, open, network, dns string) bool {
					// Public IP ranges (simplified)
					blocklist := []string{
						"0.0.0.0/0", // Any external
						"8.8.8.8",   // Google DNS
						"1.1.1.1",   // Cloudflare DNS
					}
					for _, blocked := range blocklist {
						if strings.Contains(network, blocked) {
							return true
						}
					}
					return false
				},
			},
		},
	})

	// Rule: Discovery - Process Enumeration
	se.registerRule(&SignatureRule{
		ID:          "discovery-proc",
		Name:        "Process Discovery",
		Description: "Detects access to /proc filesystem for process enumeration",
		Severity:    v1alpha1.SeverityWarning,
		Patterns: []SignaturePattern{
			{
				EventType: "open",
				Match: func(exec, open, network, dns string) bool {
					return strings.HasPrefix(open, "/proc/") && strings.Contains(open, "status")
				},
			},
		},
	})

	// Rule: Defense Evasion - Disabling Security Tools
	se.registerRule(&SignatureRule{
		ID:          "defense-evasion-disable",
		Name:        "Security Tool Disruption",
		Description: "Detects attempts to disable or interfere with security tools",
		Severity:    v1alpha1.SeverityError,
		Patterns: []SignaturePattern{
			{
				EventType: "exec",
				Match: func(exec, open, network, dns string) bool {
					dangerousCommands := []string{
						"iptables", "ufw", "firewall", "semanage",
						"audit", "auditctl", "systemctl",
					}
					for _, cmd := range dangerousCommands {
						if strings.Contains(exec, cmd) {
							return true
						}
					}
					return false
				},
			},
		},
	})

	// Rule: Lateral Movement - DNS to Suspicious Domain
	se.registerRule(&SignatureRule{
		ID:          "lateral-dns-suspicious",
		Name:        "DNS Lookup to Suspicious Domain",
		Description: "Detects DNS queries to known suspicious domains",
		Severity:    v1alpha1.SeverityWarning,
		Patterns: []SignaturePattern{
			{
				EventType: "dns",
				Match: func(exec, open, network, dns string) bool {
					suspicious := []string{
						".pastebin.com", ".github.io", ".herokuapp.com",
						".ngrok.io", ".localtunnel.me", ".duckdns.org",
					}
					for _, domain := range suspicious {
						if strings.Contains(dns, domain) {
							return true
						}
					}
					return false
				},
			},
		},
	})
}

// registerRule adds a signature rule to the engine.
func (se *SignatureEngine) registerRule(rule *SignatureRule) {
	se.rules[rule.ID] = rule
}

// EvaluateSignatures checks if any signature rules match the given events.
func (se *SignatureEngine) EvaluateSignatures(ctx context.Context, exec, open, network, dns string, enabledRules []string) []SignatureMatch {
	logger := log.FromContext(ctx)
	var matches []SignatureMatch

	// Build a filter map for enabled rules
	enabledMap := make(map[string]bool)
	if len(enabledRules) > 0 {
		// If a list is provided (even if not empty), use it as the filter
		for _, rule := range enabledRules {
			enabledMap[rule] = true
		}
	} else {
		// If no rules specified (nil or empty), enable all
		for ruleID := range se.rules {
			enabledMap[ruleID] = true
		}
	}

	// Evaluate each rule
	for ruleID, rule := range se.rules {
		if !enabledMap[ruleID] {
			continue // Skip disabled rules
		}

		for _, pattern := range rule.Patterns {
			if pattern.Match(exec, open, network, dns) {
				match := SignatureMatch{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					Description: rule.Description,
					Severity:    rule.Severity,
					Pattern:     pattern.EventType,
					Evidence: map[string]string{
						"exec":    exec,
						"open":    open,
						"network": network,
						"dns":     dns,
					},
				}
				matches = append(matches, match)
				logger.Info("signature rule matched", "rule", rule.ID, "severity", rule.Severity, "event", pattern.EventType)
			}
		}
	}

	return matches
}

// SignatureMatch represents a matched signature rule.
type SignatureMatch struct {
	RuleID      string
	RuleName    string
	Description string
	Severity    v1alpha1.RuntimeSeverity
	Pattern     string
	Evidence    map[string]string
}

// GetRules returns all available rules (for listing/debugging).
func (se *SignatureEngine) GetRules() []*SignatureRule {
	var rules []*SignatureRule
	for _, rule := range se.rules {
		rules = append(rules, rule)
	}
	return rules
}

// GetRule returns a specific rule by ID.
func (se *SignatureEngine) GetRule(id string) *SignatureRule {
	return se.rules[id]
}
