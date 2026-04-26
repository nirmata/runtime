# Kyverno Runtime Policy Library

This guide describes the built-in policy library that comes with kyverno-runtime. These policies provide immediate, day-1 protection against common runtime threats without requiring you to write custom detection rules.

## Overview

Kyverno Runtime ships with 8 production-ready policies covering the most critical runtime threats:

| Policy | Detects | Severity |
| --- | --- | --- |
| Credential Access | SSH keys, passwords, API credentials | CRITICAL |
| Shell Execution | Shell spawning and script interpreters | HIGH |
| Sensitive File Access | System configs, process metadata | MEDIUM / LOW |
| Public Network Egress | Outbound connections to public IPs | WARNING |
| Metadata Endpoint Access | Cloud credential endpoint access | HIGH |
| Process Discovery | `/proc` filesystem enumeration | LOW |
| Security Tool Disruption | Firewall and audit tool disabling | HIGH |
| Suspicious DNS | C2 and tunnel domain resolution | WARNING |

## Getting Started

### Install with Default Policies

Default policies are enabled by default when you install kyverno-runtime:

```bash
helm install kyverno-runtime ./charts/kyverno-runtime \
  --namespace kyverno-runtime --create-namespace
```

### Check Installed Policies

View the installed policies:

```bash
# List all runtime policies
kubectl get runtimepolicies

# View a specific policy
kubectl describe runtimepolicy detect-shell-execution

# View all findings
kubectl get reports -A
```

### Customize Which Policies Are Enabled

Enable or disable policies during installation:

```bash
# Install without default policies
helm install kyverno-runtime ./charts/kyverno-runtime \
  --set defaultPolicies.enabled=false

# Enable only specific policies
helm install kyverno-runtime ./charts/kyverno-runtime \
  --set defaultPolicies.policies.credentialAccess=true \
  --set defaultPolicies.policies.shellExecution=true \
  --set defaultPolicies.policies.suspiciousDNS=false
```

Or modify after installation:

```bash
helm upgrade kyverno-runtime ./charts/kyverno-runtime \
  --set defaultPolicies.policies.suspiciousDNS=true
```

## Policy Details

### 1. Credential Access Detection

**What it detects:** Attempts to read sensitive credentials from the pod's filesystem.

**Real-world examples:**

- A compromised container reads your AWS credentials (`~/.aws/credentials`)
- Malware tries to steal SSH private keys (`/.ssh/id_rsa`)
- An attacker reads system password files (`/etc/shadow`)

**Findings you'll see:**

- When a pod opens credential files
- Shows file path and process name
- Marked as CRITICAL for SSH keys, HIGH for API credentials

**Example:**

```bash
$ kubectl get reports -n production -o yaml
...
  - rule: cred-access-ssh-key
    severity: critical
    message: "SSH private key access detected"
    evidence:
      file.path: "/.ssh/id_rsa"
      process.name: "/bin/cat"
```

---

### 2. Shell Execution Detection

**What it detects:** Spawning of interactive shells or script interpreters.

**Real-world examples:**

- A web server gets exploited and attacker spawns a reverse shell
- Malware in a container runs `/bin/bash` for interactive access
- A supply-chain compromise executes `python -c` to install a backdoor

**Findings you'll see:**

- When a shell (`/bin/bash`, `/bin/sh`) is spawned
- When script interpreters (`python`, `ruby`, `perl`) are launched
- Marked as HIGH severity for direct action

**Example:**

```bash
$ kubectl describe report shell-execution-findings -n production
...
Rule: execution-shell
Severity: HIGH
Message: Suspicious shell execution detected
Evidence:
  process.name: /bin/bash
  parent.name: /usr/bin/java
```

**Note:** This may trigger false positives if you use legitimate containers that spawn shells for debugging. You can exclude specific namespaces or labels in your policy configuration.

---

### 3. Sensitive File Access Detection

**What it detects:** Reading of system configuration and process metadata files.

**Real-world examples:**

- An attacker reads `/etc/hosts` to map the cluster network
- Reconnaissance reads `/proc/*/status` to enumerate running processes
- An attacker checks `/etc/sudoers` to identify privileged users

**Findings you'll see:**

- When system files are accessed (`/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`)
- When processes enumerate other processes via `/proc`
- Marked as MEDIUM / LOW severity

**Example:**

```bash
$ kubectl get reports -n production
NAME                          SEVERITY  COUNT
process-discovery-findings    LOW       3
config-file-access            LOW       1
```

---

### 4. Public Network Egress Detection

**What it detects:** Outbound network connections to public IP addresses.

**Real-world examples:**

- Data exfiltration: A container connects to attacker's server and sends data
- Malware callback: A compromised pod calls home to a C2 server
- Unauthorized cloud access: A pod connects to external SaaS without authorization

**Findings you'll see:**

- When a pod makes outbound connections to public IPs
- Shows destination IP, port, and data transferred
- Marked as WARNING severity

**Example:**

```bash
$ kubectl describe report exfil-public-network -n production
...
Rule: exfil-public-network
Severity: WARNING
Message: Outbound connection to public IP
Evidence:
  dst.ip: 203.0.113.42
  dst.port: 443
  bytes_sent: 1048576
```

---

### 5. Metadata Endpoint Access Detection

**What it detects:** Connections to cloud metadata service endpoints.

**Real-world examples:**

- An SSRF vulnerability in your app is exploited to access AWS metadata
- Compromised pod queries `169.254.169.254` to steal temporary cloud credentials
- Stolen IAM tokens are used for lateral movement in your cloud infrastructure

**Findings you'll see:**

- When a pod connects to cloud metadata services
- Includes destination IP (AWS, GCP, Alibaba, etc.)
- Marked as HIGH severity

**Example:**

```bash
$ kubectl get reports -n production -o yaml
...
  - rule: metadata-endpoint-access
    severity: high
    message: "Connection to cloud metadata endpoint detected"
    evidence:
      dst.ip: "169.254.169.254"
      dst.port: 80
      process.name: "curl"
```

---

### 6. Process Discovery Detection

**What it detects:** Enumeration of running processes on the node.

**Real-world examples:**

- Attacker enumerates processes to find services running as root
- Post-compromise reconnaissance identifies other workloads for lateral movement
- Malware discovers which security tools are running

**Findings you'll see:**

- When processes read `/proc` filesystem
- Indicates reconnaissance activity
- Marked as LOW severity (reconnaissance, not immediate threat)

---

### 7. Security Tool Disruption Detection

**What it detects:** Disabling of host security tools.

**Real-world examples:**

- Ransomware disables the firewall (`iptables`, `ufw`)
- Backdoor disables audit logging (`auditctl`) to hide tracks
- Rootkit modifies SELinux policies (`semanage`) to evade detection

**Findings you'll see:**

- When security tools are executed with disable flags
- Shows exact tool and command
- Marked as HIGH severity (strong indicator of compromise)

**Example:**

```bash
$ kubectl describe report defense-evasion -n production
...
Rule: defense-evasion-disable
Severity: HIGH
Message: Security tool disruption command executed
Evidence:
  process.name: auditctl
  process.args: "-d"
  user: root
```

---

### 8. Suspicious DNS Resolution Detection

**What it detects:** DNS queries to known attacker infrastructure domains.

**Real-world examples:**

- C2 communication: Compromised pod resolves attacker's command server
- Reverse tunnel: Malware resolves `attacker.ngrok.io` to create a tunnel
- Data exfiltration: Botnet resolves paste service domain to exfiltrate data

**Findings you'll see:**

- When suspicious domains are resolved
- Shows domain and resolved IP
- Marked as WARNING severity

**Example:**

```bash
$ kubectl describe report suspicious-dns -n production
...
Rule: lateral-dns-suspicious
Severity: WARNING
Message: DNS query to suspicious domain
Evidence:
  dns.query: "attacker.ngrok.io"
  dns.response: "203.0.113.50"
```

**Note:** This policy requires DNS event collection to be enabled. Currently disabled by default (`suspiciousDNS: false` in values).

---

## Finding and Investigating Results

### View All Findings

List findings across your cluster:

```bash
# All findings
kubectl get reports -A

# Findings in specific namespace
kubectl get reports -n production

# High-severity findings only
kubectl get reports -A | grep -i "CRITICAL\|HIGH"
```

### Get Details

```bash
# View full report
kubectl describe report <report-name> -n <namespace>

# View as YAML (includes all evidence)
kubectl get report <report-name> -n <namespace> -o yaml

# Watch for new findings in real-time
kubectl get reports -A --watch
```

### Key Fields in Reports

- **Rule**: Which policy rule triggered
- **Severity**: CRITICAL, HIGH, MEDIUM, WARNING, LOW
- **Message**: Human-readable summary
- **Evidence**: Detailed event data (file path, IP, process name, etc.)
- **Count**: How many times this finding occurred
- **Timestamp**: When the finding was last seen

---

## Managing False Positives

Some policies may trigger on legitimate workload behavior. Here are common false positives and how to handle them:

### Shell Execution in Containers

**Problem:** Your debugging containers legitimately spawn shells.

**Solution:** Create a `RuntimePolicyException` to exclude these containers:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicyException
metadata:
  name: exclude-debug-shells
spec:
  exceptions:
  - policyName: detect-shell-execution
    namespaceSelector:
      matchLabels:
        debug: "true"
```

### System Processes Reading Config Files

**Problem:** Your init containers read system config files during startup.

**Solution:** Label those namespaces and create exceptions:

```bash
kubectl label namespace kube-system debug=true
```

### DNS Lookups to Internal Services

**Problem:** You're seeing "suspicious DNS" findings for legitimate internal domains.

**Solution:** Configure whitelist in the policy (requires policy modification) or use exceptions.

---

## Best Practices

### 1. Monitor Before Enforcing

Start policies in **monitor mode** (default) to see what triggers:

```bash
# All default policies run in audit/monitor mode
kubectl get runtimepolicies -o wide
```

Only move to **enforce mode** after you understand the patterns:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: detect-credential-access
spec:
  validationFailureAction: "enforce"  # Blocks violating pods
```

### 2. Correlate with RuntimeBehavior

Use default policies alongside learned baselines for context:

```bash
# View both signatures and baselines
kubectl get runtimepolicies
kubectl get runtimebehaviors -n <namespace>
```

### 3. Log and Archive Findings

Export findings to your security monitoring system (SIEM):

```bash
# Export findings for analysis
kubectl get reports -A -o json > findings.json

# Or set up log forwarding to your observability platform
```

### 4. Tune Policies for Your Environment

Adjust policies to match your environment's risk tolerance:

- Disable policies you don't need (e.g., `suspiciousDNS`)
- Create exceptions for known-good behaviors
- Escalate enforcement gradually namespace by namespace

---

## Common Questions

**Q: Will shell execution detection block my CI/CD pipelines?**

A: Only if running in enforce mode. By default, policies run in audit mode and generate findings without blocking. Test in monitor mode first.

**Q: Why am I seeing too many findings?**

A: Adjust namespace labels, create exceptions, or disable policies not relevant to your threat model. Start with high-severity rules and add others gradually.

**Q: Can I modify default policies?**

A: Yes, you can clone and modify them, but it's recommended to keep defaults as-is and create custom policies for your specific needs.

**Q: Do policies work without Inspektor Gadget?**

A: No, Kyverno Runtime uses Inspektor Gadget for runtime event collection. It's included in the Helm chart by default.

---

## Next Steps

- **View Default Policies**: `kubectl get runtimepolicies`
- **Create Custom Policies**: See [Configuration Guide](configuration.md)
- **Learn About Baselines**: See [RuntimeBehavior Concepts](concepts.md)
- **Set Up SIEM Integration**: See [Alert Routing](configuration.md#alert-sinks)
