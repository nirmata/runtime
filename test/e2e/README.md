# E2E Testing: AI Agent Security Threat Detection

This directory contains end-to-end test scenarios demonstrating detection of real-world security threats against AI agent workloads.

## Threat Scenarios

### 1. Credential Access Detection (`runtimepolicy-ai-agent-credential-access.yaml`)

**Attack Scenario**: AI agent workload attempts to read password files or system credentials
**Threat Model**: T1110 (Brute Force) via credential enumeration, T1003 (OS Credential Dumping)

**What Gets Detected**:

- Attempts to read `/etc/shadow` (CRITICAL)
- Attempts to read `/etc/passwd` (CRITICAL)
- Attempts to read `/.ssh/` directory (CRITICAL)

**Real-World Example**: Compromised LLM container attempts to escalate privileges by reading system password hashes.

### 2. AWS Credential Exfiltration (`runtimepolicy-ai-agent-aws-credentials.yaml`)

**Attack Scenario**: AI agent workload attempts to access cloud provider credentials
**Threat Model**: T1528 (Steal Application Access Token), T1552.007 (Unsecured Credentials)

**What Gets Detected**:

- Attempts to read `/.aws/credentials` (ERROR)
- Attempts to read `/.aws/config` (ERROR)
- Attempts to read `/.docker/config.json` (ERROR)
- Attempts to read `/.kube/config` (ERROR)

**Real-World Example**: Compromised ML inference service container tries to steal AWS credentials to access other resources or move laterally to cloud infrastructure.

### 3. Data Exfiltration Detection (`runtimepolicy-ai-agent-data-exfil.yaml`)

**Attack Scenario**: AI agent workload attempts to exfiltrate sensitive data to public IPs
**Threat Model**: T1041 (Exfiltration Over C2 Channel), T1020 (Automated Exfiltration)

**What Gets Detected**:

- Outbound connections to public DNS servers (8.8.8.8, 1.1.1.1) (WARNING)
- Network connections to non-whitelisted public IPs (WARNING)
- Unrecognized DNS queries outside approved domains (WARNING)

**Real-World Example**: Compromised AI model serving container attempts to send PII or training data to attacker-controlled servers.

### 4. Command & Control (C2) Communication (`runtimepolicy-ai-agent-c2-communication.yaml`)

**Attack Scenario**: AI agent workload attempts to establish command & control communication
**Threat Model**: T1071 (Application Layer Protocol), T1001 (Data Obfuscation)

**What Gets Detected**:

- DNS queries to ngrok.io, localtunnel.me, duckdns.org (WARNING)
- Shell execution attempts (ERROR)
- Security tool disruption attempts - iptables, auditctl (CRITICAL)

**Real-World Example**: Compromised training job attempts to establish reverse shell or maintain persistence via tunnel services.

## Architecture

Each scenario demonstrates the complete detection pipeline:

1. **RuntimeBehavior** - Defines expected (whitelist) behavior for the workload
   - Learning mode to establish baseline
   - Enforce mode to prevent deviations

2. **RuntimePolicy** - Defines signature detection and response actions
   - Alert (log finding to OpenReports `Report` resources)
   - Monitor (record but don't block)
   - Block (prevent execution)

3. **Signature Detection Engine** - Pattern matching against known threats
   - 8 built-in rules covering common attack techniques
   - Severity levels: CRITICAL, ERROR, WARNING, INFO
   - Evidence collection for investigations

4. **Anomaly Detection Engine** - Baseline deviation detection
   - Compares against learned RuntimeBehavior baseline
   - Confidence scoring based on baseline quality
   - Respects explicit deny rules

## Running E2E Tests on Kind Cluster

### Prerequisites

```bash
# Required tools
kind version
kubectl version --client
helm version
ko version
```

### Setup

```bash
# Create or select a kind cluster
kind create cluster --name runtime || true
kubectl config use-context kind-runtime

# Build, load, and install kyverno-runtime into the active kind cluster.
make kind-install KIND_CLUSTER_NAME=runtime IMAGE_TAG=e2e-docs

# Verify CRDs and runtime are present.
kubectl get pods -n kyverno-runtime
kubectl get crd reports.openreports.io
```

### Test Execution

```bash
# Test 1: Credential Access Detection
kubectl apply -f samples/runtimepolicy-ai-agent-credential-access.yaml
sleep 30
# Verify reports generated with critical findings
kubectl get reports -A

# Test 2: AWS Credential Exfiltration
kubectl apply -f samples/runtimepolicy-ai-agent-aws-credentials.yaml
sleep 30
kubectl get reports -A
# Should show blocked file open attempts for /.aws/credentials

# Test 3: Data Exfiltration Detection
kubectl apply -f samples/runtimepolicy-ai-agent-data-exfil.yaml
sleep 30
kubectl get reports -A
# Should show public IP connection attempts as anomalies

# Test 4: C2 Communication Detection
kubectl apply -f samples/runtimepolicy-ai-agent-c2-communication.yaml
sleep 30
kubectl get reports -A
# Should show ngrok.io DNS queries blocked/alerted
```

### Verify Detections

```bash
# View report details
kubectl get reports -A -o yaml

# View kyverno-runtime logs for detection events
kubectl logs -n kyverno-runtime -l app.kubernetes.io/name=kyverno-runtime -f
```

## Expected Findings

### Credential Access Test

- **Severity**: CRITICAL
- **Rules Triggered**: cred-access-shadow, cred-access-ssh-key, cred-access-keys
- **Action**: BLOCKED (explicit deny in RuntimeBehavior)

### AWS Credential Test

- **Severity**: CRITICAL
- **Rules Triggered**: cred-access-keys
- **Action**: BLOCKED (in enforce mode)

### Data Exfiltration Test

- **Severity**: WARNING
- **Rules Triggered**: exfil-public-network, anomaly deviation
- **Action**: BLOCKED (explicit deny rules + anomaly > minConfidence)

### C2 Communication Test

- **Severity**: CRITICAL (for defense evasion), WARNING (for DNS)
- **Rules Triggered**: lateral-dns-suspicious, defense-evasion-disable, execution-shell
- **Action**: BLOCKED (anomaly + signature match)

## Integration with Your CD/CI

Add to your pipeline:

```bash
# Before running workloads, verify kyverno-runtime is healthy
kubectl get pods -n kyverno-runtime
kubectl get daemonset -n kyverno-runtime

# Deploy test scenario
kubectl apply -f samples/runtimepolicy-ai-agent-<scenario>.yaml

# Wait for events to be collected
sleep 30

# Verify no critical findings slip through
CRITICAL=$(kubectl get reports -A -o yaml | grep -ci 'severity: critical' || true)
if [ $CRITICAL -gt 0 ]; then
  echo "CRITICAL findings detected - security threat blocked!"
   kubectl get reports -A -o yaml
  exit 1
fi
```

## Threat Intelligence

These scenarios are based on real attack chains observed against AI/ML infrastructure:

1. **LLM Container Privilege Escalation**: Compromised LLM reads password files to escalate
2. **Supply Chain Attacks**: Poisoned training data pulls credentials from environment
3. **Sidecar Injection**: Attacker injects container reading model weights to exfiltrate
4. **Model Extraction**: Attacker extracts model via API and exfils to S3 bucket
5. **Persistent Access**: Attacker establishes C2 via tunnel service (ngrok, localtunnel)

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Container Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Kyverno](https://kyverno.io)
