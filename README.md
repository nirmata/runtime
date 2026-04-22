# Kyverno Runtime

Kyverno Runtime evaluates runtime activity from running Pods against `RuntimePolicy` rules and reports findings to namespaced `PolicyReport` resources.

## Architecture

Kyverno Runtime runs as a single DaemonSet. It uses Inspektor Gadget to listen to eBPF events based on configured policies.

- One `kyverno-runtime` Pod runs per node.
- Each kyverno-runtime pod watches workload Pods, collects events locally with embedded Inspektor Gadget runtime, evaluates matching runtime policies, and writes `PolicyReport` results.
- For runtime behavior baseline persistence and APIs, kyverno-runtime supports `RuntimeBehavior` resources (Phase 1, disabled by default).

See [Design](docs/dev/DESIGN.md) and [Plan](docs/dev/PLAN.md) for details.

## Prerequisites

- Linux Kubernetes nodes (required for eBPF collection)
- `kind`, `kubectl`, `helm`
- `ko` for local image builds (`go install github.com/google/ko@latest`)

## Quick Start (Kind)

```bash
# Create kind cluster, load image into kind nodes, and install chart
make kind-all

# Verify Installation
kubectl --context kyverno-runtime get pods -n kyverno-runtime
kubectl --context kyverno-runtime get ds -A
kubectl describe pod -n kyverno-runtime -l app.kubernetes.io/name=kyverno-runtime | grep -E "Image:|Image ID:"
kubectl get crd runtimepolicies.runtime.kyverno.io
kubectl get crd policyreports.wgpolicyk8s.io
```

## RuntimePolicy Example

Create a test namespace and pod:

```bash
kubectl create ns runtime-demo
kubectl label ns runtime-demo runtime-monitor=enabled --overwrite
kubectl -n runtime-demo run demo --image=busybox:1.36 --restart=Never --command -- sh -c 'sleep 300'
kubectl -n runtime-demo wait --for=condition=Ready pod/demo --timeout=120s
```

Apply sample policy and trigger activity. The controller streams eBPF events continuously
for all matching pods, so no manual trigger is needed:

```bash
kubectl apply -f testdata/e2e-live-trace-policy.yaml
# Generate open events — the controller will detect them in real time.
kubectl -n runtime-demo exec demo -- sh -c 'for i in $(seq 1 25); do cat /etc/hosts >/dev/null; sleep 0.1; done'
```

Check policy reports:

```bash
kubectl get policyreport -n runtime-demo
```

If no report is created yet, check controller logs:

```bash
kubectl -n kyverno-runtime logs -l app.kubernetes.io/name=kyverno-runtime --tail=200
kubectl get policyreport -n runtime-demo
```

### Quick Start Smoke Check

Use this one-command smoke test to run the same manual flow above with
assertions and troubleshooting output:

```bash
make smoke-quickstart
```

For pre-merge local validation (build + deploy + smoke):

```bash
make premerge-smoke
```

Sample runtime policy:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: detect-sensitive-open
spec:
  namespaceSelector:
    matchLabels:
      runtime-monitor: "enabled"
  validations:
  - name: detect-etc-hosts-open
    event: open
    message: Access to /etc/hosts detected
    severity: high
    matchConditions:
    - expression: event["fname"].contains("/etc/hosts") || event["file.path"].contains("/etc/hosts")
    actions:
    - type: generate_report
      message: Sensitive file access detected
```

## RuntimeBehavior Example (Baseline Learning)

`RuntimeBehavior` defines the known-good runtime profile for a workload and drives anomaly detection.

> **Current implementation**: `enforce` mode generates `PolicyReport` findings (severity: high) for
> any deviation from the allow list. Active enforcement actions (process termination, network blocking)
> are planned for a future phase. Use a `RuntimePolicy` with a `terminate` action today for hard enforcement.

Create a baseline for allowed network access. `allow.network` entries are plain CIDR strings;
`allow.deny.network` entries are CIDRs that always generate findings regardless of the allow list:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: demo-network-baseline
  namespace: runtime-demo
spec:
  workloadSelector:
    matchLabels:
      app: demo
  mode: learning
  allow:
    network:
      - 10.0.0.0/8       # Kubernetes internal
      - 172.16.0.0/12    # Kubernetes internal
      - 192.168.0.0/16   # Kubernetes internal
    deny:
      network:
        - 8.8.8.8         # Always flag access to known public IPs
        - 1.1.1.1
```

Then promote to `enforce` mode to generate findings for disallowed connections:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: demo-network-baseline
  namespace: runtime-demo
spec:
  workloadSelector:
    matchLabels:
      app: demo
  mode: enforce
  allow:
    network:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
    deny:
      network:
        - 8.8.8.8
        - 1.1.1.1
```

Label the demo pod and check for anomaly findings:

```bash
kubectl -n runtime-demo label pod demo app=demo --overwrite

# Generate a connect event to an external IP
kubectl -n runtime-demo exec demo -- sh -c 'nc -zv 8.8.8.8 443 2>&1; true'

# Check for policy violations in the report
kubectl get policyreport -n runtime-demo
```

## Build and Test

```bash
make build
go test ./...
```

## Helm Install

```bash
helm upgrade --install kyverno-runtime ./charts/kyverno-runtime \
  --namespace kyverno-runtime --create-namespace --wait
```

For local kind development, use:

```bash
make kind-install
```

This target builds the local image, loads it into the kind cluster nodes, and
then runs the Helm install/upgrade with matching image values.

## Raw Manifests Install

```bash
kubectl apply -f config/crd/bases/runtime.kyverno.io_runtimepolicies.yaml
kubectl apply -f config/crd/bases/wgpolicyk8s.io_policyreports.yaml
kubectl apply -f config/rbac/service_account.yaml
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/rbac/role_binding.yaml
kubectl apply -f config/manager/deployment.yaml
```

## Controller Flags

### Runtime Configuration

- `--inspektor-gadget-timeout=8s`: Timeout for inspektor gadget runtime initialization.
- `--metrics-bind-address=:8080`: The address the metric endpoint binds to.
- `--health-probe-bind-address=:8081`: The address the probe endpoint binds to.
- `--leader-elect`: Enable leader election for controller manager.

### Report Buffering (Event Throttling)

Event buffering batches PolicyReport updates to reduce API server load and prevent alert storms:

- `--report-buffer-interval=5s` (default for new installs): Flush reports every 5 seconds. Balances alert latency vs. batching efficiency.
- `--report-buffer-max-count=500` (default for new installs): Flush reports after 500 findings. Prevents unbounded memory growth and enforces maximum latency even under high load.

**Tuning**: On busy clusters, reduce `maxCount` to 100-200 for lower latency. On quiet clusters, increase interval to 30s and maxCount to 1000 to reduce API server load.

### Feature Gates

Feature gates control detection capabilities and alert handling. Recommended defaults for new installations are:

| Gate | Default | Purpose |
|------|---------|---------|
| `--feature-baseline-engine` | **enabled** | Enable baseline learning via `RuntimeBehavior` CRD. Tracks allowed exec, open, network, and DNS patterns per workload. |
| `--feature-signature-engine` | **enabled** | Enable 8 built-in threat detection rules for known attack patterns (credential access, shell execution, exfiltration, C2 communication, etc.). |
| `--feature-alert-sinks` | disabled | Route findings to external systems (HTTP, syslog, alertmanager, etc.). Enable only if you have external alerting infrastructure. |
| `--feature-alert-aggregation` | **enabled** | Prevent alert storms with cooldown and burst limits. Critical for throttling high-volume threat detections. |

**Note**: Sensible defaults are enabled for new installations (baseline + signature + aggregation). For existing clusters with high workload churn, you can selectively disable features or tune alert aggregation to avoid disruption.

## Dual Detection Engines

Kyverno Runtime now includes two complementary detection engines for comprehensive threat detection:

### Signature-Based Detection (8 Built-in Rules)

Detects known attack patterns through pattern matching:

| Rule | Severity | Purpose | Real-World Example |
|------|----------|---------|--------------------|
| `cred-access-ssh-key` | CRITICAL | SSH private key access | Compromised LLM steals /root/.ssh/id_rsa |
| `cred-access-shadow` | CRITICAL | System password file access | Ransomware reads /etc/shadow for brute force |
| `cred-access-keys` | ERROR | API key/credential locations | Training job steals ~/.aws/credentials |
| `execution-shell` | ERROR | Unexpected shell spawning | Log4Shell RCE spawns reverse shell |
| `exfil-public-network` | WARNING | Public IP connections | Malware exfils data to 8.8.8.8 |
| `discovery-proc` | WARNING | /proc enumeration | Attacker enumerates processes in /proc |
| `defense-evasion-disable` | ERROR | Security tool disruption | Backdoor disables auditd |
| `lateral-dns-suspicious` | WARNING | C2 domain queries | Compromised workload queries ngrok.io |

Enable with: `--feature-signature-engine=true`

### Anomaly-Based Detection

Detects deviations from learned behavioral baselines using `RuntimeBehavior` profiles:

- **Baseline Learning**: Observe allowed behaviors during learning phase
- **Confidence Scoring**: Quality metrics (sample count, drop rate, lifecycle) drive detection confidence
- **Threshold-Based Alerting**: `minConfidence` parameter suppresses low-confidence findings

Enable with: `--feature-baseline-engine=true`

### RuntimeRuleBinding: Selective Detection

Control which rules apply to which workloads using `RuntimeRuleBinding` resource:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeRuleBinding
metadata:
  name: ai-threat-detection
spec:
  workloadSelector:
    matchLabels:
      app: ml-inference
  ruleSelection:
    include:
      - cred-access-*
      - exfil-*
  signatureDetectionConfig:
    enabled: true
    rules:
      - cred-access-keys
      - exfil-public-network
  anomalyDetectionConfig:
    enabled: true
    minConfidence: 0.7
```

### Real-World E2E Scenarios

Test realistic threat scenarios with example manifests:

```bash
# Credential access detection
kubectl apply -f testdata/e2e-ai-agent-credential-access.yaml

# AWS credential exfiltration  
kubectl apply -f testdata/e2e-ai-agent-aws-credentials.yaml

# Data exfiltration to public IPs
kubectl apply -f testdata/e2e-ai-agent-data-exfil.yaml

# C2 communication via tunnel services
kubectl apply -f testdata/e2e-ai-agent-c2-communication.yaml
```

See [testdata/E2E_TESTING.md](testdata/E2E_TESTING.md) for comprehensive deployment guide and threat intelligence mapping.

### Logging Flags

- `--zap-log-level=<level>`: Log level (debug, info, warn, error). Defaults to `info`.
- `--zap-devel=true|false`: Enable development mode logging. Defaults to `false`.

## Samples

- [testdata/runtimepolicy-usecases.yaml](testdata/runtimepolicy-usecases.yaml)
- [testdata/e2e-live-all-usecases.yaml](testdata/e2e-live-all-usecases.yaml)
- [testdata/e2e-live-trace-policy.yaml](testdata/e2e-live-trace-policy.yaml)
- [testdata/sample-runtimepolicy.yaml](testdata/sample-runtimepolicy.yaml)
