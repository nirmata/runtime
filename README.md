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
make kind

# Verify Installation
kubectl --context kyverno-runtime get pods -n kyverno-runtime
kubectl --context kyverno-runtime get ds -A
kubectl describe pod -n kyverno-runtime -l app.kubernetes.io/name=kyverno-runtime | grep -E "Image:|Image ID:"
kubectl get crd runtimepolicies.runtime.kyverno.io
kubectl get crd runtimebehaviors.runtime.kyverno.io
kubectl get crd runtimerulebindings.runtime.kyverno.io
kubectl get crd policyreports.wgpolicyk8s.io
```

## RuntimePolicy Example

Create a test namespace and pod:

```bash
kubectl create ns runtime-demo
kubectl label ns runtime-demo runtime-monitor=enabled --overwrite
kubectl -n runtime-demo run demo --image=busybox:1.36 --restart=Never --command -- sh -c 'sleep infinity'
kubectl -n runtime-demo wait --for=condition=Ready pod/demo --timeout=120s
```

Apply sample policy and trigger activity. The controller streams eBPF events continuously
for all matching pods. Each triggered event is evaluated against policies and deduplicated findings
are reported:

```bash
# File-open detection policy
kubectl apply -f testdata/e2e-live-trace-policy.yaml

# Trigger file-open events (cat /etc/hosts multiple times)
kubectl -n runtime-demo exec demo -- sh -c 'for i in $(seq 1 25); do cat /etc/hosts >/dev/null; sleep 0.1; done'

# Network-egress detection policy
kubectl apply -f testdata/runtimepolicy-network-egress-check.yaml

# Trigger network egress events (connect to public IPs)
kubectl -n runtime-demo exec demo -- sh -c 'for i in $(seq 1 10); do nc -w 1 -zv 8.8.8.8 53 || true; done'
```

Check policy reports. Writes are buffered by default, so allow 5-10 seconds after
triggering activity before you expect both reports to appear:

```bash
# Summary view
kubectl get policyreport -n runtime-demo

# Detailed findings (shows which rules matched)
kubectl get policyreport -n runtime-demo -o yaml
```

**Expected output**:

- Two PolicyReports for the `demo` pod: one labeled `e2e-live-trace-open` and one labeled `detect-public-egress-quickstart`
- PolicyReport names match pod: `demo-<hash>`
- The open report typically shows `FAIL=1`
- The network report may show `FAIL=1` or `FAIL=2` because a single `nc` can emit both `connect` and `close` events
- Results detail shows which policy and rule generated each finding

If reports are empty, check controller logs:

```bash
kubectl -n kyverno-runtime logs -l app.kubernetes.io/name=kyverno-runtime --tail=100 | grep -E "(policy-evaluator|evaluating)"
```

**Troubleshooting**:

- File-open findings not appearing: Verify `cat /etc/hosts` executed (generates no output but affects system)
- Network findings not appearing: Verify `nc` connects successfully (shows `open` in output) and wait at least 5-10 seconds before rechecking reports
- Only the open report appears at first: The buffered reporter has not flushed the network finding yet; re-run `kubectl get policyreport -n runtime-demo -o yaml` after a few more seconds
- No findings at all: Check controller logs with the command above and confirm both policies exist with `kubectl get runtimepolicy -A`

Sample runtime policies:

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
    conditions:
    - expression: '("fname" in event && event["fname"].contains("/etc/hosts")) || ("file.path" in event && event["file.path"].contains("/etc/hosts")) || ("path" in event && event["path"].contains("/etc/hosts")) || ("fullPath" in event && event["fullPath"].contains("/etc/hosts"))'
    actions:
    - type: generate_report
      message: Sensitive file access detected
```

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: detect-public-egress
spec:
  namespaceSelector:
    matchLabels:
      runtime-monitor: "enabled"
  validations:
  - name: detect-public-network-egress
    event: tcpconnect
    message: Public network egress detected
    severity: high
    conditions:
    - expression: '(("destination.ip" in event) && (event["destination.ip"] == "8.8.8.8" || event["destination.ip"] == "1.1.1.1")) || (("dst.addr" in event) && (event["dst.addr"] == "8.8.8.8" || event["dst.addr"] == "1.1.1.1"))'
    actions:
    - type: generate_report
      message: Outbound connection to a disallowed public destination
```

```bash
kubectl apply -f testdata/e2e-live-trace-policy.yaml

# Generate open events
kubectl -n runtime-demo exec demo -- sh -c 'for i in $(seq 1 10); do cat /etc/hosts >/dev/null; sleep 0.1; done'

# Check for policy violations in the report (writes are buffered; allow a few seconds)
kubectl get policyreport -n runtime-demo
```

Expected behavior after RuntimeBehavior implementation is complete:

- Disallowed network destinations should produce anomaly/findings based on `mode` and allow/deny rules.
- Baseline-consistent destinations should not produce RuntimeBehavior findings.

Additional RuntimeBehavior sample manifests:

- [testdata/runtimebehavior-deny-loopback-metadata.yaml](testdata/runtimebehavior-deny-loopback-metadata.yaml)
- [testdata/runtimebehavior-restrict-sensitive-files.yaml](testdata/runtimebehavior-restrict-sensitive-files.yaml)

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
applies chart CRDs before running Helm install/upgrade with matching image values.

## Raw Manifests Install

```bash
kubectl apply -f config/crd/bases/runtime.kyverno.io_runtimepolicies.yaml
kubectl apply -f config/crd/bases/runtime.kyverno.io_runtimebehaviors.yaml
kubectl apply -f config/crd/bases/runtime.kyverno.io_runtimerulebindings.yaml
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

- [testdata/runtimepolicy-network-egress-check.yaml](testdata/runtimepolicy-network-egress-check.yaml)
- [testdata/runtimepolicy-usecases.yaml](testdata/runtimepolicy-usecases.yaml)
- [testdata/e2e-live-all-usecases.yaml](testdata/e2e-live-all-usecases.yaml)
- [testdata/e2e-live-trace-policy.yaml](testdata/e2e-live-trace-policy.yaml)
- [testdata/sample-runtimepolicy.yaml](testdata/sample-runtimepolicy.yaml)
- [testdata/runtimebehavior-demo-network-baseline-enforce.yaml](testdata/runtimebehavior-demo-network-baseline-enforce.yaml)
- [testdata/runtimebehavior-deny-loopback-metadata.yaml](testdata/runtimebehavior-deny-loopback-metadata.yaml)
- [testdata/runtimebehavior-restrict-sensitive-files.yaml](testdata/runtimebehavior-restrict-sensitive-files.yaml)
