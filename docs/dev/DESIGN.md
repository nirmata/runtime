# Kyverno Runtime Prototype Design

## Goal

`kyverno-runtime` runs as a single-process runtime policy controller packaged as a
DaemonSet. It evaluates Pods against runtime-oriented policies and writes findings
into namespaced `PolicyReport` resources, using the same reporting surface Kyverno
already exposes.

The current implementation is a collapsed model: controller, collection,
evaluation, and reporting are all in one binary/process (`cmd/kyverno-runtime`).

For runtime baseline data modeling in kyverno-runtime, the canonical CR name is
`RuntimeBehavior`.

## Architecture Overview

`kyverno-runtime` is a modular DaemonSet controller with clean separation between
policy matching, event collection, evaluation, and reporting, but these modules
run in one process:

### Controller (DaemonSet Pods, One Active Reconciler by Default)

- Watches Pod resources in the cluster
- Lists all `RuntimePolicy` resources
- **Matches** policies to pods using `matchConstraints` and selectors
- **Collects** runtime events using embedded Inspektor Gadget local runtime
- **Evaluates** policies against events using CEL expressions
- **Reports** findings in `PolicyReport` resources
- Runs as a DaemonSet in `kyverno-runtime` namespace

This model eliminates the previous controller/sensor network hop.

Important current behavior:

- The reconciler does not filter pods by node name.
- Deployment defaults to leader election enabled.
- In that default mode, a single active controller instance reconciles cluster
  pods and performs runtime collection from the node where that active instance
  is running.

## Component Responsibilities

### DaemonSet Controller

The controller is composed of four modular pipeline components that process each
reconciled pod through the same pipeline:

#### 1. Matcher

- Validates policy `matchConstraints` (resource/namespace/object rules)
- Checks `namespaceSelector` against pod's namespace labels
- Determines which policies apply to this pod

#### 2. Collector

- Uses `pkg/datasource/inspektor_gadget_source.go`
- Invokes Inspektor Gadget via embedded local runtime
- Uses execution timeout (default 8 seconds) and collection window (default 5 seconds)
- Captures runtime events matching the event types needed by applicable policies
- Returns events as structured data

#### 3. Evaluator

- For each policy, evaluates `matchConditions` (pre-conditions that must all pass)
- If matchConditions pass, evaluates policy `conditions` (CEL expressions over events)
- Generates findings for events that match conditions and severity levels

#### 4. Reporter

- Creates or updates `PolicyReport` resources in the pod's namespace
- Deduplicates findings by fingerprint and updates existing entries with
  `firstTimestamp`, `lastTimestamp`, and `count`
- Stores up to 20 results after dedup/merge
- Updates summary counts and severity tallies

#### Reconciliation Loop:

- Triggered by Pod watch events and explicitly requeued every 15 minutes
- Requeued every 15 minutes to catch new events
- Processes policies per pod through the pipeline manager

## Communication Protocol

### Pipeline Processing Model

Policies apply in a hierarchical filtering model on each pod:

``` text
1. Policy-level matching (matchConstraints — resource/namespace/object rules)
   ↓
   Does policy matchConstraints + selectors match this pod?
   (resourceRules + excludeResourceRules + namespaceSelector + objectSelector)
   ↓ YES
2. Event collection (local Inspektor Gadget)
   ↓
   Collect events for event types needed by this policy
   ↓
3. Validation-level filtering (CEL-based)
   ↓
   Do matchConditions apply to this event?
   (all conditions must pass)
   ↓ YES
4. Validation-level evaluation (CEL-based)
   ↓
   Do conditions match this event?
   (generate findings if all match)
   ↓
5. Report writing
   ↓
   Append findings to PolicyReport
```

#### Local Execution Model

- Event collection, evaluation, and reporting happen inside the same process
- No separate sensor service is required in the main runtime path
- Kubernetes API server is used for policy listing and PolicyReport writes

## Deployment Model

### Single DaemonSet Controller

``` text
DaemonSet Pod (Every Node)
    |
    +---> Inspektor Gadget (embedded local runtime)
    |       |
    |       +---> IG Collection (exec, open, connect)
    |
    +---> Matcher (policy selection)
    |
    +---> Evaluator (CEL expressions)
    |
    +---> Reporter (PolicyReport writer)
    |
    v
API Server
    |
    +---> PolicyReport resources
```

**Key design:**

- Single binary, DaemonSet deployment
- No sensor DaemonSet/service in the current runtime execution path
- Policies are listed from API server per reconciliation
- Reports are written directly to the API server
- Stateless pipeline: no long-lived per-pod event cache

### Current Deployment Semantics

- `cmd/kyverno-runtime/main.go` wires matcher, collector, evaluator, and reporter
  into one reconciler.
- Helm and raw manifests deploy this as a DaemonSet.
- Leader election is enabled by default in chart values and manager manifests.
- Because the reconciler has no nodeName filter, behavior is effectively
  single-active-controller unless leader election is disabled.

## Example Workflow

### Scenario: Detect shell execution in production pods

**Setup:**

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: block-shell-escalation
spec:
  matchConstraints:
    namespaceSelector:
      matchLabels:
        env: production
    resourceRules:
    - apiGroups: [""]
      resources: ["pods"]
  validations:
  - name: detect-shell
    event: exec
    message: Shell execution detected
    severity: high
    matchConditions:
    - name: not-system-pod
      expression: pod.metadata.labels.system != "true"
    conditions:
    - expression: event["process.name"] == "/bin/sh"
    actions:
    - type: terminate
```

**Step-by-step execution (current behavior):**

1. **Active controller instance reconciles a pod**
   - Pod exists in `production` namespace (labeled `env=production`)
   - Reconciliation triggered on pod create/update

2. **Policy matching**
   - Matcher checks: does `matchConstraints` match this pod? ✓
   - Checks: namespace selector match? ✓ (env=production)
   - Checks: pod is a "pods" resource? ✓
   - Result: policy applies to this pod

3. **Event collection (embedded IG local runtime)**
   - Collector extracts event types: `["exec"]`
   - Invokes Inspektor Gadget embedded runtime in-process
   - Gadget collects for 5 seconds, capturing exec events from this pod
   - Events are filtered by pod namespace/name

4. **Policy evaluation**
   - Evaluator processes events
   - For each validation, evaluates matchConditions:
     - `not-system-pod`: checks if pod.metadata.labels.system != "true"
       → ✓ passes
   - Matchconditions passed, now evaluates main conditions:
     - For each event, evaluates CEL condition:
       `event["process.name"] == "/bin/sh"`
     - If match: create finding with severity=high

5. **Report generation**
   - Reporter creates/updates PolicyReport named
     `pod-name-<hash>-block-shell-escalation`
  - Merges by fingerprint when a matching result already exists
  - Updates `lastTimestamp` and increments `count` on repeated matches
   - Summary counts violations

6. **User inspection**

   ```bash
   kubectl get policyreport -n production
   kubectl get policyreport pod-name-xxxx -n production -o yaml
   ```

## Why This Design

### Separation of Concerns

The pipeline is modular, with each component as a replaceable interface:

- **Matcher**: Policy selection logic (can swap label selector implementations)
- **Collector**: Event collection (can swap Inspektor Gadget for eBPF, syscall hooks, etc.)
- **Evaluator**: CEL evaluation (can evolve without touching collection)
- **Reporter**: Report writing (can write to different storage backends)

Each component has unit tests and mocks for easy testing.

### Simplicity

- Single binary to build, test, and deploy
- No controller-to-sensor RPC path in the current runtime flow
- Straightforward pipeline wiring through interfaces (matcher/collector/evaluator/reporter)

### Scalability

- Collection cost is bounded by policy event types and gadget timeouts
- Stateless DaemonSet pods can be restarted freely
- With leader election enabled, only one active reconciler handles the queue

### Extensibility

- Each pipeline component is an interface; mock implementations exist for testing
- Policy-level control is already available (`matchConstraints`)
- CEL expressions allow fine-grained event filtering without code changes
- Validation-level `matchConditions` enable composable pre-filtering
- A standalone sensor package exists in the repo, but is not on the main
  runtime path used by `cmd/kyverno-runtime`

## Future Extensions

- **Real-time streaming**: Replace periodic reconciliation with event-driven
  streaming from Inspektor Gadget for sub-second detection
- **Action execution**: Implement the `actions` field to terminate pods or
  trigger webhooks on policy violations
- **Multi-event correlation**: Correlate events across time and pods for
  more sophisticated attack pattern detection
- **Report aggregation**: Optionally collect reports from all nodes to a
  central policyreport-aggregator for cluster-wide visibility
- **Collection plugins**: Add other collectors (syscall tracing, network
  monitoring, file access) beyond Inspektor Gadget as additional pipeline
  backends

---

## Phase 0: Foundation Alignment

Phase 0 establishes infrastructure for future enhancements without implementing
those features. All Phase 0 feature gates default to `false` for safe operation.

### Feature Gates

Feature gates enable experimental and future capabilities:

- **`baselineEngine`**: Enables `RuntimeBehavior` CRD support for baseline learning
  and enforcement. When enabled, the controller can create, manage, and enforce
  workload runtime profiles. Requires Phase 1 implementation.
- **`signatureEngine`**: Enables signature-based rule detection engine for known
  attack patterns. Runs alongside anomaly detection from `RuntimeBehavior`.
  Requires Phase 1 implementation.
- **`alertSinks`**: Enables external alert sink routing. Directs findings to
  systems like HTTP endpoints, syslog, or Alertmanager in addition to PolicyReport.
  Requires Phase 1 implementation.
- **`alertAggregation`**: Enables cross-rule aggregation and suppression controls.
  Adds cooldown and burst limits for alerts to reduce noise. Requires Phase 1
  implementation.

### Configuration

Feature gates are enabled via CLI flags:

```bash
kyverno-runtime \
  --feature-baseline-engine=true \
  --feature-signature-engine=false \
  --feature-alert-sinks=false \
  --feature-alert-aggregation=false
```

Or via Helm values:

```yaml
featureGates:
  baselineEngine: true
  signatureEngine: false
  alertSinks: false
  alertAggregation: false
```

---

## Phase 1: Baseline Lifecycle and Confidence

Phase 1 implements the `RuntimeBehavior` CRD and baseline learning/enforcement
engine. This requires `--feature-baseline-engine=true`.

### RuntimeBehavior CRD

The `RuntimeBehavior` resource represents the known-good runtime profile for a
workload. It combines admin-defined allowed behaviors with auto-learned
observations and enforces a lifecycle (learning → monitor → enforce) that
controls how deviations are handled.

#### Structure

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: my-app
  namespace: production
spec:
  # Target workload (omit for shared defaults library)
  workloadSelector:
    matchLabels:
      app: my-app

  # Operational mode
  mode: learning   # learning | monitor | enforce

  # Auto-learning parameters
  learning:
    duration: 24h            # How long to observe
    minSamples: 1000         # Minimum events needed
    startAfter: ready        # immediate | ready (wait for pod readiness)

  # Allowed behaviors
  allow:
    exec:
      - /app/server
      - /usr/bin/python3
    open:
      - /app/**
      - /etc/resolv.conf
    network:
      - dst: 10.96.0.0/12
    dns:
      - "*.svc.cluster.local"

    # Reference shared defaults from other RuntimeBehavior resources
    refs:
      - name: enterprise-safe-defaults
        namespace: kyverno-runtime

    # Explicit deny (always blocks, overrides allow)
    deny:
      exec:
        - /bin/sh
        - /bin/bash

status:
  # Lifecycle state
  lifecycle: learning   # learning | partial | completed | stale | failed

  # Quality metrics
  confidence:
    observedFrom: "2026-04-01T00:00:00Z"
    observedTo: "2026-04-02T00:00:00Z"
    sampleCount: 12450
    dropRate: 0.002

  # Auto-learned behaviors
  observed:
    exec:
      - /app/server
      - /usr/bin/curl       # Learned (not in spec.allow)
    open:
      - /etc/hosts
      - /etc/resolv.conf
    network:
      - dst: 10.96.0.1:443
```

#### Lifecycle State Machine

```
          duration met
┌──────────┐ & minSamples    ┌──────────┐   admin        ┌──────────┐
│ learning │ ──────────────> │ monitor  │ ──────────────> │ enforce  │
└──────────┘                 └──────────┘  promotes      └──────────┘
     │                            │                          │
     │ timeout/failure            │ staleness detected       │
     v                            v                          │
┌──────────┐                 ┌──────────┐                   │
│  failed  │                 │  stale   │ <─────────────────┘
└──────────┘                 └──────────┘
                                  │
                                  │ relearn
                                  v
                             ┌──────────┐
                             │ learning │
                             └──────────┘
```

**Lifecycle Descriptions:**

- **learning**: Observation window active. Behaviors are collected in `status.observed`.
  No findings are generated. Auto-transitions to `monitor` when duration + minSamples
  met, or manually via annotation.
- **monitor**: Deviations generate warning-level findings. Admin reviews and tunes
  `spec.allow`. Transitions to `enforce` when ready.
- **enforce**: Deviations trigger enforcement actions from the matching `RuntimePolicy`.
  `status.observed` is updated for audit but doesn't expand the allow set.
- **partial**: Learning is in progress; conditions not yet met for promotion.
- **stale**: Workload image changed or no activity for the staleness window.
  Resets to `learning`.
- **failed**: Learning could not complete (e.g., insufficient samples within timeout).

#### Modes

**`learning` mode:**

- All gadgets for the policy are enabled
- Events are collected and recorded in `status.observed`
- No findings or PolicyReports are generated
- `status.confidence` (sampleCount, dropRate, observedFrom/To) is continuously updated
- Readiness-aware learning: when `spec.learning.startAfter: ready` is set, observation
  begins only after the pod passes its readiness probe, excluding startup noise

**`monitor` mode:**

- Effective allow set = `spec.allow` + referenced shared defaults + `status.observed`
- Deviations generate warning-level findings in PolicyReport
- No enforcement actions taken

**`enforce` mode:**

- Same merged allow set as monitor
- Deviations generate findings with severity from the matching RuntimePolicy
- Enforcement actions (terminate, kill_process, etc.) are executed if configured

#### Shared Defaults Library

A `RuntimeBehavior` without `spec.workloadSelector` acts as a reusable library:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: enterprise-safe-defaults
  namespace: kyverno-runtime
spec:
  # No workloadSelector — this is a shared defaults library
  allow:
    network:
      - dst: proxy.corp.internal:3128
      - dst: 10.0.0.0/8
    dns:
      - "*.corp.internal"
```

Other workload-bound `RuntimeBehavior` resources reference it via `spec.allow.refs`:

```yaml
spec:
  allow:
    refs:
      - name: enterprise-safe-defaults
        namespace: kyverno-runtime
```

#### Merge Precedence

When computing the effective allow set:

1. **Deny rules win**: `spec.allow.deny` always blocks, regardless of other sources
2. **Inline rules**: `spec.allow` (inline) rules take precedence
3. **Shared defaults**: Referenced `RuntimeBehavior` resources (in order)
4. **Observed behaviors**: `status.observed` (auto-learned) fills remaining gaps

#### Integration with RuntimePolicy

`RuntimePolicy` drives the allowed behavior set comparison. When a policy violation
is detected and `featureGates.baselineEngine=true`:

1. Controller fetches the corresponding `RuntimeBehavior` for the workload
2. Computes the merged allow set (spec.allow + refs + observed)
3. Compares the event against the allow set
4. If not allowed, severity is based on the matching validation rule in the policy
5. `status.observed` is updated for audit purposes (if in learning/monitor/enforce)

### Confidence Metadata

The `status.confidence` fields track observation quality:

- **`observedFrom`**: When observation started
- **`observedTo`**: Last observed behavior timestamp
- **`sampleCount`**: Total events observed
- **`dropRate`**: Fraction of dropped events (0.0 to 1.0)

This metadata helps admins decide when learning is mature enough to promote to
monitor or enforce.

### Readiness-Aware Learning

When `spec.learning.startAfter: ready` is set, the controller:

1. Watches the pod until it passes its readiness probe
2. Begins observation only after readiness succeeds
3. Excludes one-time startup behaviors (init scripts, library loading, migrations)

This improves profile fidelity by avoiding false positives from startup noise.

### Example Workflow

1. **Day 0 (optional):** Admin creates `RuntimeBehavior` with pre-populated `spec.allow`
   and `mode: learning` in the production namespace.
2. **Day 0 (auto):** If no `RuntimeBehavior` exists, one is auto-created in `learning`
   mode when a RuntimePolicy first matches a workload.
3. **Learning period:** Events are collected. No alerts fire.
4. **Promotion to monitor:** Admin reviews `status.observed`, adds desired entries to
   `spec.allow`, sets `mode: monitor`.
5. **Monitor period:** Deviations generate warnings. Admin tunes `spec.allow`.
6. **Promotion to enforce:** Admin sets `mode: enforce`. Violations trigger
   enforcement actions.

## Phase 2: Rule Binding Resource

The `RuntimeRuleBinding` CRD maps detection rules to workloads, enabling selective
detection based on workload characteristics and threat models.

### RuntimeRuleBinding Structure

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeRuleBinding
metadata:
  name: ai-agent-detection
spec:
  workloadSelector:
    matchLabels:
      app: ml-inference
      environment: production
  
  # Bind specific rules with wildcards
  ruleSelection:
    include:
      - cred-access-*      # All credential access rules
      - exfil-*            # All exfiltration rules
    exclude:
      - lateral-dns-*      # Exclude lateral movement detection
  
  # Configuration for signature detection
  signatureDetectionConfig:
    enabled: true
    rules:
      - cred-access-keys
      - cred-access-shadow
      - exfil-public-network
  
  # Configuration for anomaly detection
  anomalyDetectionConfig:
    enabled: true
    minConfidence: 0.65
    baseline: default-ml-profile

status:
  matchedWorkloads: 12
  enabledRules: 6
  conditions:
  - type: Ready
    status: "True"
```

### Real-World Scenario: AI Agent Threat Detection

**Workload**: ML inference service running LLM model serving with PII access

**Threats Detected**:
1. Credential access (T1003, T1110) — attempts to read password files
2. API key theft (T1528) — attempts to access AWS/Docker credentials
3. Data exfiltration (T1041) — outbound connections to public IPs

**RuntimeRuleBinding Configuration**:
- Select workloads: `app: ml-inference`
- Enable rules: credential access, exfiltration detection
- Anomaly threshold: 0.65 (balanced sensitivity)

**Expected Findings**:
- **CRITICAL**: /etc/shadow access → blocked via deny rule
- **ERROR**: ~/.aws/credentials access → alerted in monitor, blocked in enforce
- **WARNING**: Outbound to 8.8.8.8 → flagged as potential exfiltration

## Phase 3: Dual Detection Engines

### Signature Detection Engine

The signature engine matches runtime events against 8 built-in threat patterns:

#### Rule: cred-access-ssh-key (CRITICAL)

Detects SSH private key access.

**Real-world scenario**: Compromised container reads `/root/.ssh/id_rsa` to steal
credentials for lateral movement to other infrastructure.

```yaml
spec:
  validations:
  - name: detect-ssh-key-access
    event: open
    message: SSH private key access detected
    severity: critical
    matchConditions:
    - expression: event["fname"].contains("/.ssh/") || event["fname"].contains("/id_rsa")
    actions:
    - type: generate_report
      severity: critical
```

#### Rule: cred-access-keys (ERROR)

Detects API key and credential locations.

**Real-world scenario**: Training job reads `~/.aws/credentials` to steal cloud
provider access tokens for unauthorized API calls.

Patterns detected:
- `~/.aws/credentials`, `~/.aws/config`
- `~/.docker/config.json`
- `~/.kube/config`
- `.env`, `.secrets`, `.token`

#### Rule: exfil-public-network (WARNING)

Detects outbound connections to public IP addresses.

**Real-world scenario**: Malware in production container connects to `8.8.8.8:53`
to exfiltrate stolen training data.

Blocked IPs:
- `8.8.8.8` (Google DNS)
- `1.1.1.1` (Cloudflare DNS)
- `0.0.0.0/0` (any external network)

#### Rule: lateral-dns-suspicious (WARNING)

Detects DNS queries to known C2 domains.

**Real-world scenario**: Compromised training workload resolves `attacker.ngrok.io`
to establish reverse shell for remote access.

Blocked domains:
- `.ngrok.io` (tunnel service)
- `.localtunnel.me` (tunnel service)
- `.duckdns.org` (dynamic DNS)
- `pastebin.com` (data staging)

#### Rule: execution-shell (ERROR)

Detects unexpected shell spawning.

**Real-world scenario**: Log4Shell RCE vulnerability triggers execution of
`/bin/bash -c` for command injection.

Blocked executables:
- `/bin/sh`, `/bin/bash`
- `/usr/bin/python`, `/usr/bin/perl`, `/usr/bin/ruby`

#### Rule: defense-evasion-disable (ERROR)

Detects security tool disruption.

**Real-world scenario**: Backdoor process executes `auditctl -D` to disable
audit logging and hide its tracks.

Blocked commands:
- `iptables`, `ufw`, `firewall`
- `auditctl`, `systemctl`

#### Rule: discovery-proc (WARNING)

Detects /proc filesystem enumeration.

**Real-world scenario**: Attacker enumerates running processes via `/proc/[pid]/status`
to identify high-privilege processes for privilege escalation.

#### Rule: cred-access-shadow (CRITICAL)

Detects system password file access.

**Real-world scenario**: Ransomware reads `/etc/shadow` to extract password
hashes for offline cracking.

### Anomaly Detection Engine

The anomaly engine detects deviations from learned `RuntimeBehavior` baselines
using confidence-based scoring.

#### Confidence Calculation

Confidence = base (0.5) + sample_bonus + drop_rate_bonus + lifecycle_bonus

- **Sample count bonus**: 
  - 1000+ samples: +0.3
  - 100+ samples: +0.2
  - 10+ samples: +0.1
  
- **Drop rate bonus**:
  - <0.1%: +0.2
  - <1%: +0.1
  
- **Lifecycle bonus**:
  - `completed`: +0.1

**Example**: A baseline with 1500 samples, 0.01% drop rate, and `completed`
lifecycle = 0.5 + 0.3 + 0.2 + 0.1 = 1.0 (capped)

#### Real-World Scenario: Behavioral Deviation Detection

**Baseline** (from learning phase):
- Allowed exec: `/usr/local/bin/python`, `/usr/bin/curl`
- Allowed open: `/app/config`, `/var/log/app.log`
- Allowed network: `10.96.0.0/12` (Kubernetes internal)

**Observed Event**: Container executes `/usr/bin/perl script.pl`

**Detection**:
- `/usr/bin/perl` NOT in baseline → anomaly
- Baseline quality: 1200 samples, 0.2% drop rate → confidence 0.8
- MinConfidence threshold: 0.6 → ALERT (0.8 > 0.6)
- Severity: ERROR (from anomaly engine)

**Result**: PolicyReport generated with:
- Rule: `anomaly-deviation-exec`
- Severity: ERROR
- Confidence: 80%
- Pattern: `execution outside learned baseline`

### E2E Validation

Real-world threat scenarios are provided in `testdata/`:

1. **e2e-ai-agent-credential-access.yaml** — credential access detection
2. **e2e-ai-agent-aws-credentials.yaml** — cloud credential exfiltration
3. **e2e-ai-agent-data-exfil.yaml** — data exfiltration to public IPs
4. **e2e-ai-agent-c2-communication.yaml** — C2 communication via tunnels

Deploy on kind cluster:

```bash
kind create cluster --name kyverno-runtime-test
helm install kyverno-runtime ./charts/kyverno-runtime \
  --set featureGates.signatureEngine=true \
  --set featureGates.baselineEngine=true

kubectl apply -f testdata/e2e-ai-agent-credential-access.yaml
sleep 30
kubectl get policyreport -A
```

See [testdata/E2E_TESTING.md](../testdata/E2E_TESTING.md) for comprehensive guide.
