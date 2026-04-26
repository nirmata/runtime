# Kyverno Runtime Prototype Design

## Goal

`kyverno-runtime` runs as a single-process runtime policy controller packaged as a
DaemonSet. It evaluates Pods against runtime-oriented policies and writes findings
into namespaced OpenReports `Report` resources.

The current implementation is a collapsed model: controller, collection,
evaluation, and reporting are all in one binary/process (`cmd/kyverno-runtime`).

For runtime baseline data modeling in kyverno-runtime, the canonical CR name is
`RuntimeBehavior`.

## Design Decisions (April 2026)

The current design is intentionally simplified for operational adoption.

1. `RuntimePolicy` remains the primary detection rule API and ships with a
  default cluster-scoped library for day-1 protection.
2. `RuntimeBehavior` is workload-specific and is auto-created by the controller
  for enrolled workloads.
3. RuntimeBehavior enrollment is security-team controlled (default-on,
  monitor-first), with opt-out handled through explicit exception controls.

## Architecture Overview

`kyverno-runtime` is a modular DaemonSet controller with clean separation between
policy matching, event collection, evaluation, and reporting, but these modules
run in one process:

### Controller (DaemonSet Pods, One Active Reconciler by Default)

- Watches Pod resources in the cluster
- Lists all cluster-scoped `RuntimePolicy` resources
- **Matches** policies to pods using `matchConstraints` and selectors
- **Collects** runtime events using embedded Inspektor Gadget local runtime
- **Evaluates** policies against events using CEL expressions
- **Reports** findings in OpenReports `Report` resources
- Runs as a DaemonSet in `kyverno-runtime` namespace

This model eliminates the previous controller/sensor network hop.

Important current behavior:

- The reconciler supports node-local pod filtering via `NODE_NAME`.
- Deployment defaults to leader election enabled.
- In that default mode, a single active controller instance reconciles cluster
  pods and performs runtime collection from the node where that active instance
  is running.

## Component Responsibilities

### DaemonSet Controller

The controller is composed of four modular pipeline components that process each
reconciled pod through the same pipeline:

Runtime policy scope model:

- `RuntimePolicy` is cluster-scoped and centrally managed.
- Workload targeting remains per-namespace/per-pod through `matchConstraints`
  and selectors in each policy.

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

Collector metadata filtering semantics (to avoid node-level noise while keeping
gadget compatibility):

| Event type | Missing k8s namespace/pod metadata | Behavior |
| --- | --- | --- |
| `connect`, `tcpconnect` | dropped | prevents unrelated system-process network events from polluting pod reports |
| `open`, `exec` | retained | these gadgets can surface valid workload events even when metadata is sparse |

#### 3. Evaluator

- For each policy, evaluates `matchConditions` (pre-conditions that must all pass)
- If matchConditions pass, evaluates policy `conditions` (CEL expressions over events)
- Generates findings for events that match conditions and severity levels

#### 4. Reporter

- Creates or updates OpenReports `Report` resources in the pod's namespace
- Deduplicates findings by fingerprint and updates existing entries with
  `firstTimestamp`, `lastTimestamp`, and `count`
- Stores up to a configurable max results value (default: 1000) after dedup/merge
- Keeps the latest entries by `lastTimestamp` and trims older ones
- Adds annotation `runtime.kyverno.io/truncated-results` when trim occurs
- Updates summary counts and severity tallies
- Skips update calls at capacity for pure duplicate-count increments to reduce
  API server churn

Reporter and datasource metrics exposed on `/metrics`:

- `kyverno_runtime_datasource_events_dropped_no_metadata_total{event_type=...}`
- `kyverno_runtime_reporter_results_truncated_total`
- `kyverno_runtime_reporter_updates_skipped_total{reason=...}`
- `kyverno_runtime_reporter_writes_total{operation=...,result=...}`

#### Reconciliation Loop

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
  Append findings to OpenReports Report
```

#### Local Execution Model

- Event collection, evaluation, and reporting happen inside the same process
- No separate sensor service is required in the main runtime path
- Kubernetes API server is used for policy listing and OpenReports writes

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
    +---> Reporter (OpenReports writer)
    |
    v
API Server
    |
    +---> Report resources
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
- When `NODE_NAME` is injected (downward API), the reconciler skips pods whose
  `pod.spec.nodeName` does not match the local node, preventing off-node watch
  churn while preserving backward-compatible behavior when `NODE_NAME` is empty.

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

1. **Policy matching**
   - Matcher checks: does `matchConstraints` match this pod? ✓
   - Checks: namespace selector match? ✓ (env=production)
   - Checks: pod is a "pods" resource? ✓
   - Result: policy applies to this pod

1. **Event collection (embedded IG local runtime)**
   - Collector extracts event types: `["exec"]`
   - Invokes Inspektor Gadget embedded runtime in-process
   - Gadget collects for 5 seconds, capturing exec events from this pod
   - Events are filtered by pod namespace/name

1. **Policy evaluation**
   - Evaluator processes events
   - For each validation, evaluates matchConditions:
     - `not-system-pod`: checks if pod.metadata.labels.system != "true"
       → ✓ passes
   - Matchconditions passed, now evaluates main conditions:
     - For each event, evaluates CEL condition:
       `event["process.name"] == "/bin/sh"`
     - If match: create finding with severity=high

1. **Report generation**

  Reporter creates or updates a Report named
  `pod-name-<hash>-block-shell-escalation`.
  It merges by fingerprint when a matching result already exists,
  updates `lastTimestamp`, increments `count` on repeated matches,
  and updates summary counts.

1. **User inspection**

```bash
kubectl get reports -n production
kubectl get report pod-name-xxxx -n production -o yaml
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
- **Extended enforcement actions**: Implement additional action types beyond audit:
  - `terminate`: Forcefully terminate the pod/workload
  - `kill_process`: Kill a specific process within the container
  - `webhook`: Trigger external webhooks for integration with SOAR/SIEM systems
  - `escalate_incident`: Escalate findings to incident management systems
  - `notify`: Send notifications to teams via email, Slack, Teams, etc.

  Currently, only `audit` actions are implemented, which record findings to the `Report` CRD.
  Other action types are reserved for future implementation when enforcement mechanisms
  become available.
- **Multi-event correlation**: Correlate events across time and pods for
  more sophisticated attack pattern detection
- **Report aggregation**: Optionally collect reports from all nodes to a
  central report aggregator for cluster-wide visibility
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
  systems like HTTP endpoints, syslog, or Alertmanager in addition to OpenReports.
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

```text
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

A `RuntimeBehavior` without `spec.workloadSelector` acts as a reusable library of allow rules. This is the **primary mechanism for users to define cluster-wide "good" behavior defaults** that apply to multiple workloads without duplication.

Shared defaults are typically stored in the `kyverno-runtime` namespace and referenced by workload-bound profiles via `spec.allow.refs`.

**Use cases:**

1. **Enterprise infrastructure defaults**: Allow outbound to corporate proxies, DNS servers, observability backends
2. **Workload-class defaults**: Allow exec patterns specific to workload types (e.g., Jupyter notebooks, CI/CD agents)
3. **Application dependencies**: Shared allow-lists for database connections, message queues, cache servers
4. **Security baselines**: Curated security-approved patterns for file access, network destinations, process execution

#### Example: Enterprise infrastructure defaults

```yaml
# kyverno-runtime namespace - shared library
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: enterprise-safe-network
  namespace: kyverno-runtime
spec:
  # No workloadSelector — this is a shared defaults library
  allow:
    network:
      - dst: proxy.corp.internal:3128        # corporate proxy
      - dst: 10.0.0.0/8                      # internal networks
      - dst: 169.254.169.254:80              # AWS metadata
    dns:
      - "*.corp.internal"                    # internal domains
      - "*.svc.cluster.local"                # kubernetes services
```

#### Example: Workload-class defaults (Jupyter notebooks)

```yaml
# kyverno-runtime namespace - runtime.kyverno.io/runtime-class library
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: jupyter-approved-patterns
  namespace: kyverno-runtime
  labels:
    runtime.kyverno.io/runtime-class: jupyter
spec:
  # No workloadSelector — this is a shared library for Jupyter workloads
  allow:
    exec:
      - /usr/bin/python3                     # python interpreter
      - /usr/bin/python                      # python symlink
      - /bin/bash                            # shell for notebook cells
      - /usr/bin/perl                        # sometimes used in notebooks
    open:
      - /usr/local/lib/python*/dist-packages/**
      - /usr/lib/python*/dist-packages/**
      - /home/**/*.ipynb                     # notebook files
    network:
      - dst: 10.0.0.0/8                      # internal networks
      - dst: "*:443"                         # HTTPS to external APIs
```

#### Example: Workload-specific RuntimeBehavior referencing shared defaults

```yaml
# production namespace - auto-created or user-managed
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: my-jupyter-notebook
  namespace: production
spec:
  workloadSelector:
    matchLabels:
      app: ml-analysis
      runtime.kyverno.io/runtime-class: jupyter

  mode: monitor

  learning:
    duration: 24h
    minSamples: 1000
    startAfter: ready

  allow:
    # Application-specific rules
    open:
      - /data/datasets/**
      - /results/**
    
    # Reference shared defaults
    refs:
      - name: enterprise-safe-network
        namespace: kyverno-runtime
      - name: jupyter-approved-patterns
        namespace: kyverno-runtime
    
    # Workload-specific denies (override everything else)
    deny:
      exec:
        - /bin/sh                            # don't allow plain shell
      network:
        - dst: 0.0.0.0/0                     # deny unexpected destinations

status:
  lifecycle: completed
  confidence:
    sampleCount: 8500
    dropRate: 0.001
  observed:
    # Auto-learned behaviors during learning phase
    exec:
      - /usr/bin/python3
      - /usr/bin/ipython
    open:
      - /data/datasets/training.csv
    network:
      - dst: 10.96.0.1:443                   # kubernetes API
```

**How auto-created RuntimeBehavior discovers shared defaults:**

When the controller auto-creates a `RuntimeBehavior` for a pod:

1. It inspects pod labels and annotations
2. It searches for shared `RuntimeBehavior` resources in `kyverno-runtime` namespace that match via label selectors
3. It automatically populates `spec.allow.refs` with discovered shared defaults
4. Example: A pod with `runtime.kyverno.io/runtime-class: jupyter` automatically references `jupyter-approved-patterns`

This means users don't manually configure every workload — shared defaults are discovered automatically based on workload classification.

**References from other RuntimeBehavior resources:**

```yaml
spec:
  allow:
    refs:
      - name: enterprise-safe-network
        namespace: kyverno-runtime
      - name: jupyter-approved-patterns
        namespace: kyverno-runtime
```

Refs include the namespace for cross-namespace lookups. Merged in order; first matching rule wins.

#### Merge Precedence (RuntimeBehavior)

When computing the effective allow set for a RuntimeBehavior:

1. **Deny rules win**: `spec.allow.deny` always blocks, regardless of other sources
2. **Inline rules**: `spec.allow` (inline workload-specific) rules
3. **Shared defaults**: Referenced `RuntimeBehavior` resources via `spec.allow.refs` (in order; first match wins)
4. **Observed behaviors**: `status.observed` (auto-learned during learning phase)

Example merge for a Jupyter pod:

```text
Deny:          [/bin/sh, /etc/shadow]                     (blocks everything below)
         |
         ↓
Inline:        [/data/datasets/**, /results/**]           (workload-specific)
         |
         ↓
Refs:          [jupyter-approved-patterns, enterprise-safe-network]
               - jupyter: [/usr/bin/python3, /bin/bash]
               - enterprise: [10.0.0.0/8, proxy.corp:3128]
         |
         ↓
Observed:      [/usr/bin/ipython, /data/logs/**]          (learned during learning phase)
         |
         ↓
Effective:     [/data/datasets/**, /results/**, /usr/bin/python3, /bin/bash,
                10.0.0.0/8, proxy.corp:3128, /usr/bin/ipython, /data/logs/**]
                EXCEPT: /bin/sh, /etc/shadow (always denied)
```

#### RuntimePolicy vs RuntimeBehavior Interaction

`RuntimePolicy` and `RuntimeBehavior` are **complementary detection engines that fire in parallel**. They serve different purposes:

**RuntimePolicy (Cluster-level Signatures):**

- Detects known-bad behavior patterns (e.g., shell execution, credential access)
- Applied cluster-wide via `matchConstraints`
- Expert-authored rules, not learning-based
- Enforced regardless of RuntimeBehavior

**RuntimeBehavior (Workload-level Baseline):**

- Detects deviations from workload's learned "good" behavior
- Workload-specific or workload-class-specific
- Learning-based from observed behavior
- Alerts when something unusual happens (even if not inherently bad)

**Precedence and Interaction Model:**

When an event occurs:

1. **RuntimePolicy evaluation** (signature check):
   - Does this event match a known-bad pattern? → Generate CRITICAL/ERROR finding
   - Example: "Shell execution detected" (signature match)

2. **RuntimeBehavior evaluation** (anomaly check):
   - Does this event match the workload's learned profile? → No anomaly finding
   - Does this event deviate from learned profile? → Generate WARNING/ERROR finding (based on mode)
   - Example: "Exec outside learned baseline" (anomaly)

3. **Both can fire simultaneously**:
   - An event can trigger BOTH a RuntimePolicy rule AND a RuntimeBehavior anomaly
   - They are independent findings in the same PolicyReport
   - User can act on either or both

**Precedence Table:**

| Scenario | RuntimePolicy Match | RuntimeBehavior Match | Result | Action |
| --- | --- | --- | --- | --- |
| Known-good behavior | ❌ No match | ✅ In learned profile | No finding | Allow (normal) |
| Known-bad pattern | ✅ Matches rule | ✅ or ❌ | CRITICAL/ERROR finding | Terminate (RuntimePolicy action) |
| Deviation from baseline | ❌ No match | ❌ Outside profile | WARNING/ERROR finding | Alert & tune profile |
| Anomaly + Signature match | ✅ Matches rule | ❌ Outside profile | CRITICAL + ERROR findings | Terminate immediately (RuntimePolicy) |

#### Real-world example: "I have 10 RuntimePolicy rules but one app needs exceptions"

Scenario: You have a RuntimePolicy rule that blocks all shell execution:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: block-shell-execution
spec:
  validations:
  - name: no-shell
    event: exec
    conditions:
    - expression: 'event.comm == "/bin/sh" || event.comm == "/bin/bash"'
    actions:
    - type: terminate
    severity: critical
```

But your CI/CD pipeline legitimately needs to run shell scripts. Solution:

```yaml
# 1. Create a shared defaults for CI/CD workloads
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: cicd-approved-patterns
  namespace: kyverno-runtime
spec:
  allow:
    exec:
      - /bin/bash      # CI jobs need shell
      - /bin/sh
      - /usr/bin/make
      - /usr/bin/git

# 2. Auto-created RuntimeBehavior for your CI job references it
---
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: auto-ci-job-abc123
  namespace: ci-cd
spec:
  workloadSelector:
    matchLabels:
      runtime.kyverno.io/runtime-class: ci-job
  mode: enforce
  allow:
    refs:
      - name: cicd-approved-patterns
        namespace: kyverno-runtime
  deny:
    exec:
      - /bin/sh --privileged    # still deny dangerous variants
```

Behavior:

- RuntimePolicy still fires for unauthorized shell execution globally
- RuntimeBehavior allows shell in CI jobs (via shared defaults)
- User can safely run CI without suppressing the global policy rule
- The policy applies everywhere; RuntimeBehavior provides workload-specific exceptions

When `featureGates.baselineEngine=true`, the controller evaluates events against
the merged behavior profile for the workload:

1. Controller fetches the corresponding `RuntimeBehavior` for the workload
2. Computes the merged allow set (spec.allow + refs + observed)
3. Compares the event against the allow set
4. If not allowed, emits anomaly findings using configured severity/action policy
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

### RuntimeBehavior Example Workflow

1. **Day 0 (security setup):** Security team enables default RuntimePolicy library
  and configures RuntimeBehavior enrollment flags.
2. **Day 0 (auto enrollment):** For eligible controller-managed workloads (and
  optional bare pods), the controller auto-creates RuntimeBehavior profiles.
3. **Learning period:** Events are collected. No alerts fire.
4. **Promotion to monitor:** Admin reviews `status.observed`, adds desired entries to
   `spec.allow`, sets `mode: monitor`.
5. **Monitor period:** Deviations generate warnings. Admin tunes `spec.allow`.
6. **Promotion to enforce:** Admin sets `mode: enforce`. Violations trigger
   enforcement actions.

## RuntimeBehavior Enrollment Policy

RuntimeBehavior creation is controlled by security-owned runtime configuration,
not developer-by-default annotations.

Recommended enrollment defaults:

1. Enable auto-creation for controller-managed workloads:
  Deployment, StatefulSet, DaemonSet, Job, CronJob, ReplicaSet.
2. Keep bare pod enrollment disabled unless explicitly enabled.
3. Exclude system namespaces by default.
4. Start newly created profiles in `learning` or `monitor` mode.
5. Gate enforcement promotion on lifecycle and confidence readiness.

Recommended runtime flags:

- `--runtimebehavior-auto-create`
- `--runtimebehavior-include-controllers`
- `--runtimebehavior-include-bare-pods`
- `--runtimebehavior-include-namespaces`
- `--runtimebehavior-exclude-namespaces`
- `--runtimebehavior-initial-mode`
- `--runtimebehavior-optout-label`

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

Real-world threat scenarios are provided in `test/samples/`:

1. **runtimepolicy-ai-agent-credential-access.yaml** — credential access detection
2. **runtimepolicy-ai-agent-aws-credentials.yaml** — cloud credential exfiltration
3. **runtimepolicy-ai-agent-data-exfil.yaml** — data exfiltration to public IPs
4. **runtimepolicy-ai-agent-c2-communication.yaml** — C2 communication via tunnels

Deploy on kind cluster:

```bash
kind create cluster --name kyverno-runtime-test
helm install kyverno-runtime ./charts/kyverno-runtime \
  --set featureGates.signatureEngine=true \
  --set featureGates.baselineEngine=true

kubectl apply -f samples/runtimepolicy-ai-agent-credential-access.yaml
sleep 30
kubectl get policyreport -A
```

See [test/e2e/E2E_TESTING.md](../../test/e2e/E2E_TESTING.md) for comprehensive guide.
