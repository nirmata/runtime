# Kyverno Runtime Enhancement Plan (v2)

## Objective

Evolve kyverno-runtime from a basic runtime event checker into a production-ready
runtime threat detection platform while preserving the current collapsed
single-binary DaemonSet architecture.

This plan focuses on:

1. Higher fidelity detections (anomaly + signature)
2. Better operational controls (bindings, sinks, aggregation)
3. Safer baseline lifecycle (learning/completion/confidence)
4. Scale-readiness (bounded persistence, metrics, suppression)

## Current Baseline

- Runtime evaluation pipeline is matcher -> collector -> evaluator -> reporter.
- Runtime collection uses embedded Inspektor Gadget runtime in-process.
- Deployment model is a single DaemonSet binary.
- Policy output is written to PolicyReport resources.
- Currently supported gadgets: trace_open, trace_exec, trace_tcp (connect).

## Inspektor Gadget Coverage

### Available Gadgets

The table below lists all IG image-based gadgets relevant to runtime threat
detection. The **Status** column shows whether kyverno-runtime supports the
gadget today.

| Gadget | IG Image | Syscall / Hook | Status |
|---|---|---|---|
| exec | trace_exec | execve | Supported |
| open | trace_open | open/openat | Supported |
| connect | trace_tcp | connect (TCP) | Supported |
| network | trace_network | network (all) | Planned |
| dns | trace_dns | DNS queries/responses | Planned |
| capabilities | trace_capabilities | capability checks | Planned |
| symlink | trace_symlink | symlink/symlinkat | Planned |
| hardlink | trace_hardlink | link/linkat | Planned |
| ptrace | trace_ptrace | ptrace | Planned |
| kmod | trace_kmod | init_module/finit_module | Planned |
| ssh | trace_ssh | SSH connections | Planned |
| bpf | trace_bpf | bpf() syscall | Planned |
| unshare | trace_unshare | unshare | Planned |
| iouring | trace_iouring | io_uring_setup | Future |
| http | trace_http | HTTP request/response | Future |
| randomx | trace_randomx | RandomX crypto instructions | Future |
| seccomp | trace_seccomp | syscall audit | Future |

### Policy-to-Gadget Mapping

Each policy event type maps to one or more gadgets. The collector must enable
the required gadgets for the policy to produce findings.

| Policy Event Type | Required Gadget(s) | Example Use Case |
|---|---|---|
| `open` | trace_open | Sensitive file access (/etc/hosts, /etc/shadow) |
| `exec` | trace_exec | Shell spawning, unexpected process execution |
| `connect` / `tcpconnect` | trace_tcp | Unauthorized outbound connections |
| `dns` | trace_dns | DNS tunneling, C2 domain resolution |
| `network` | trace_network | Full network visibility (TCP + UDP + ICMP) |
| `capabilities` | trace_capabilities | Privilege escalation via capability use |
| `symlink` | trace_symlink | Symlink attacks (e.g. container escape) |
| `hardlink` | trace_hardlink | Hardlink-based file manipulation |
| `ptrace` | trace_ptrace | Process injection, debugger attach |
| `kmod` | trace_kmod | Rootkit / kernel module loading |
| `ssh` | trace_ssh | Lateral movement via SSH |
| `bpf` | trace_bpf | Unauthorized eBPF program loading |
| `unshare` | trace_unshare | Namespace escape attempts |

### Gadget Enablement Strategy

Gadgets are enabled on-demand based on the event types declared in active
RuntimePolicy resources. The collector inspects `spec.validations[].event`
across all policies and starts only the required gadgets. This avoids
unnecessary eBPF overhead on nodes with no matching policies.

Future enhancements:

- Allow explicit gadget enablement via Helm values for always-on tracing.
- Support composite policies that combine multiple event types in a single
  evaluation (e.g. exec + open correlation).
- Add gadget health metrics to surface collection failures per gadget.

## Scope

- Code and API flow
  - Add baseline lifecycle and confidence tracking
  - Add signature rule engine support alongside existing policy evaluation
  - Add rule-to-workload binding resource for targeting
  - Add alert sink routing and aggregation controls
- Persistence and data model
  - Add bounded RuntimeBehavior CR and storage model
  - Add compaction, caps, and drift metadata
- Packaging and deployment
  - Add configuration values for lifecycle, sinks, and suppression
  - Keep single DaemonSet deployment model
- Documentation
  - Update design and operations docs
  - Add runbooks for learning and alert tuning
- Validation
  - Unit tests + integration tests + kind validation

## Non-goals

- Replacing Inspektor Gadget internals
- Introducing external queueing (Kafka/NATS)
- Building a full SIEM UI in this phase

## Target Architecture (v2)

Single DaemonSet runtime controller, with modular engines:

- Collection layer:
  embedded IG runtime + event normalization
- Detection layer:
  anomaly engine (baseline deviation) + signature engine (known attack patterns)
- Decision layer:
  confidence-aware severity and suppression
- Output layer:
  PolicyReport + optional external sinks

No separate runtime sensor service is required in this plan.

## Open Design Discussion

### RuntimePolicy vs Standard Kyverno Policy Types

The current design introduces a dedicated `RuntimePolicy` CRD for runtime
event evaluation. An alternative approach is to reuse standard Kyverno
policy types:

- **ValidatingPolicy** — evaluate runtime events and trigger violations
  (PolicyReport findings), reusing the existing Kyverno CEL evaluation
  engine and policy semantics.
- **MutatingPolicy** — transform or enrich runtime events before evaluation
  (e.g., normalize fields, inject labels).
- **GeneratingPolicy** — trigger side effects in response to runtime events
  (e.g., create NetworkPolicy, generate alerts, update RuntimeBehavior).

**Potential benefits:**

- Consistent policy authoring experience across admission and runtime.
- Reuse of existing Kyverno policy tooling (CLI, test framework, VS Code
  extension).
- Policy exceptions (`PolicyException` CRD) work out of the box.
- Familiar semantics for `match`, `exclude`, `preconditions`, and
  `validationFailureAction`.

**Potential concerns:**

- Runtime events have different schemas and lifecycles than admission
  requests — the policy model may need adaptation.
- Continuous streaming evaluation differs from one-shot admission webhooks.
- Action semantics (terminate pod, kill process) don't map cleanly to
  existing Kyverno action types.
- May require extending upstream Kyverno policy types to accommodate
  runtime-specific fields (event types, severity, collection parameters).

**Decision needed:** Evaluate whether the benefits of policy type reuse
outweigh the adaptation cost, or whether a dedicated RuntimePolicy with
Kyverno-aligned semantics is the better path.

### Policy Exceptions

Runtime policies need an exception mechanism to suppress known-good
violations without modifying the policy itself. Options:

1. **Kyverno PolicyException CRD** — if standard Kyverno policy types are
   adopted, the existing `PolicyException` resource applies directly. It
   allows exempting specific namespaces, workloads, or containers from
   specific policy rules.
2. **RuntimePolicy-native exceptions** — if `RuntimePolicy` is retained,
   add an equivalent exception mechanism (e.g., `RuntimePolicyException`
   CRD or inline `exclude` blocks).
3. **RuntimeBehavior allow rules** — for baseline-based detection, the
   `spec.allow` and `spec.allow.refs` fields already serve as a form of
   exception. Explicit allow entries suppress findings for known-good
   behaviors.

Regardless of approach, exceptions should support:

- Scoping by namespace, workload label selector, and container name.
- Per-rule granularity (exempt specific rules, not entire policies).
- Audit trail (who created the exception, when, and why).
- Expiration (time-bounded exceptions for maintenance windows).

## Implementation Phases

### Phase 0: Foundation Alignment

Status: **COMPLETED** ✅ — Feature gates fully implemented, wired, documented, and tested.

- Add feature gates for all new capabilities:
  - `baselineEngine` ✅
  - `signatureEngine` ✅
  - `alertSinks` ✅
  - `alertAggregation` ✅

Deliverables:

- `docs/dev/DESIGN.md` ✅
- `README.md` ✅
- runtime config struct updates in command wiring ✅
- Feature gate unit tests ✅
- Helm values and template updates ✅
- Raw manifest updates ✅

Implementation notes:

- Feature gates are implemented in `pkg/config/features.go`
- CLI flags wired in `cmd/kyverno-runtime/main.go`
- Helm values in `charts/kyverno-runtime/values.yaml`
- Helm templates updated in `charts/kyverno-runtime/templates/deployment.yaml`
- Raw manifest updated in `config/manager/deployment.yaml`
- All feature gates default to `false` for safe operation
- `docs/dev/DESIGN.md` updated with comprehensive Phase 0 and Phase 1 sections
### Critical: PolicyReport Result Deduplication

Status: implemented.

The current reporter creates a new PolicyReport result for every matching
eBPF event. A single `kubectl exec` that opens `/etc/hosts` in a loop
produces dozens of nearly identical findings in the PolicyReport. This
makes reports noisy and hard to consume.

**Required behavior:** Deduplicate results by fingerprint and update
existing entries instead of appending new ones. The fingerprint key is:

`(policy, rule, namespace, pod, container, matched-fields)`

For example, all `trace_open` events matching the same CEL rule for
`fname=/etc/hosts` in the same pod should collapse into a single
PolicyReport result with:

- `firstTimestamp` — time of the first occurrence
- `lastTimestamp` — time of the most recent occurrence
- `count` — total number of matching events

When a new event matches an existing fingerprint, the reporter updates
`lastTimestamp` and increments `count` rather than creating a new result
entry.

Deliverables:

- Fingerprint computation in `pkg/pipeline/k8s_reporter.go`
- Update-or-insert logic in `pkg/pipeline/k8s_reporter.go`
- Unit tests for dedup, count increment, and timestamp updates in
  `pkg/pipeline/reporter_test.go`

Implementation notes:

- Dedup runs in the existing in-process reporter path (no separate
  cross-node controller in this phase).
- Each result stores a stable `fingerprint` property derived from
  `(policy, rule, namespace, pod, container, matched-fields)`.
- On repeated matches, reporter preserves `firstTimestamp`, updates
  `lastTimestamp`, and increments `count` instead of appending a new entry.

### Phase 1: Baseline Lifecycle and Confidence

Status: **FOUNDATIONAL WORK COMPLETE** ✅ — RuntimeBehavior CRD types, merge logic, and comprehensive tests implemented. Ready for controller and lifecycle orchestration development.

Completed deliverables:

- `api/v1alpha1/runtimebehavior_types.go` ✅ — Complete CRD definition with all types
- `api/v1alpha1/runtimebehavior_types_test.go` ✅ — Comprehensive unit tests 
- `api/v1alpha1/register.go` ✅ — Type registration in scheme
- `pkg/baseline/merge.go` ✅ — Baseline merge logic with proper precedence
- Documentation in `docs/dev/DESIGN.md` ✅ — Full Phase 1 architecture
- `docs/dev/DESIGN.md` Phase 1 section ✅ — Lifecycle state machine, merge precedence, integration patterns

Pending implementation (for next iteration):
- `pkg/pipeline/` lifecycle orchestration (controller logic)
- `pkg/policy/` confidence-aware evaluation hooks
- Auto-learning and profile promotion logic
- Staleness detection and relearning
- Tests for state transitions and merge behavior

#### RuntimeBehavior CRD

A `RuntimeBehavior` resource describes the known-good runtime profile for a
workload. It combines admin-defined allowed behaviors with auto-learned
observations, and transitions through lifecycle modes that control how
deviations are handled.

Example:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: my-app
  namespace: production
spec:
  workloadSelector:
    matchLabels:
      app: my-app

  mode: monitor   # learning | monitor | enforce

  learning:
    duration: 24h
    minSamples: 1000
    startAfter: ready   # immediate | ready (default: immediate)
                        # "ready" delays learning until the pod passes
                        # its readiness probe, excluding startup noise.

  allow:
    # Inline allow rules for this workload.
    exec:
      - /app/server
      - /usr/bin/python3
    open:
      - /app/**
      - /etc/hosts
      - /etc/resolv.conf
    network:
      - dst: 10.96.0.0/12
    dns:
      - "*.svc.cluster.local"

    # Shared defaults inherited by reference to other RuntimeBehavior
    # resources (without workloadSelector). Refs include namespace for
    # cross-namespace lookups. Merged with inline rules; inline deny
    # takes precedence.
    refs:
      - name: enterprise-safe-defaults
        namespace: kyverno-runtime
      - name: monitoring-stack
        namespace: kyverno-runtime

    deny:
      exec:
        - /bin/sh
        - /bin/bash
      open:
        - /etc/shadow
        - /etc/passwd
      network:
        - dst: 0.0.0.0/0   # deny all external unless allowed above

status:
  lifecycle: completed    # learning | partial | completed | stale
  confidence:
    observedFrom: "2026-04-01T00:00:00Z"
    observedTo: "2026-04-02T00:00:00Z"
    sampleCount: 12450
    dropRate: 0.002
  observed:
    exec:
      - /app/server
      - /usr/bin/python3
      - /usr/bin/curl       # learned — not in spec.allow
    open:
      - /etc/hosts
      - /etc/resolv.conf
      - /app/config.yaml
    network:
      - dst: 10.96.0.1:443
      - dst: 10.96.0.10:53
    dns:
      - kubernetes.default.svc.cluster.local
```

#### Shared Defaults (RuntimeBehavior without workloadSelector)

A `RuntimeBehavior` without `spec.workloadSelector` acts as a reusable
library of allow rules. Other `RuntimeBehavior` resources reference
it via `spec.allow.refs` (with an optional `namespace` for cross-namespace
lookups). This avoids duplicating common infrastructure rules across every
workload profile and keeps the API surface to a single CRD.

Shared defaults are typically stored in a well-known namespace (e.g.
`kyverno-runtime`) and referenced by workload-bound profiles.

Example use cases:

- Enterprise proxy: allow outbound to `proxy.corp.internal:3128`
- Monitoring stack: allow connections to Prometheus, Grafana, OTel collector
- DNS infrastructure: allow queries to internal DNS servers
- Logging agents: allow file opens on `/var/log/**`

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: enterprise-safe-defaults
  namespace: kyverno-runtime
spec:
  # No workloadSelector — this is a shared defaults library.
  allow:
    network:
      - dst: proxy.corp.internal:3128
      - dst: 10.0.0.0/8
    dns:
      - "*.corp.internal"
      - "*.svc.cluster.local"
    open:
      - /etc/ssl/certs/**
      - /etc/resolv.conf
---
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: monitoring-stack
  namespace: kyverno-runtime
spec:
  # No workloadSelector — this is a shared defaults library.
  allow:
    network:
      - dst: prometheus.monitoring.svc:9090
      - dst: otel-collector.monitoring.svc:4317
```

#### Modes and Data Management

The `spec.mode` field controls how the RuntimeBehavior processes events
and handles deviations:

**`learning` mode:**

- All gadgets for the workload are active.
- Observed behaviors are recorded in `status.observed`.
- No findings or PolicyReports are generated.
- Confidence metadata (`sampleCount`, `dropRate`, `observedFrom/To`) is
  continuously updated.
- Transitions to `monitor` automatically when `learning.duration` expires
  and `learning.minSamples` is met, or manually via annotation.
- If `spec.allow` is pre-populated, learning still runs but only adds
  new entries to `status.observed` (it does not modify `spec.allow`).
- **Readiness-aware learning:** When `spec.learning.startAfter: ready` is
  set, observation begins only after the pod passes its readiness probe.
  This excludes one-time startup behaviors (init scripts, migration runs,
  library loading) that would otherwise widen the profile and reduce
  detection fidelity. Without this, a flat learning window can capture
  startup `execve` calls (e.g. shell scripts) that mask real attacks like
  reverse shells triggered via Log4Shell.

**`monitor` mode:**

- The effective allowed set is computed by merging:
  1. `spec.allow` (inline rules)
  2. All `RuntimeBehavior` resources (shared defaults) referenced by `spec.allow.refs`
  3. `status.observed` (auto-learned behaviors from the learning phase)
- Any behavior not in the merged allow set OR matching `spec.allow.deny`
  generates an informational PolicyReport finding (severity: warning).
- No enforcement actions are taken (pods are not terminated).
- Admins review findings and tune `spec.allow` before promoting to enforce.

**`enforce` mode:**

- Same merged allowed set as monitor mode.
- Deviations generate PolicyReport findings with severity from the matching
  RuntimePolicy validation.
- Enforcement actions configured in the RuntimePolicy (e.g. `terminate`,
  `kill_process`) are executed.
- `status.observed` is still updated for audit, but new observations do not
  expand the allow set.

#### Merge Precedence

When computing the effective allow set:

1. `spec.allow.deny` always wins — explicitly denied behaviors are never
   allowed regardless of other sources.
2. `spec.allow` inline rules take next precedence.
3. Referenced `RuntimeBehavior` resources (shared defaults) from
   `spec.allow.refs` are merged in order (first ref wins on conflict).
4. `status.observed` (auto-learned) fills remaining gaps.

#### Lifecycle State Machine

```text
                  duration met
  ┌──────────┐  & minSamples    ┌──────────┐   admin promotes   ┌──────────┐
  │ learning │ ───────────────> │ monitor  │ ─────────────────> │ enforce  │
  └──────────┘                  └──────────┘                    └──────────┘
       │                             │                               │
       │ failure/timeout             │ staleness detected            │
       v                             v                               │
  ┌──────────┐                  ┌──────────┐                         │
  │  failed  │                  │  stale   │ <───────────────────────┘
  └──────────┘                  └──────────┘
                                     │ relearn
                                     v
                                ┌──────────┐
                                │ learning │
                                └──────────┘
```

Staleness is detected when:

- The workload image changes.
- No events have been observed for a configurable staleness window.
- An admin manually triggers relearning.

#### Workflow Summary

1. **Day 0 (optional):** Admin creates `RuntimeBehavior` with `spec.allow`
   pre-populated and `mode: learning`. Also creates shared
   `RuntimeBehavior` resources (without `workloadSelector`) for shared
   enterprise defaults.
2. **Day 0 (auto):** If no `RuntimeBehavior` exists, one is auto-created in
   `learning` mode when a RuntimePolicy first matches a workload.
3. **Learning period:** Behaviors are observed and recorded in
   `status.observed`. No alerts fire.
4. **Promotion to monitor:** Admin reviews `status.observed`, copies desired
   entries to `spec.allow`, sets `mode: monitor`.
5. **Monitor period:** Deviations generate warning-level findings. Admin
   tunes `spec.allow` and `spec.allow.deny`.
6. **Promotion to enforce:** Admin sets `mode: enforce`. Deviations now
   trigger enforcement actions.

A future CLI helper (`kubectl kyverno runtime profile export <name>`) can
generate `spec.allow` from `status.observed` to simplify step 4.

#### Multi-Source Profile Building

A single observation window may miss lazy-loaded components, error-handling
paths, or periodic jobs. To build high-confidence profiles, the effective
`spec.allow` should be a union of multiple sources:

1. **Previous production profiles** — carried forward across deploys and
   expanded over time. When a workload is redeployed, the existing
   `RuntimeBehavior` is retained (staleness detection handles image changes).
2. **CI/CD test observations** — run integration or edge-case tests with
   learning enabled in a staging environment, then export and merge the
   profile into the production `RuntimeBehavior`.
3. **Live observation** — the existing learning mechanism.
4. **Manual additions** — admin edits to `spec.allow` for known-good
   behaviors that are hard to trigger during testing.

The CLI export/import workflow supports this:

```bash
# Export a learned profile from staging
kubectl kyverno runtime profile export my-app -n staging -o my-app-profile.yaml

# Merge into production RuntimeBehavior
kubectl kyverno runtime profile merge my-app -n production -f my-app-profile.yaml
```

#### Zero-Exposure Enforcement

When a tight, readiness-aware profile exists from a previous deployment, it
can be loaded at pod start so that protection is active *before* the pod
receives traffic:

1. Deployment N: App runs → readiness passes → learning builds tight
   profile → profile persists in `RuntimeBehavior`.
2. Deployment N+1: Existing profile loaded → enforcement active at pod
   start → app starts → readiness passes → traffic flows.

**Safety net:** If the profile is too strict and blocks a required startup
behavior, the application fails its readiness probe. Kubernetes halts the
rollout automatically, preventing an outage. This makes enforcement
self-correcting — overly strict profiles cause deployment failures rather
than silent production breakage.

This requires `spec.mode: enforce` combined with a pre-populated
`spec.allow` from a previous learning cycle.

#### Deliverables

- `api/v1alpha1/` new `RuntimeBehavior` type (used for both workload profiles
  and shared defaults)
- `pkg/pipeline/` lifecycle orchestration and mode handling
- `pkg/policy/` confidence-aware evaluation hooks
- `pkg/baseline/` merge logic for allow + refs + observed
- tests for state transitions, merge precedence, and mode behavior

### Phase 2: Rule Binding Resource

- Add RuntimeRuleBinding-style CRD to map detection rules/policies to workloads
  via selectors.
- Provide defaults (all-enabled) plus explicit include/exclude support.

Deliverables:

- `api/v1alpha1/runtime_rule_binding_types.go`
- CRD manifests under `config/crd/bases/`
- matcher updates in `pkg/pipeline/policy_matcher.go`
- docs with examples and migration notes

### Phase 3: Dual Detection Engines

- Baseline anomaly engine:
  detect deviations from completed baselines.
- Signature engine:
  implement curated rules for common runtime attack patterns.
- Add engine routing in evaluator:
  policy/rule-level selection and combined verdict output.

Deliverables:

- `pkg/policy/` anomaly evaluator module
- `pkg/policy/` signature rules module
- evaluator integration and tests

### Phase 4: Alert Aggregation and Suppression

Building on the critical dedup work (see "Critical: PolicyReport Result
Deduplication" above), this phase adds cross-rule aggregation and
suppression controls.

- Extend the existing fingerprint-based dedup with configurable aggregation:
- Emit aggregate fields:
  `firstSeen`, `lastSeen`, `count`, `window`.
- Add suppression controls:
  cooldown and per-rule burst limits.

Deliverables:

- `pkg/pipeline/reporter*.go` aggregation support
- config values in Helm chart
- tests for dedup, rate-limit, and summary correctness

### Phase 5: Alert Sinks and Routing

- Add sink framework:
  `stdout`, `http`, `syslog`, `alertmanager`.
- Add per-sink retry/backoff, timeout, and rate limiting.
- Preserve PolicyReport as default native sink.

Deliverables:

- `pkg/pipeline/` sink interfaces + implementations
- chart values and docs for sink configuration
- integration tests with mock endpoints

### Phase 6: Persistence Hardening and Compaction

- Add bounded retention and compaction for baseline internals.
- Normalize dynamic file paths/domains where beneficial.
- Introduce caps for high-cardinality dimensions and explicit overflow markers.

Deliverables:

- baseline storage package updates
- compaction tests and size regression checks

### Phase 7: Operational Readiness

- Add preflight checks:
  kernel and eBPF capability readiness.
- Add runtime detection SLO metrics:
  - events collected
  - dropped events
  - eval latency
  - sink failures
  - baseline completion ratio
  - alerts emitted/suppressed

Deliverables:

- health/readiness extensions
- metrics export additions
- operational runbook in docs

## Cross-Cutting Validation

### Unit and integration tests

```bash
go test ./...
```

Coverage targets:

- baseline lifecycle transitions
- confidence-aware severity outcomes
- binding selector behavior
- aggregation/suppression logic
- sink retry/rate-limit behavior

### Helm and manifest validation

```bash
helm template kyverno-runtime ./charts/kyverno-runtime -n kyverno-runtime >/tmp/kyverno-runtime-rendered.yaml
```

Validate generated config for:

- feature gates
- lifecycle parameters
- sink endpoints
- suppression settings

### kind validation

```bash
kind create cluster --name kyverno-runtime || true
kubectl config use-context kind-kyverno-runtime
helm upgrade --install kyverno-runtime ./charts/kyverno-runtime -n kyverno-runtime --create-namespace --wait
kubectl get pods -n kyverno-runtime
kubectl get ds -n kyverno-runtime
kubectl get policyreport -A
```

## Risks and Mitigations

- Alert storms from incomplete baselines
  - Mitigation: lifecycle gating, confidence-aware severity, suppression windows.
- Startup noise widens learned profiles, reducing detection fidelity
  - Mitigation: readiness-aware learning (`startAfter: ready`), multi-source
    profile building, profile export/merge tooling.
- Increased compute overhead from dual engines
  - Mitigation: feature gates, sampling, selective bindings.
- False positives due to dynamic workloads
  - Mitigation: normalization, periodic relearning, rule tuning guidance.
- Operational complexity from multiple sinks
  - Mitigation: explicit defaults, per-sink health metrics, backoff/retry limits.

## Completion Criteria

- RuntimeBehavior lifecycle and confidence metadata are implemented and surfaced.
- Rule binding CRD is available and used in matching.
- Dual engines (anomaly + signature) are functional behind feature gates.
- Alert aggregation/suppression and at least one external sink are production-ready.
- `go test ./...` passes.
- kind install validates healthy runtime behavior with generated PolicyReports and
  controlled alert output.
