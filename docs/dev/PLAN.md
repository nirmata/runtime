# Kyverno Runtime Enhancement Plan (v2)

## Objective

Evolve kyverno-runtime from a basic runtime event checker into a production-ready
runtime threat detection platform while preserving the current collapsed
single-binary DaemonSet architecture.

This plan focuses on:

1. Higher fidelity detections (anomaly + signature)
2. Simpler operations (default policy library + auto enrollment)
3. Safer baseline lifecycle (learning/completion/confidence)
4. Scale-readiness (bounded persistence, metrics, suppression)

## Current Baseline

- Runtime evaluation pipeline is matcher -> collector -> evaluator -> reporter.
- Runtime collection uses embedded Inspektor Gadget runtime in-process.
- Deployment model is a single DaemonSet binary.
- Policy output is written to OpenReports `Report` resources.
- Currently supported gadgets: trace_open, trace_exec, trace_tcp (connect).

## Inspektor Gadget Coverage

### Available Gadgets

The table below lists all IG image-based gadgets relevant to runtime threat
detection. The **Status** column shows whether kyverno-runtime supports the
gadget today.

| Gadget | IG Image | Syscall / Hook | Status |
| --- | --- | --- | --- |
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
| --- | --- | --- |
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
  - Add default RuntimePolicy library and workload enrollment controls
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
  OpenReports `Report` + optional external sinks

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

## Completed Work

The following phases have been implemented and are in active production use. See [DESIGN.md](DESIGN.md) for details on these features.

### Phase 0: Foundation Alignment ✅

Feature gates (`baselineEngine`, `signatureEngine`, `alertSinks`, `alertAggregation`) fully implemented and tested. See [DESIGN.md](DESIGN.md#phase-0-foundation-alignment) for architecture details.

### Phase 2.1: Default RuntimePolicy Library ✅

8 production-ready policies ship with every Helm install, providing day-1 protection without custom CEL rules. Policies cover credential access, shell execution, sensitive file access, public network egress, metadata endpoint access, process discovery, security tool disruption, and C2 domain resolution. See [docs/users/library.md](../users/library.md) for the user guide and [DESIGN.md](DESIGN.md#phase-21-default-runtimepolicy-library) for implementation details.

### Phase 3: Dual Detection Engines ✅

Signature-based detection (8 high-confidence rules) and anomaly detection (baseline deviation with confidence scoring) are wired into the live evaluation path. Both engines feed findings to the report model. See [DESIGN.md](DESIGN.md#phase-3-dual-detection-engines) for engine descriptions.

### Phase 5: OpenReports Output, Kubernetes Events, and Metrics ✅

Findings are persisted to OpenReports Report resources (primary backend). Kubernetes Events are emitted with amplification controls. Output metrics track report writes, truncations, and event rates. See [DESIGN.md](DESIGN.md#phase-5-openreports-output-kubernetes-events-and-metrics) for details.

### Phase 6: Persistence Hardening and Compaction ✅

Baseline observation storage is bounded with compaction, normalization of dynamic paths/domains, and overflow markers. See [DESIGN.md](DESIGN.md#phase-6-persistence-hardening-and-compaction) for details.

### Phase 7: Operational Readiness ✅

eBPF readiness preflight checks and SLO metrics (events collected, dropped events, eval latency, baseline completion ratio) implemented. See [DESIGN.md](DESIGN.md#phase-7-operational-readiness) for details.

---

## Implementation Phases

### Phase 0.5: Quickstart Reliability and Validation Guardrails (PROPOSED)

### Phase 0.5: Quickstart Reliability and Validation Guardrails

Status: **PROPOSED**

Purpose: make the README quickstart deterministic for local validation and
reduce coordination friction when results are buffered or split across multiple
PolicyReport objects.

Scope:

- Add a single-command quickstart verifier for kind-based local validation.
- Encode expected report shape checks (two policies -> two PolicyReports).
- Add deployment-path guardrails so stale images are less likely during debug.

Deliverables:

- `make quickstart-verify` (or equivalent script in `hack/`) that:
  - applies quickstart policies,
  - triggers one open and one network event,
  - waits for buffered flush windows,
  - fails with actionable output if expected reports are missing.
- Deterministic checks in verifier output:
  - `e2e-live-trace-open` PolicyReport exists,
  - `detect-public-egress-quickstart` PolicyReport exists,
  - network PolicyReport has at least one `fail` result.
- README quickstart verification block that points to the verifier command and
  explains that findings appear as separate PolicyReports.
- E2E test coverage in `test/e2e/` for quickstart report-shape assertions
  (presence/labels/policy names), not strict `FAIL` count equality.

Guardrails:

- Explicitly document and enforce that code-change validation in kind must use
  `make kind-install` (or `make ko-build && make kind-load-image`) before
  replaying quickstart events.
- Add a troubleshooting check that prints the runtime DaemonSet `Image ID` when
  verification fails, to quickly detect stale deployments.

Open decision (follow-up item):

- Decide whether quickstart network policy should intentionally report multiple
  lifecycle events (`connect` + `close`) or collapse to a single logical
  finding per probe. If collapse is required, define filtering semantics in
  policy conditions or normalization layer and add regression tests.

### Phase 0.6: E2E Test Resilience and Speed

Status: **PROPOSED**

Purpose: make the Chainsaw e2e suite more reliable under cluster load and
faster to execute, drawing on lessons from the session that fixed the
quickstart tests.

#### Background

Two failure patterns were found during quickstart debugging:

1. **Timing races** — the `quickstart-samples-verification` pod completed in
   ~3 seconds when `busybox sleep 0.1` rounded to zero, allowing the
   chainsaw assert step to start before the controller had indexed the
   namespace or processed any events. The fix (integer sleeps + initial
   delay) is fragile: a slower node inverts the problem.

2. **API version drift** — all six e2e tests were asserting
   `wgpolicyk8s.io/v1alpha2 PolicyReport` while the controller had already
   been writing `openreports.io/v1alpha1 Report` for multiple releases.
   This mismatch went undetected because the tests were also broken by the
   `.gitignore` issue; cascading silent failures masked the divergence.

#### Resilience Improvements

Replace timing-based waits with controller-signalled readiness:

- Add a **namespace readiness step** at the start of every test that
  asserts the kyverno-runtime DaemonSet Pod is `Ready` on the node
  running the test namespace's workloads before starting the workload
  pod. This eliminates the race between namespace labelling and the
  controller's informer cache sync.
- Replace all `sleep N` heuristics in demo-pod commands with a
  **termination signal pattern**: the pod runs until it has produced at
  least one `open` event that the controller has had time to flush, then
  exits. Concretely: iterate in a loop with a 1 s sleep and let chainsaw's
  `assert` timeout govern the overall wait. The pod never needs to "run
  long enough" — it just needs to produce events.
- Add a **retry step** or a longer `assert` timeout on Report assertions
  so transient API server latency does not cause a flake. The current 150 s
  assert timeout is adequate; the issue is the pod finishing too quickly,
  not the assertion window being too short.
- Add a `make validate-policies` target that runs
  `kubectl apply --dry-run=server` on every file in `samples/` and
  `charts/kyverno-runtime/templates/`. This catches K8s validation errors
  (such as the K8s 1.35 CEL `in` operator rejection) before they reach
  CI or a kind cluster.

#### Speed Improvements

- **Parallel test execution**: Chainsaw already runs tests in parallel by
  default. Verify the `.chainsaw.yaml` `parallel` setting and set it
  explicitly so test count growth does not silently serialize.
- **Shared namespace labelling**: Tests that only need an
  `open`-event workload can share a single labelled namespace rather than
  creating and deleting one per test. Reduces namespace churn and the
  associated informer re-sync delay.
- **Reduce pod run time**: The demo pod for `quickstart-trace-open` runs
  200 iterations × 0.05 s = ~10 s. With the controller already watching
  (readiness step above), 5–10 `cat /etc/hosts` calls with `sleep 1`
  between them (5–10 s total) is sufficient to trigger a finding. Use
  integer sleeps exclusively for busybox compatibility.
- **Add a `make test-e2e-quickstart` target** that runs only the two
  quickstart tests, for fast pre-commit smoke checking without the full
  suite.
- **CRD drift detection**: Add a `make verify-crds` target that diffs the
  CRDs in `charts/kyverno-runtime/crds/` against the live cluster CRDs
  (or a known-good source). Fail CI if they diverge, preventing the
  repeat of the PolicyReport vs Report mismatch.

#### Deliverables

- `test/e2e/quickstart/chainsaw-test.yaml` — replace heuristic sleeps
  with integer-sleep loops; add DaemonSet readiness assert step.
- All other `test/e2e/*/chainsaw-test.yaml` — apply same pattern for
  demo-pod timing.
- `test/e2e/.chainsaw.yaml` — set explicit `parallel` value.
- `Makefile` — add `test-e2e-quickstart` and `validate-policies` targets.
- `Makefile` — add `verify-crds` target.

#### Definition of Done

- All e2e tests pass on a freshly provisioned kind cluster three runs
  in a row with no flakes.
- `make test-e2e-quickstart` completes in under 90 s.
- `make validate-policies` catches the K8s 1.35 CEL `in`-operator
  example (regression test for that specific expression).
- `make verify-crds` fails when the chart CRDs diverge from the
  expected API group.

---

### Phase 1: Baseline Lifecycle and Confidence (FOUNDATIONAL WORK COMPLETE)

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
- Currently, `audit` actions record findings to PolicyReports. Extended enforcement
  actions (e.g., `terminate`, `kill_process`, webhooks) are planned for future phases.
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

### Phase 2.1: Default RuntimePolicy Library

Status: **COMPLETED**

Objective: provide day-1 protection without requiring users to author CEL rules.

Deliverables:

- Ship curated default RuntimePolicy manifests with Helm install.
- Include high-confidence rules (shell spawn, credential access, sensitive file access, public exfil indicators).
- Add configuration to enable/disable default library as a unit.
- Add docs mapping default policies to threat scenarios.
- Add e2e assertions that library policies produce expected PolicyReports.

### Phase 2.2: Security-Owned RuntimeBehavior Auto-Enrollment

Status: **PROPOSED**

Objective: auto-create RuntimeBehavior for enrolled workloads with security-team
control over scope and rollout.

Deliverables:

- Enrollment flags for controller kinds and bare pod handling.
- Namespace include/exclude controls.
- Initial-mode control (`learning` or `monitor`) for new profiles.
- Workload identity mapping and idempotent RuntimeBehavior creation.
- Exception controls for auditable opt-out.
- Controller tests covering controller-managed workloads and optional bare pods.

### Phase 3: Dual Detection Engines

Status: **COMPLETED** ✅ — Signature/anomaly engine routing is wired into the live evaluator/controller path, RuntimeBehavior observations are updated during evaluation, and unit plus kind-backed validation completed.

- Baseline anomaly engine: detect deviations from completed baselines.
- Signature engine: implement curated rules for common runtime attack patterns.
- Add engine routing in evaluator: policy/rule-level selection and combined verdict output.

Deliverables:

- `pkg/policy/signature_engine.go` ✅ — 8 production rules covering real attack patterns
- `pkg/policy/anomaly_detector.go` ✅ — Confidence-based baseline deviation detection
- `pkg/policy/signature_engine_test.go` ✅ — 50+ unit tests covering all rule patterns
- `pkg/policy/anomaly_detector_test.go` ✅ — 35+ unit tests for confidence calculation
- Scenario manifests in `test/samples/` ✅ — 4 real-world threat simulations modeled as manifests
- `test/e2e/E2E_TESTING.md` ✅ — Deployment and validation guide

Implementation notes:

- Feature gates now control evaluator construction in the live runtime path.
- Signature engine and anomaly detector execute alongside CEL evaluation for matching event types.
- RuntimeBehavior observations are updated during live evaluation and compacted for bounded storage.
- Dual-engine findings are normalized into the runtime report model with stable rule IDs and severities.

Remaining follow-up:

- Expand controller-path e2e coverage for live dual-engine findings under representative workloads.

**Signature Detection Rules Implemented:**

1. **cred-access-ssh-key** (CRITICAL) — Detects /.ssh/ private key access
   - Real-world example: Compromised container reads /root/.ssh/id_rsa for lateral movement
   - Severity: CRITICAL (key compromise enables account takeover)

2. **cred-access-shadow** (CRITICAL) — Detects /etc/shadow and /etc/passwd access
   - Real-world example: Ransomware container attempts to read password hashes for brute force
   - Severity: CRITICAL (system credential exposure)

3. **cred-access-keys** (ERROR) — Detects API key/credential locations
   - Patterns: ~/.aws/credentials, ~/.docker/config.json, ~/.kube/config, .env, .secrets
   - Real-world example: Compromised training job steals AWS keys from environment
   - Severity: ERROR (cloud credential theft)

4. **execution-shell** (ERROR) — Detects unexpected shell spawning
   - Patterns: /bin/sh, /bin/bash, /usr/bin/python, /usr/bin/perl, /usr/bin/ruby
   - Real-world example: Log4Shell RCE attempts to spawn reverse shell
   - Severity: ERROR (command execution indicates compromise)

5. **exfil-public-network** (WARNING) — Detects outbound to public IPs
   - Patterns: 8.8.8.8, 1.1.1.1, 0.0.0.0/0 (external networks)
   - Real-world example: Malware in container exfils stolen data to attacker server
   - Severity: WARNING (potential data breach)

6. **discovery-proc** (WARNING) — Detects /proc filesystem enumeration
   - Pattern: /proc/[pid]/status access for process discovery
   - Real-world example: Attacker container enumerates running processes for lateral movement
   - Severity: WARNING (reconnaissance activity)

7. **defense-evasion-disable** (ERROR) — Detects security tool disruption
   - Patterns: iptables, ufw, firewall, auditctl, semanage
   - Real-world example: Backdoor disables auditd to hide tracks
   - Severity: ERROR (active evasion indicates compromise)

8. **lateral-dns-suspicious** (WARNING) — Detects C2 domain DNS queries
   - Patterns: .ngrok.io, .localtunnel.me, .duckdns.org, pastebin.com, .github.io
   - Real-world example: Compromised workload resolves attacker-controlled tunnel domain
   - Severity: WARNING (C2 communication attempt)

**Anomaly Detection Engine:**

- Detects deviations from RuntimeBehavior baselines with confidence scoring
- Confidence formula: baseline quality (sample count + drop rate + lifecycle) → 0.0-1.0
- Supports threshold-based alerting: `minConfidence` parameter
- Real-world example: ML serving pod attempts exec to /usr/bin/perl (not in baseline) → anomaly with confidence 0.78 → ALERT if minConfidence=0.6

**Scenario manifests (test/samples/):**

1. `runtimepolicy-ai-agent-credential-access.yaml` — Credential access with policy blocking
2. `runtimepolicy-ai-agent-aws-credentials.yaml` — AWS credential theft with enforce mode
3. `runtimepolicy-ai-agent-data-exfil.yaml` — Data exfiltration with network isolation
4. `runtimepolicy-ai-agent-c2-communication.yaml` — C2 tunnel detection with blocking

**Current validation coverage:**

- Unit tests: 85+ test cases (signature + anomaly engine libraries)
- Build validation: 0 lint errors, all tests passing
- Coverage: All 8 signature rules tested, confidence scoring verified
- Gap: controller-path e2e coverage for live dual-engine findings should be expanded beyond the current unit-focused validation.

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

### Phase 5: OpenReports Output, Kubernetes Events, and Metrics

Status: **COMPLETED** ✅ — OpenReports is now the persisted backend, Kubernetes Events are emitted with amplification controls, and output metrics are implemented and validated in kind.

- Persist findings to OpenReports as the sole target-state backend.
- Emit Kubernetes Events for selected detections/lifecycle transitions.
- Add output-path metrics and keep Event emission rate-limited/deduplicated.

Deliverables:

- OpenReports writer and schema mapping from existing finding model.
- Kubernetes Event emission path with amplification controls.
- Output/eventing metrics and integration coverage.

### Phase 5.5: Legacy PolicyReport Migration (Folded into Phase 5)

Status: **PARTIALLY COMPLETE** ⚠️ — Runtime output has moved to OpenReports, but migration guidance and rollback documentation still need a final operator-facing pass.

- Keep migration staged so existing clusters can upgrade safely without report loss.
- Preserve legacy PolicyReport compatibility only for migration-time guidance.
- Do not implement dual-write as a steady-state operating mode.

Deliverables:

- Migration documentation for install/upgrade/rollback and CRD lifecycle guidance.
- kind upgrade validation from legacy PolicyReport installs to OpenReports-only installs.
- Validation evidence that legacy PolicyReport output can be retired post-migration.

### Phase 6: Persistence Hardening and Compaction

Status: **COMPLETED** ✅ — Baseline observation compaction, normalization, overflow markers, and regression tests are implemented.

- Add bounded retention and compaction for baseline internals.
- Normalize dynamic file paths/domains where beneficial.
- Introduce caps for high-cardinality dimensions and explicit overflow markers.

Deliverables:

- baseline storage package updates
- compaction tests and size regression checks

### Phase 7: Operational Readiness

Status: **COMPLETED** ✅ — eBPF readiness preflight checks and operational SLO metrics are implemented and validated in the deployed runtime.

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

---

## Phase 8: Scalability and Performance (KubeScape-Inspired)

This phase addresses scalability and hot-path performance gaps identified
by comparing the current implementation with the
[KubeScape Node Agent](https://github.com/kubescape/node-agent).
The enhancements are ordered from lowest effort / highest urgency to highest
architectural impact.

Background: KubeScape runs node-wide gadgets (one eBPF program per event type
regardless of pod count), deduplicates events before CEL evaluation, and
batches API server writes. kyverno-runtime currently spawns one eBPF program
per pod per event type and calls the API server on every matching event.
At 50 pods × 3 event types, that means 150 concurrent eBPF programs and
one API write per event.

### Phase 8.1: nodeName Pod Filtering (Priority 1 — Low effort, correctness fix)

Status: **PROPOSED**

The reconciler processes all Pods in the cluster without filtering by node
name. With leader election enabled, a single active instance reconciles every
Pod but can only capture eBPF events from the local node. Every Pod on another
node wastes a goroutine and an IG gadget load that produces zero events.

Changes required:

- Read `NODE_NAME` from the environment in `cmd/kyverno-runtime/main.go`
  (populated via the Kubernetes downward API) and inject it into
  `DaemonSetReconciler`.
- In `Reconcile`, skip pods where `pod.Spec.NodeName != r.nodeName` (empty
  `NODE_NAME` retains current behaviour for backward compatibility).
- Add `NODE_NAME` as a downward API env var in
  `config/manager/deployment.yaml` and
  `charts/kyverno-runtime/templates/deployment.yaml`.
- Update `DESIGN.md` to document per-node collection semantics.

Deliverables:

- `pkg/controller/daemonset_reconciler.go` — add `nodeName` field and
  filter in `Reconcile`
- `cmd/kyverno-runtime/main.go` — read and pass `NODE_NAME`
- `config/manager/deployment.yaml` — downward API env var
- `charts/kyverno-runtime/templates/deployment.yaml` — downward API env var
- `controller_test.go` — unit test for node-name filter path

This is a prerequisite for node-wide shared gadgets (Phase 8.4).

### Phase 8.2: Per-Pod Finding Buffer with Timed Flush (Priority 2 — Medium effort)

Status: **PROPOSED**

Currently `WatchManager` calls `reporter.Report` inside the streaming event
handler callback — a synchronous API server read-modify-write per matching
event. For an active workload generating tens of matches per second, this is
the dominant API server load and a throughput bottleneck.

Replace the per-event report call with a per-pod `FindingBuffer` that flushes
to the API server when:

- The buffer reaches a configurable size (default: 50 findings), or
- A configurable flush timeout elapses (default: 10 s), or
- The pod is deleted or the watch is stopped (drain flush).

Design:

```go
type FindingBuffer struct {
    mu         sync.Mutex
    findings   []v1alpha1.RuleFinding
    maxSize    int           // default 50
    timeout    time.Duration // default 10s
    timer      *time.Timer
    flushFn    func([]v1alpha1.RuleFinding)
}

Status: **COMPLETED** ✅ — Default RuntimePolicy library implemented with 7 curated policies, Helm configuration, comprehensive documentation, and e2e test coverage.
Buffering reduces API server writes from O(events/s) to O(events / maxSize)
**Completed deliverables:**
- `charts/kyverno-runtime/templates/default-policies.yaml` ✅ — 7 production-ready policies
- `charts/kyverno-runtime/values.yaml` ✅ — Configuration options
- `docs/users/library.md` ✅ — Complete policy reference (user-facing guide)
- `test/e2e/default-policies/` ✅ — E2E test suite
or O(1/timeout), matching KubeScape's alert-bulking model.

Changes required:

- Add `pkg/pipeline/finding_buffer.go` with `FindingBuffer` type and
  flush logic (size trigger, timer trigger, drain).
- Update `WatchManager` to create one `FindingBuffer` per pod watch and
  send findings to it instead of calling `reporter.Report` directly.
- Make `maxSize` and `flushTimeout` configurable in the runtime config
  struct and wired from `cmd/kyverno-runtime/main.go`.
- Add `kyverno_runtime_reporter_buffer_depth{namespace,pod}` gauge.

Deliverables:

- `pkg/pipeline/finding_buffer.go` + `finding_buffer_test.go`
- `pkg/pipeline/watch_manager.go` — integrate buffer
- `pkg/config/` — add `FindingBufferMaxSize`, `FindingBufferFlushTimeout`
- `cmd/kyverno-runtime/main.go` — wire config values
- Helm chart values for both settings

### Phase 8.3: Time-Bucket Event Deduplication (Priority 3 — Medium effort)

Status: **PROPOSED**

High-frequency benign events (a web server opening its config file on every
request, or a shell loop) produce structurally identical eBPF packets in rapid
succession. Without pre-CEL deduplication, each triggers a full CEL evaluation
pass across all validations. KubeScape marks events as `Duplicate` using 64 ms
time-bucket fingerprints and the rule manager short-circuits before any CEL
work.

Design:

- Compute a fingerprint per event using key fields per event type:

  | Event type | Fingerprint fields |
  | --- | --- |
  | `exec` | `comm` + `path` + `pid` |
  | `open` | `path` + `flags` |
  | `connect` / `tcpconnect` | `destination.ip` + `destination.port` + `l4proto` |

- Bucket fingerprints by 64 ms wall-clock slots (matching KubeScape's
  `DedupBucket` approach).
- On a cache hit within the same bucket, mark the event as duplicate and
  skip CEL evaluation.
- Cache is per-watch (per-pod), bounded by a configurable size
  (default: 10,000 entries), evicted by LRU.

Changes required:

- Add `pkg/pipeline/event_dedup.go` with `EventDeduplicator` and per-type
  fingerprint functions.
- Call dedup check in `WatchManager` event handler before evaluator.
- Add metric `kyverno_runtime_datasource_events_deduped_total{event_type}`.

Deliverables:

- `pkg/pipeline/event_dedup.go` + `event_dedup_test.go`
- `pkg/pipeline/watch_manager.go` — call dedup before evaluate
- `pkg/observability/metrics.go` — new counter
- `pkg/config/` — `DedupCacheSize`, `DedupBucketMs` config fields

### Phase 8.4: Node-Wide Shared Gadgets (Priority 4 — High effort, highest ceiling)

Status: **PROPOSED**

The dominant scalability cost is the current model of one eBPF program per pod
per event type. Each call to `streamGadget` allocates a fresh eBPF program,
perf-buffer pair, and goroutine. At 50 pods × 3 event types that is
150 concurrent programs. KubeScape runs 3 node-wide programs and
demultiplexes by mount namespace / container ID.

Design:

```text
NodeTracer (one per event type)
    │
    └── shared eBPF gadget (trace_exec / trace_open / trace_tcp)
            │
            └── packetToRuntimeEvents()
                        │
                    PodRouter.Route(namespace, podName)
                        │
                    pod-A channel  ──> WatchManager pod-A handler
                    pod-B channel  ──> WatchManager pod-B handler
                    pod-C channel  ──> WatchManager pod-C handler
```

A `NodeTracer` owns one long-running gadget per event type. Pod watches
register/deregister channels with the `NodeTracer` keyed on
`(namespace, podName)`. The node-level gadget survives pod churn entirely;
no restart on policy changes.

Event routing uses the mount namespace ID (most reliable) falling back to
`k8s.namespace` + `k8s.podName` fields extracted from the packet.

Changes required:

- Add `pkg/datasource/node_tracer.go` — `NodeTracer` and `PodRouter`.
- Refactor `WatchManager` to use `NodeTracer` channel subscriptions instead
  of calling `StreamEventsForPod` per pod.
- Update `inspektor_gadget_runner_linux.go` to expose a channel-based
  subscription API alongside the existing stream API.
- Add metric `kyverno_runtime_watches_active{event_type}` gauge.
- Add metric `kyverno_runtime_datasource_events_received_total{event_type}` counter.
- Phase 8.1 (nodeName filter) is a prerequisite.

Deliverables:

- `pkg/datasource/node_tracer.go` + `node_tracer_test.go`
- `pkg/pipeline/watch_manager.go` — refactored to use `NodeTracer`
- `pkg/datasource/interface.go` — new `NodeTracerSource` interface
- `cmd/kyverno-runtime/main.go` — wire `NodeTracer` construction
- Updated `docs/dev/DESIGN.md` node-wide collection model

### Phase 8.5: CEL Expression Prefilter (Priority 5 — Medium effort)

Status: **PROPOSED**

When a CEL condition contains a literal equality constraint such as
`event["path"] == "/etc/shadow"`, the current evaluator still runs the full
CEL engine for every `open` event regardless of the `path` value. KubeScape's
`prefilter` package statically analyses CEL expressions at policy load time to
extract literal equality and prefix constraints, then skips CEL evaluation
entirely when the extracted fields can't satisfy them.

Design:

- At `WatchManager.Sync` time, parse each validation's CEL conditions using
  the CEL AST to extract:
  - `path == <literal>` → `PathEquals`
  - `path.startsWith("<prefix>")` → `PathPrefix`
  - `destination.port == <int>` → `DestPortEq`
  - If no constraint can be extracted, set `PassThrough = true`.
- In the event handler, before calling `evaluator.Evaluate`, run the
  prefilter. Skip CEL if no hint matches (and `PassThrough == false`).
- Store compiled prefilter hints in the watch alongside the policy list.

Changes required:

- Add `pkg/pipeline/cel_prefilter.go` — `PrefilterHint` type and
  `AnalyzeConditions()` function using CEL AST visitor.
- Call prefilter in `WatchManager` event handler.
- Add metric `kyverno_runtime_evaluator_prefiltered_total{policy,validation}`.

Deliverables:

- `pkg/pipeline/cel_prefilter.go` + `cel_prefilter_test.go`
- `pkg/pipeline/watch_manager.go` — call prefilter before evaluate
- `pkg/observability/metrics.go` — new counter

### Phase 8.6: Rule Cooldown (Priority 6 — Low effort)

Status: **PROPOSED**

Without a cooldown mechanism, a single detection rule can fire continuously
for the same workload (e.g. `cred-access-shadow` fires on every `/etc/shadow`
access), flooding the PolicyReport and producing alert fatigue. KubeScape
gates `SendRuleAlert` calls through a `RuleCooldown` tracker that suppresses
repeated identical findings within a configurable window.

Design:

- Add `pkg/pipeline/rule_cooldown.go` with `CooldownTracker`:
  - Key: `(policyName, ruleName, namespace, pod)`.
  - After the first finding is reported for a key, suppress for
    `cooldownDuration` (default: 5 m).
  - Bounded LRU cache (default: 10,000 entries) to cap memory.
- Call in `WatchManager` before `reporter.Report` (or `FindingBuffer.Add`).
- Make duration and cache size configurable.

Deliverables:

- `pkg/pipeline/rule_cooldown.go` + `rule_cooldown_test.go`
- `pkg/pipeline/watch_manager.go` — call cooldown check
- `pkg/config/` — `RuleCooldownDuration`, `RuleCooldownCacheSize`
- Helm chart values for both settings
- Add metric `kyverno_runtime_evaluator_cooldown_skipped_total{policy,rule}`

### Phase 8.7: CEL Pre-Compilation at Watch Start (Priority 7 — Low effort)

Status: **PROPOSED**

CEL programs are currently compiled lazily on the first event that exercises
a given expression. Compilation errors therefore surface mid-stream (on a
live event) rather than at policy activation time. The compiled program cache
already exists in `pkg/policy/evaluator.go`; this change moves the trigger
from lazy to eager.

Changes required:

- Add an `EnsureCompiled(policy *v1alpha1.RuntimePolicy) error` method to
  `policy.Evaluator` that pre-compiles all CEL expressions from a policy's
  validations and match conditions using the existing `compileCELProgram`
  path.
- Call `EnsureCompiled` in `WatchManager.Sync` when adding a new watch.
- If pre-compilation returns an error, log it and skip starting the watch
  for that policy (with a metric increment), surfacing the problem at
  reconcile time.
- Add metric `kyverno_runtime_evaluator_compile_errors_total{policy}`.

Deliverables:

- `pkg/policy/evaluator.go` — `EnsureCompiled` method
- `pkg/policy/evaluator_test.go` — pre-compile test
- `pkg/pipeline/watch_manager.go` — call `EnsureCompiled` at watch start
- `pkg/observability/metrics.go` — new counter

### Phase 8.8: Enhanced Observability Metrics (Priority 8 — Low effort)

Status: **PROPOSED**

The current four counters provide minimal visibility into pipeline
performance. This phase adds the metrics needed to observe and tune the
improvements from Phases 8.1–8.7, aligned with KubeScape's observability
model.

New metrics to add in `pkg/observability/metrics.go`:

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `kyverno_runtime_evaluator_duration_seconds` | Histogram | `policy`, `validation`, `event_type` | CEL evaluation duration |
| `kyverno_runtime_evaluator_prefiltered_total` | Counter | `policy`, `validation` | Events skipped by CEL prefilter |
| `kyverno_runtime_datasource_events_deduped_total` | Counter | `event_type` | Events skipped by time-bucket dedup |
| `kyverno_runtime_watches_active` | Gauge | `event_type` | Currently active streaming watches |
| `kyverno_runtime_reporter_buffer_depth` | Gauge | `namespace` | Per-pod finding buffer depth |
| `kyverno_runtime_datasource_events_received_total` | Counter | `event_type` | Raw events received from gadget |
| `kyverno_runtime_evaluator_cooldown_skipped_total` | Counter | `policy`, `rule` | Findings suppressed by rule cooldown |
| `kyverno_runtime_evaluator_compile_errors_total` | Counter | `policy` | CEL programs that failed pre-compilation |

Deliverables:

- `pkg/observability/metrics.go` — register all new metrics
- `pkg/observability/metrics_test.go` — registration smoke test
- Update `docs/dev/DESIGN.md` metrics table

---

### Phase 8 Summary Table

| Phase | Enhancement | Effort | Impact |
| --- | --- | --- | --- |
| 8.1 | nodeName pod filtering | Low | Correctness + eliminates off-node waste |
| 8.2 | Per-pod finding buffer | Medium | Reduces API server write load |
| 8.3 | Time-bucket event dedup | Medium | Reduces CEL evaluation load |
| 8.4 | Node-wide shared gadgets | High | Dominant scalability win (O(event_types) vs O(pods × event_types)) |
| 8.5 | CEL expression prefilter | Medium | Eliminates evaluations for high-frequency benign events |
| 8.6 | Rule cooldown | Low | Reduces alert fatigue and PolicyReport churn |
| 8.7 | CEL pre-compilation at watch start | Low | Surfaces errors at activation; eliminates first-event lag |
| 8.8 | Enhanced observability metrics | Low | Observability prerequisite for tuning all of the above |

---

## Phase-by-Phase Implementation Task List

This section is the execution checklist for implementation. Each phase includes
task-level work items and a clear definition of done.

### Execution Phase 0: Foundation Alignment

Implementation tasks:

- Verify all feature gates are wired end-to-end (flags, config, chart, manifest).
- Confirm defaults and docs are consistent across README, chart values, and manager manifests.
- Keep feature gates disabled by default where required for safe rollout behavior.

Definition of done:

- `make build` and `make test` pass.
- Helm render includes all feature-gate flags with expected defaults.

### Execution Phase 0.5: Quickstart Reliability and Guardrails

Implementation tasks:

- Add `make quickstart-verify` script flow in `hack/`.
- Validate expected quickstart report shape (open + network policies) with actionable failure output.
- Add stale-image diagnostics (print Runtime DaemonSet `Image ID` on verification failure).

Definition of done:

- Quickstart verifier succeeds on fresh kind install.
- Failure cases provide deterministic remediation hints.

### Execution Phase 0.6: E2E Test Resilience and Speed

Implementation tasks:

- Add DaemonSet readiness assert step to all e2e tests before creating workload pods.
- Replace heuristic fractional sleeps in demo-pod commands with integer-sleep loops.
- Set explicit `parallel` value in `test/e2e/.chainsaw.yaml`.
- Add `make test-e2e-quickstart` target for fast smoke checking.
- Add `make validate-policies` target (`kubectl apply --dry-run=server` on all samples and chart templates).
- Add `make verify-crds` target to detect CRD drift between chart and cluster/source.

Definition of done:

- All e2e tests pass three consecutive runs without flakes on a fresh kind cluster.
- `make test-e2e-quickstart` completes in under 90 s.
- `make validate-policies` catches CEL expression errors rejected by K8s validation.
- `make verify-crds` fails on API group mismatch.

### Execution Phase 1: Baseline Lifecycle and Confidence

Implementation tasks:

- Implement lifecycle orchestration in controller/pipeline for learning/monitor/enforce.
- Implement confidence/status updates (`observedFrom`, `observedTo`, `sampleCount`, `dropRate`).
- Implement staleness detection and relearning transitions.
- Implement shared-default merge path (`spec.allow`, `refs`, `status.observed`) in evaluation flow.
- Add transition and merge precedence tests.

Definition of done:

- Lifecycle transitions are covered by unit/integration tests.
- RuntimeBehavior status is updated consistently for active workloads.

### Execution Phase 2.1: Default RuntimePolicy Library

Implementation tasks:

- Create curated default RuntimePolicy manifests under chart/templates or referenced install assets.
- Add enable/disable toggle for installing policy library.
- Add policy metadata labels/annotations for ownership and versioning.
- Add e2e tests asserting expected findings from library rules.

Definition of done:

- Fresh install produces default policy resources when enabled.
- Library rules generate expected runtime report outcomes in e2e
  (legacy PolicyReport pre-migration; OpenReports post-migration).

### Execution Phase 2.2: Security-Owned RuntimeBehavior Auto-Enrollment

Implementation tasks:

- Add enrollment flags: controller kinds, bare-pod toggle, namespace include/exclude, initial mode.
- Implement workload identity resolution and idempotent RuntimeBehavior creation.
- Implement explicit opt-out exception controls (auditable by label/annotation policy).
- Add controller tests for enrolled controller-managed pods and optional bare pods.

Definition of done:

- Eligible workloads get exactly one managed RuntimeBehavior profile.
- Non-eligible workloads are skipped deterministically by enrollment policy.

### Execution Phase 3: Dual Detection Engines Integration

Implementation tasks:

- Wire signature/anomaly engines into live evaluator and watch manager paths.
- Route feature gates to evaluator construction behavior.
- Resolve runtime baseline loading/caching in monitor/enforce paths.
- Normalize finding shape (rule ID, severity, fingerprint) across CEL/signature/anomaly outputs.
- Add e2e coverage validating dual-engine findings in live controller execution.

Definition of done:

- Dual-engine findings appear in runtime reports with stable dedup behavior
  (legacy PolicyReport pre-migration; OpenReports post-migration).
- Feature gates can independently enable/disable engine paths.

### Execution Phase 4: Alert Aggregation and Suppression

Implementation tasks:

- Extend reporter aggregation fields (`firstSeen`, `lastSeen`, `count`, `window`).
- Add cooldown/burst suppression controls and config wiring.
- Add tests for aggregation correctness and suppression windows.

Definition of done:

- High-frequency findings are aggregated and rate-limited as configured.

### Execution Phase 5: OpenReports Output, Kubernetes Events, and Metrics

Implementation tasks:

- Implement OpenReports scheme/dependencies and writer backend as the sole persisted report output.
- Implement finding model mapping to OpenReports schema.
- Emit Kubernetes Events for key detection/lifecycle transitions with dedup/rate limiting.
- Add output-path metrics (success/failure counters, latency, emitted/dropped, rate-limited).
- Add unit/integration tests for OpenReports writes, Event emission behavior, and metric updates.

Definition of done:

- OpenReports is the only persisted runtime report backend.
- Kubernetes Events are emitted for configured classes without uncontrolled amplification.
- Metrics cover output and eventing health and are validated by tests.

### Execution Phase 5.5: Legacy PolicyReport Migration (Folded into Phase 5)

Implementation tasks:

- Publish one-time migration guidance for upgrading existing PolicyReport-based installs.
- Provide upgrade validation and rollback guidance for legacy clusters.
- Do not introduce dual-write as a steady-state path.

Definition of done:

- Migration runbook is documented and validated on kind upgrade flow.
- No active PolicyReport output path remains after migration.

### Execution Phase 6: Persistence Hardening and Compaction

Implementation tasks:

- Implement bounded retention and compaction for baseline internals.
- Add normalization for high-cardinality paths/domains where beneficial.
- Add overflow markers and cap enforcement tests.

Definition of done:

- Baseline storage growth is bounded and verified by regression checks.

### Execution Phase 7: Operational Readiness

Implementation tasks:

- Add preflight checks for eBPF/kernel capability readiness.
- Add operational SLO metrics for collection, evaluation, suppression, and sink health.
- Publish operator runbook updates.

Definition of done:

- Runtime exposes operationally actionable health and performance signals.

### Execution Phase 8: Scalability and Performance

Implementation tasks:

- Implement Phases 8.1 through 8.8 in priority order.
- Benchmark before/after API write rate, evaluator throughput, and event latency.
- Validate no regression in finding correctness while optimizing hot paths.

Definition of done:

- Node-scale test shows reduced API churn and stable detection fidelity.

---

## Cross-Cutting Validation

### Unit and integration tests

```bash
go test ./...
```

Coverage targets:

- baseline lifecycle transitions
- confidence-aware severity outcomes
- enrollment selector behavior (controller kinds + namespace scope + bare pod toggle)
- aggregation/suppression logic
- sink retry/rate-limit behavior

### Helm and manifest validation

```bash
helm template kyverno-runtime ./charts/kyverno-runtime -n kyverno-runtime >/tmp/kyverno-runtime-rendered.yaml
```

Validate generated config for:

- feature gates
- lifecycle parameters
- output/event settings
- suppression settings

### kind validation

```bash
kind create cluster --name kyverno-runtime || true
kubectl config use-context kind-kyverno-runtime
helm upgrade --install kyverno-runtime ./charts/kyverno-runtime -n kyverno-runtime --create-namespace --wait
kubectl get pods -n kyverno-runtime
kubectl get ds -n kyverno-runtime
kubectl api-resources | grep -i report
```

## Risks and Mitigations

- Alert storms from incomplete baselines
  - Mitigation: lifecycle gating, confidence-aware severity, suppression windows.
- Startup noise widens learned profiles, reducing detection fidelity
  - Mitigation: readiness-aware learning (`startAfter: ready`), multi-source
    profile building, profile export/merge tooling.
- Increased compute overhead from dual engines
  - Mitigation: feature gates, sampling, scoped auto-enrollment controls.
- False positives due to dynamic workloads
  - Mitigation: normalization, periodic relearning, rule tuning guidance.
- Operational complexity from multiple output channels
  - Mitigation: explicit defaults, health metrics, and conservative rate limiting.

## Completion Criteria

- RuntimeBehavior lifecycle and confidence metadata are implemented and surfaced.
- Default RuntimePolicy library is shipped and enabled by documented install flow.
- RuntimeBehavior auto-enrollment is implemented for configured controller kinds.
- Bare pod enrollment is configurable and disabled by default.
- Dual engines (anomaly + signature) are functional behind feature gates.
- Alert aggregation/suppression is production-ready.
- OpenReports output path with Kubernetes Events and metrics is production-ready.
- `go test ./...` passes.
- kind install validates healthy runtime behavior with generated runtime reports and
  controlled alert output.
