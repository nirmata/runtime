# RuntimePolicy reference

`RuntimePolicy` is the single CRD Nirmata Runtime reads. It names the pods to watch, the
behaviors to allow or deny, and whether the daemon blocks or only reports.

| Property | Value |
| --- | --- |
| Group/version | `runtime.nirmata.io/v1alpha1` |
| Kind | `RuntimePolicy` |
| Scope | Cluster |
| Short name | `rpol` |
| Status subresource | yes |
| Print columns | `Mode`, `Applied`, `Reason`, `Age` |

```bash
kubectl get rpol
kubectl get rpol <name> -o yaml
```

## Spec reference

| Field | Type | Meaning |
| --- | --- | --- |
| `spec.podSelector` | `LabelSelector` | Pods this policy applies to. Absent selects every pod on the node. Relabeling a pod re-evaluates the match. |
| `spec.mode` | `monitor` \| `enforce` | What the daemon does with a matched pod. Optional, with no default. |
| `spec.evaluationInterval` | duration | How often matched pods are re-evaluated. Required to pick up changes behind a `resource` or `http` expression. |
| `spec.variables` | list of `name` + `expression` | Named CEL expressions, referenced as `variables.<name>` from any other expression. |
| `spec.behaviors` | list | One entry per behavior kind; each entry configures exactly one of `network`, `exec`, `open`. |

Each entry in `spec.behaviors` configures exactly one of `network`, `exec`, or `open`.
Each of those takes an `allow` and/or a `deny` rule, and each rule accepts a literal
`values` list, a CEL `expression` that evaluates to `list(string)`, or both (the two
are unioned):

```yaml
spec:
  behaviors:
  - network:            # exactly one of network | exec | open per list item
      allow:
        values: [...]        # literal list of allowed items
        expression: "..."    # CEL expression returning list(string), unioned with values
      deny:
        values: [...]
        expression: "..."
```

- `network`: IPv4 addresses for egress.
- `exec`: command names/paths.
- `open`: file paths.
- `deny.values: ["*"]` (or an expression that returns `["*"]`) is treated as a
  **default deny** for that behavior (`network`, `exec`, or `open`). This is
  evaluated across all `RuntimePolicy` objects matching a pod: if any one of
  them sets a default deny for a behavior, that behavior becomes
  deny-all-except-allowed, and the allow list is the union of `allow` entries
  from every matching policy. If none of the matching policies set a default
  deny for that behavior, it defaults to allow-all-except-denied, where the
  deny list is the union of `deny` entries from every matching policy.
- `spec.variables` defines named CEL expressions that can be reused across behaviors via
  `variables.<name>` inside any `expression`.
- `expression` must evaluate to a statically-typed `list(string)`. Functions that return
  `dyn` (e.g. `http.get(...).body`, `json.unmarshal(...)`) need an explicit coercion, since
  the checker can't infer a concrete element type from `dyn` on its own:
  `someDynValue.map(x, string(x))`.
- `spec.mode` selects `enforce` or `monitor` (see below). It is optional; a policy that omits
  it neither enforces nor reports.

An entry that sets more than one of `network`, `exec`, `open` — or none of them — is
rejected at admission by a CEL validation rule on the CRD.

Expression syntax, the available CEL libraries, and the `resource`/`http`/`json` helpers
are in [CEL in RuntimePolicy](cel.md).

## Modes: enforce and monitor

`spec.mode` selects what the daemon does with a matched pod:

| `spec.mode` | Kernel programs attached | Deny/allow maps programmed | Blocks | Emits findings |
| --- | --- | --- | --- | --- |
| `enforce` | yes | yes | yes | no |
| `monitor` | yes | **no** (maps stay empty) | no | yes |
| omitted | no | no | no | no |

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: nginx-baseline-monitor
spec:
  mode: monitor
  podSelector:
    matchLabels:
      app: nginx
  behaviors:
  - network:
      deny:
        values:
        - "198.51.100.23"
  - open:
      deny:
        values:
        - "/etc/shadow"
```

In `monitor` mode the same eBPF programs are attached to the same matched pods, but with
**empty** `banned`/`allowed` maps and default-deny left off, so nothing is ever blocked. What
the programs do is *count* what the workload touched:

- the LSM programs count every `file_open` / `bprm_check_security` path per cgroup;
- the egress program counts every destination IPv4 address per pod.

The daemon polls those counters every 10 seconds, attributes each observation to a pod (via the
cgroup ID → pod index built from the local pod watch), and evaluates the policy's `allow`/`deny`
lists **in userspace**. A match produces a finding (see
[Findings and Reports](#findings-and-reports)). Because counters are read-and-reset, each observation carries the number of occurrences
since the previous poll.

Matching in monitor mode follows the same semantics as enforcement: an explicit `deny` entry
matches, and under a default deny (`deny.values: ["*"]`) anything absent from `allow` matches.
`monitor` and `enforce` are per policy, so a pod can be monitored by one policy while another
enforces on it. Switching a policy's `mode` rebuilds its attachments, because an observing
program must never inherit deny entries and an enforcing one must not start from empty maps.

## Status

`status` is written per node. Each daemon owns exactly one entry in `status.nodes` (keyed by
`nodeName`) and never touches another node's entry; `status.lastEvaluatedTime` is the newest shard
timestamp. Updates are flushed every 30 seconds with conflict retry.

Per-pod detail is not in the status. Which pods a policy matched and which of them violated it are
in the Reports (which name them) and in the Prometheus counters; the status answers "is this policy
loaded on this node, in which mode, and when was it last evaluated".

```yaml
status:
  lastEvaluatedTime: "2026-07-27T10:15:04Z"
  nodes:
  - nodeName: node-1
    lastEvaluatedTime: "2026-07-27T10:15:04Z"
  - nodeName: node-2
  conditions:
  - type: Applied
    status: "True"
    reason: Monitoring
    message: the policy is observed and reported but never blocks
  - type: TargetsValid
    status: "False"
    reason: UnsupportedTargets
    message: '2 network target(s) cannot be programmed: "example.com": not an IPv4 ...'
```

Conditions:

| Type | Reasons | Meaning |
| --- | --- | --- |
| `Applied` | `Enforcing`, `Monitoring` | The daemon has the policy loaded, and in which mode. |
| `TargetsValid` | `AllTargetsSupported`, `NoTargets`, `UnsupportedTargets` | Whether every `network` target could be programmed. `UnsupportedTargets` lists the rejected values and why. |
| `ExecRulesValid` | `AllPathsSupported`, `NoPaths`, `UnsupportedPaths` | Whether every `exec` path could be programmed. `UnsupportedPaths` lists the rejected values and why. |
| `OpenRulesValid` | `AllPathsSupported`, `NoPaths`, `UnsupportedPaths` | The same for `open` paths. |
| `ObservationAvailable` | `ObservationUnavailable` | Set to `False` when a loaded LSM program has no observation maps, so a monitor-mode policy would silently produce no findings. |

A target or path the runtime cannot program is never silently skipped: it always reaches both an
operator-visible log line and a `False` condition.

## Findings and Reports

Monitor-mode matches are written as [OpenReports](https://openreports.io) `Report` objects in
the offending pod's namespace, one Report per (namespace, node), named
`kyverno-runtime-<nodeName>`, labeled `runtime.nirmata.io/node: <nodeName>`.

```bash
kubectl get reports -A
kubectl get report kyverno-runtime-node-1 -n default -o yaml
```

Each result carries `policy` (the RuntimePolicy name), `rule` (the behavior: `network`,
`open`, `exec`), `result: fail`, `severity: medium` (`RuntimePolicy` has no severity field yet),
`source: kyverno-runtime`, `category: Runtime Security`, the offending pod as
`subjects[0]`, and a fixed set of `properties`: `fingerprint`, `count`, `firstTimestamp`,
`lastTimestamp`, `behavior`, `enforced`, `node`, `container`, `owner`, `serviceAccount`,
and — where applicable — `destIP`, `destHost`, `comm`.

`enforced` distinguishes a blocked operation from one that only matched: it is `"false"` on
findings from a `monitor` policy, where the behavior was observed but allowed to proceed.

Details worth knowing:

- Findings are buffered and flushed every 10 seconds, deduplicated by a stable fingerprint of
  (policy, behavior, pod, target), so a repeated observation increments `count` rather than
  appending a result.
- Reports are capped at 500 results; a truncated Report is annotated
  `runtime.nirmata.io/truncated-results: "true"`.
- Pod labels are never copied into a Report, and there is no mechanism to attach arbitrary
  key/values to one. Every emitted value is scrubbed on the way out. This is not configurable.
- A finding for a pod whose namespace is not a valid DNS-1123 label is dropped rather than
  written to an invalid object name.

Counters for ingested observations, dropped observations, and emitted findings are in
[Metrics](metrics.md).

## Limits of monitor mode

Monitor mode is built on the counters the existing eBPF programs already keep. It adds no new
kernel programs, and it does not observe DNS names, TLS SNI, or HTTP. These are real,
current limits, not rounding errors:

- **Observation is poll-based, not streamed.** There is no ring buffer; counters are drained
  every 10 seconds, so a finding can lag the behavior by up to that interval, and only counts
  are preserved — not the ordering or timing of individual occurrences within a window.
- **Open/exec path counters cap per cgroup.** The per-cgroup path map holds 2048 distinct
  `(path, decision)` keys; a workload touching more than that within one poll interval loses
  the excess. The read-and-reset drain mitigates this but does not eliminate it.
- **Network observation is IPv4 only** — destination address only, with no port or protocol —
  because the egress maps are keyed on a `u32` IPv4 address.
- **Unsupported `network` targets are rejected, not skipped.** IPv6 literals, CIDRs wider than
  `/24`, and hostnames cannot be programmed (hostnames in particular cannot be resolved at
  policy-evaluation time). They are reported through `TargetsValid=False` with the reason per
  value. A CIDR of `/24` or narrower is expanded into individual addresses.
- **`open` and `exec` values are literal paths, bounded at 127 bytes.** They are never split into
  tokens and never treated as globs; only the whole value `"*"` is the default-deny sentinel. A
  longer value, an empty one, or one carrying a NUL byte is rejected at admission and reported
  through `ExecRulesValid=False` / `OpenRulesValid=False` if it arrives from an `expression`.
- **Observations that cannot be attributed to a pod are dropped** and counted in
  `nirmata_runtime_attribution_misses_total`. Node-level and host-process activity is
  therefore not reported.

## Worked examples

Each directory holds runnable manifests and a walkthrough. Every manifest under `examples/` is
validated in CI.

Network egress enforcement and observation require only a cgroup v2 host and BPF support; a
stock kind cluster on a Linux host qualifies.

File `open` and process `exec` enforcement require a kernel booted with BPF-LSM active: `bpf`
must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel boot parameter). Stock
distributions and hosted CI runners are typically not booted with it.

| Example | Pattern it demonstrates | Mode | Requires |
| --- | --- | --- | --- |
| [block-known-bad-egress](../../../examples/block-known-bad-egress/) | Deny a literal destination IPv4 with `deny.values` | `enforce` | cgroup v2 |
| [default-deny-egress](../../../examples/default-deny-egress/) | `deny.values: ["*"]` plus an `allow` list | `enforce` | cgroup v2 |
| [monitor-egress](../../../examples/monitor-egress/) | Same policy shape observed instead of blocked | `monitor` | cgroup v2 |
| [deny-sensitive-file-access](../../../examples/deny-sensitive-file-access/) | `open` deny with `values` unioned with a `variables` expression | `enforce` | BPF-LSM |
| [restrict-exec-allowlist](../../../examples/restrict-exec-allowlist/) | Default-deny `exec` with an allow-list | `enforce` | BPF-LSM |
| [monitor-workload-baseline](../../../examples/monitor-workload-baseline/) | `network`, `exec`, and `open` observed together | `monitor` | BPF-LSM for `open`/`exec`; egress findings alone need only cgroup v2 |
| [blocklist-from-configmap](../../../examples/blocklist-from-configmap/) | `resource.get` with `evaluationInterval` | `enforce` | cgroup v2 |
| [blocklist-from-http](../../../examples/blocklist-from-http/) | `http.get` with the `dyn` coercion | `enforce` | cgroup v2 |
| [blocklist-from-json](../../../examples/blocklist-from-json/) | `json.unmarshal` composed with `resource.get` | `monitor` | cgroup v2 |
| [enforce-workload-baseline](../../../examples/enforce-workload-baseline/) | All three behaviors under default-deny with `evaluationInterval` | `enforce` | BPF-LSM |

The full catalog, grouped by feature, is in [Examples](../examples.md).
