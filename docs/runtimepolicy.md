# RuntimePolicy

## Table of Contents

- [Spec reference](#spec-reference)
- [Modes: enforce and monitor](#modes-enforce-and-monitor)
- [Status](#status)
- [Findings and Reports](#findings-and-reports)
- [Metrics](#metrics)
- [Limits of monitor mode](#limits-of-monitor-mode)
- [Example: RuntimePolicy](#example-runtimepolicy)
- [Example: deny using a CEL expression](#example-deny-using-a-cel-expression)
- [Example: allow using values and expressions](#example-allow-using-values-and-expressions)
- [Example: default deny with an allow list](#example-default-deny-with-an-allow-list)
- [Example: re-evaluated policy with a selector across multiple behaviors](#example-re-evaluated-policy-with-a-selector-across-multiple-behaviors)
- [Example: deny IPs from a ConfigMap (resource library)](#example-deny-ips-from-a-configmap-resource-library)
- [Example: deny IPs from an HTTP endpoint (http library)](#example-deny-ips-from-an-http-endpoint-http-library)
- [Example: parsing a JSON blob (json library)](#example-parsing-a-json-blob-json-library)

## Spec reference

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
- `spec.variables` defines named CEL expressions (`admissionregistrationv1.Variable`)
  that can be reused across behaviors via `variables.<name>` inside any `expression`.
- `expression` must evaluate to a statically-typed `list(string)`. Functions that return
  `dyn` (e.g. `http.get(...).body`, `json.unmarshal(...)`) need an explicit coercion, since
  the checker can't infer a concrete element type from `dyn` on its own:
  `someDynValue.map(x, string(x))`.
- `spec.mode` selects `enforce` or `monitor` (see below). It is optional; a policy that omits
  it neither enforces nor reports.

## Modes: enforce and monitor

`spec.mode` selects what the daemon does with a matched pod:

| `spec.mode` | Kernel programs attached | Deny/allow maps programmed | Blocks | Emits findings |
| --- | --- | --- | --- | --- |
| `enforce` | yes | yes | yes | no |
| `monitor` | yes | **no** (maps stay empty) | no | yes |
| omitted | no | no | no | no |

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
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
| `ObservationAvailable` | `ObservationUnavailable` | Set to `False` when a loaded LSM program has no observation maps, so a monitor-mode policy would silently produce no findings. |

A target the runtime cannot program is never silently skipped: it always reaches both an
operator-visible log line and a `TargetsValid=False` condition.

## Findings and Reports

Monitor-mode matches are written as [OpenReports](https://openreports.io) `Report` objects in
the offending pod's namespace, one Report per (namespace, node), named
`kyverno-runtime-<nodeName>`, labeled `runtime.kyverno.io/node: <nodeName>`.

```bash
kubectl get reports -A
kubectl get report kyverno-runtime-node-1 -n default -o yaml
```

Each result carries `policy` (the RuntimePolicy name), `rule` (the behavior: `network`,
`open`, `exec`), `result: fail`, `severity: medium` (`RuntimePolicy` has no severity field yet),
`source: kyverno-runtime`, `category: Runtime Security`, the offending pod as
`subjects[0]`, and a fixed set of `properties`: `fingerprint`, `count`, `firstTimestamp`,
`lastTimestamp`, `behavior`, `node`, `container`, `owner`, `serviceAccount`, and — where
applicable — `destIP`, `destPort`, `comm`, `argv`.

Details worth knowing:

- Findings are buffered and flushed every 10 seconds, deduplicated by a stable fingerprint of
  (policy, behavior, pod, target), so a repeated observation increments `count` rather than
  appending a result.
- Reports are capped at 500 results; a truncated Report is annotated
  `runtime.kyverno.io/truncated-results: "true"`.
- Pod labels are never copied into a Report, and there is no mechanism to attach arbitrary
  key/values to one. Every emitted value is scrubbed on the way out. This is not configurable.
- A finding for a pod whose namespace is not a valid DNS-1123 label is dropped rather than
  written to an invalid object name.

## Metrics

The daemon serves Prometheus metrics on `--metrics-addr` (default `:9090`, the chart's
`daemon.metrics.port`; set it to the empty string to disable the endpoint):

| Metric | Labels | Meaning |
| --- | --- | --- |
| `kyverno_runtime_events_ingested_total` | `source`, `kind` | Observations ingested by the collector. |
| `kyverno_runtime_events_dropped_total` | `source`, `reason` | Dropped observations (`buffer_full`, `unattributed`, `unattributed_kernel_deny`). |
| `kyverno_runtime_attribution_misses_total` | — | Observations that could not be tied to a pod. |
| `kyverno_runtime_findings_emitted_total` | `policy`, `behavior`, `severity` | Findings handed to the reporter. |
| `kyverno_runtime_report_writes_total` | `result` | Report write attempts (`ok`, `error`, `skipped`). |

`kyverno_runtime_policy_eval_errors_total{policy,stage}` is registered but not yet populated.

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
- **Observations that cannot be attributed to a pod are dropped** and counted in
  `kyverno_runtime_attribution_misses_total`. Node-level and host-process activity is
  therefore not reported.

## Example: RuntimePolicy

Deny loopback egress by literal value:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: detect-loopback-egress
spec:
  podSelector:
    matchLabels:
      app: nginx
  behaviors:
  - network:
      deny:
        values:
        - "127.0.0.1"
```

```bash
kubectl apply -f loopback-egress.yaml
kubectl get runtimepolicy detect-loopback-egress
```

## Example: deny using a CEL expression

`deny.expression` must evaluate to `list(string)`. Here it denies a set of IPs
computed at evaluation time rather than hardcoded in `values`:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: deny-known-bad-ips
spec:
  podSelector:
    matchLabels:
      app: nginx
  behaviors:
  - network:
      deny:
        expression: "['198.51.100.23', '198.51.100.24', '203.0.113.9']"
```

`values` and `expression` can be combined on the same rule — the results are
unioned, so this denies `/etc/shadow` plus whatever a variable-driven expression
produces:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: deny-sensitive-files
spec:
  podSelector:
    matchLabels:
      app: nginx
  variables:
  - name: extraDenied
    expression: "['/etc/gshadow', '/root/.ssh/id_rsa']"
  behaviors:
  - open:
      deny:
        values:
        - "/etc/shadow"
        expression: "variables.extraDenied"
```

## Example: allow using values and expressions

`allow` follows the same shape as `deny`. This lets an `nginx` pod exec only a
fixed set of binaries plus a set computed from a variable:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: allow-nginx-exec
spec:
  podSelector:
    matchLabels:
      app: nginx
  variables:
  - name: shells
    expression: "['/bin/sh', '/bin/bash']"
  behaviors:
  - exec:
      allow:
        values:
        - "/usr/sbin/nginx"
        - "/usr/bin/tail"
        expression: "variables.shells"
```

## Example: default deny with an allow list

Setting `deny.values: ["*"]` on a behavior switches it to default-deny: nothing
matches unless it's also present in `allow`. This is the pattern for a
"deny-all-then-allowlist" egress policy — only DNS and the internal API server
are reachable, everything else is blocked:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: default-deny-egress
spec:
  podSelector:
    matchLabels:
      app: nginx
  behaviors:
  - network:
      deny:
        values:
        - "*"
      allow:
        values:
        - "10.96.0.10"     # cluster DNS
        - "10.96.0.1"      # kube-apiserver
```

The same pattern applies to `exec` and `open` — deny everything, then allow only
the specific commands or files the workload needs:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: default-deny-exec
spec:
  podSelector:
    matchLabels:
      app: nginx
  behaviors:
  - exec:
      deny:
        values:
        - "*"
      allow:
        values:
        - "/usr/sbin/nginx"
        - "/usr/bin/nginx-debug"
```

`deny.expression` can also produce the default-deny sentinel dynamically, e.g.
gated by a variable, but in most cases a literal `deny.values: ["*"]` is clearer.

## Example: re-evaluated policy with a selector across multiple behaviors

Combine `network`, `exec`, and `open` in one policy, and re-check matched pods
every 30 seconds:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: nginx-baseline
spec:
  podSelector:
    matchLabels:
      app: nginx
  evaluationInterval: 30s
  behaviors:
  - network:
      deny:
        values:
        - "*"
      allow:
        values:
        - "10.96.0.10"
  - exec:
      allow:
        values:
        - "/usr/sbin/nginx"
  - open:
      deny:
        values:
        - "/etc/shadow"
        - "/etc/kubernetes/pki"
```

```bash
kubectl apply -f nginx-baseline.yaml
kubectl get runtimepolicy nginx-baseline
```

## Example: deny IPs from a ConfigMap (resource library)

The `resource` CEL library lets a behavior expression look up other cluster resources at
evaluation time, so a deny/allow list can be sourced from a ConfigMap instead of being
inlined in the policy. Because the list now lives in external, mutable state, set
`evaluationInterval` so the policy is periodically re-evaluated and picks up ConfigMap
changes without requiring an update to the `RuntimePolicy` itself:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ip-blocklist
  namespace: default
data:
  ips: "192.0.2.55,203.0.113.9"
```

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: deny-configmap-ips
spec:
  podSelector:
    matchLabels:
      app: nginx
  evaluationInterval: 5m
  behaviors:
  - network:
      deny:
        expression: resource.get("v1", "configmaps", "default", "ip-blocklist").data["ips"].split(",")
```

```bash
kubectl apply -f ip-blocklist.yaml
kubectl apply -f deny-configmap-ips.yaml
kubectl get runtimepolicy deny-configmap-ips
```

## Example: deny IPs from an HTTP endpoint (http library)

The `http` CEL library lets a behavior expression fetch a deny/allow list from an
external endpoint at evaluation time. This is a minimal Python server returning a JSON
array of IPs to block:

```python
#!/usr/bin/env python3
"""Minimal HTTP server returning a JSON list of IPs, for testing the CEL http library."""

import http.server
import json

IPS = ["198.51.100.23", "198.51.100.24", "203.0.113.9"]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(IPS).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
```

`http.get(url)` returns a value shaped like `{"statusCode": ..., "body": ...}`. As with the
ConfigMap example, this pulls from external, mutable state, so set `evaluationInterval` to
keep it fresh:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: deny-http-ips
spec:
  podSelector:
    matchLabels:
      app: nginx
  evaluationInterval: 5m
  behaviors:
  - network:
      deny:
        expression: http.get("http://ip-server.default.svc.cluster.local:8080").body.map(x, string(x))
```

```bash
kubectl apply -f deny-http-ips.yaml
kubectl get runtimepolicy deny-http-ips
```

## Example: parsing a JSON blob (json library)

The `json` CEL library parses a raw JSON string into a CEL value via `json.unmarshal(str)`,
letting a policy pull a deny/allow list out of an arbitrary JSON blob instead of requiring
the source to already be a plain comma-separated string or array. `spec.variables` is a
convenient place to stage the parsing before it's used in a behavior expression:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: deny-json-ips
spec:
  podSelector:
    matchLabels:
      app: nginx
  variables:
  - name: jsonStr
    expression: "\"{\\\"ips\\\":[\\\"198.51.100.23\\\",\\\"198.51.100.24\\\",\\\"203.0.113.9\\\"]}\""
  - name: jsonObj
    expression: json.unmarshal(variables.jsonStr)
  behaviors:
  - network:
      deny:
        expression: variables.jsonObj["ips"].map(x, string(x))
```

```bash
kubectl apply -f deny-json-ips.yaml
kubectl get runtimepolicy deny-json-ips
```

This composes with the `resource` and `http` libraries — for example, unmarshaling a JSON
blob fetched from a ConfigMap or an HTTP endpoint instead of a hardcoded variable:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: deny-configmap-json-ips
spec:
  podSelector:
    matchLabels:
      app: nginx
  evaluationInterval: 5m
  variables:
  - name: jsonObj
    expression: json.unmarshal(resource.get("v1", "configmaps", "default", "ip-blocklist-json").data["ips"])
  behaviors:
  - network:
      deny:
        expression: variables.jsonObj["ips"].map(x, string(x))
```

```bash
kubectl apply -f deny-configmap-json-ips.yaml
kubectl get runtimepolicy deny-configmap-json-ips
```
