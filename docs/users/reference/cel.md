# CEL in RuntimePolicy

CEL appears in three places in a `RuntimePolicy`:

- `spec.variables[].expression` — a named expression, referenced elsewhere as `variables.<name>`.
- `spec.behaviors[].{network,exec,open}.{allow,deny}.expression` — the rule's dynamic list of
  targets.
- `spec.monitorFilter.expressions[].expression` — a predicate over one observation, deciding
  whether it becomes a finding.

The first two are evaluated when the policy is evaluated against a matched pod, not once per
kernel event. The kernel sees only the resulting flat lists of IPv4 addresses, command paths,
or file paths. An expression that reads external state therefore returns a snapshot;
`spec.evaluationInterval` is the knob that refreshes it.

A `monitorFilter` expression is the other shape: it runs once per candidate finding, over an
`event` variable, in a [narrower environment](#monitorfilter-expressions).

## Expression contract

A `spec.variables` or behavior-rule `expression` must type-check to a statically-typed
`list(string)`. Its result is unioned with the rule's literal `values`, so a rule can carry
both. (A `monitorFilter` expression types as `bool` instead — see
[monitorFilter expressions](#monitorfilter-expressions).)

Functions that return `dyn` — `http.get(...).body`, `json.unmarshal(...)`, and anything indexed
out of them — do not satisfy that on their own, because the checker cannot infer a concrete
element type from `dyn`. Coerce explicitly:

```text
someDynValue.map(x, string(x))
```

An expression that fails to compile or to type-check fails the policy's sync: nothing is
programmed for it, the daemon retries with backoff, and the error is logged after the retries
are exhausted. Check the daemon logs when a policy shows no `Applied` condition at all.

## Environment

The base environment enables homogeneous aggregate literals, eager declaration validation, UTC
as the default time zone, and cross-type numeric comparisons, plus these libraries:

| Group | Libraries |
| --- | --- |
| cel-go | optional types, `bindings`, `encoders`, `lists`, `math`, `protos`, `sets`, `strings` |
| Kubernetes | `CIDR`, `Format`, `IP`, `Lists`, `Regex`, `URLs`, `Quantity`, `Semver` |
| Kyverno SDK | `http`, `resource`, `json` |

The Kubernetes libraries are the same ones the apiserver exposes to CEL — see
[Kubernetes CEL library documentation](https://kubernetes.io/docs/reference/using-api/cel/).
The `http`, `resource`, and `json` libraries come from
[kyverno/sdk](https://github.com/kyverno/sdk), so an expression that works in a Kyverno
`ValidatingPolicy` works here.

## variables

`spec.variables` is an ordered list of `name`/`expression` pairs. A variable may reference an
earlier one, and any behavior expression may reference any of them as `variables.<name>`. It is
the place to stage a parse or a fetch that more than one rule needs, or to keep a long
expression out of the rule itself:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: deny-sensitive-files
spec:
  mode: enforce
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

Runnable version: [deny-sensitive-file-access](../../../examples/files-and-processes/deny-sensitive-file-access/).

## resource library

`resource.get(apiVersion, resource, namespace, name)` reads a cluster resource at policy
evaluation time, so a deny or allow list can be owned by a ConfigMap instead of being inlined
in the policy:

```text
resource.get("v1", "configmaps", "default", "ip-blocklist").data["ips"].split(",")
```

Two prerequisites:

- The daemon's ClusterRole grants no access to ConfigMaps or other arbitrary resources. Add the
  read permission the expression needs through the chart's `daemon.rbac.extraRules`.
- The list lives in external, mutable state, so set `spec.evaluationInterval` — without it the
  lookup happens once and the policy never sees a ConfigMap edit.

Runnable version: [blocklist-from-configmap](../../../examples/dynamic-lists/blocklist-from-configmap/).

## http library

`http.get(url)` returns a value shaped like `{"statusCode": ..., "body": ...}`. `body` is `dyn`,
so a rule consuming a JSON array of addresses has to coerce it:

```text
http.get("http://ip-server.default.svc.cluster.local:8080").body.map(x, string(x))
```

The fetch happens at policy evaluation time and on every re-evaluation, so
`spec.evaluationInterval` sets how often the feed is polled.

Runnable version: [blocklist-from-http](../../../examples/dynamic-lists/blocklist-from-http/).

## json library

`json.unmarshal(str)` parses a raw JSON string into a CEL value. It is what lets a policy pull a
list out of an arbitrary JSON blob rather than requiring the source to already be a
comma-separated string or a flat array. The result is `dyn`, so indexing into it still needs the
coercion:

```text
json.unmarshal(variables.jsonStr)["ips"].map(x, string(x))
```

It composes with the other two libraries — unmarshaling a blob fetched from a ConfigMap or an
HTTP endpoint:

```text
json.unmarshal(resource.get("v1", "configmaps", "default", "ip-blocklist-json").data["ips"])
```

Runnable version: [blocklist-from-json](../../../examples/dynamic-lists/blocklist-from-json/).

## monitorFilter expressions

`spec.monitorFilter.expressions` is a list of `name`/`expression` pairs evaluated once per
candidate monitor-mode finding. Each expression must type-check to `bool`, and the finding is
reported only if every one of them is true. The semantics — the ANDing, the short-circuit, the
fail-open direction, and why an `enforce` policy may not carry one — are in
[Filtering monitor findings](runtimepolicy.md#filtering-monitor-findings). What follows is the
`event` schema and the environment.

### The event variable

`event` is the observation the finding was formed from, in the same shape the event plane
carries it. It is a discriminated union: `kind` names the shape, and exactly one of `open`,
`exec`, `net`, `dns`, `protocol` is present. `has(event.exec)` is therefore both the kind test
and the guard that makes a later `event.exec.argv` safe to write.

| Path | Type | Notes |
| --- | --- | --- |
| `event.kind` | `string` | `net`, `dns`, `exec`, `open`, `protocol` |
| `event.time` | `timestamp` | |
| `event.comm` | `string` | Empty on `open`, and on an `exec` that came from the counter source. |
| `event.pid` | `int` | Ring-buffer sources only. |
| `event.count` | `int` | Greater than 1 aggregates that many occurrences from a poll source. |
| `event.kernelDenied` | `bool` | The kernel denied the operation — not that this policy is what denied it. |
| `event.wouldDeny` | `bool` | Never set on a `dns` event. |
| `event.pod.namespace`, `.name`, `.uid`, `.container`, `.containerID`, `.ownerKind`, `.ownerName`, `.nodeName`, `.serviceAccount` | `string` | |
| `event.pod.labels` | `map(string, string)` | |
| `event.open.path` | `string` | |
| `event.exec.filename` | `string` | |
| `event.exec.argv` | `list(string)` | Empty for the counter source. |
| `event.net.destIP`, `.domain` | `string` | `domain` is only ever a name some policy already named, so it can echo one back and can never surface one you did not write. |
| `event.dns.qname` | `string` | |
| `event.protocol.protocol`, `.alpn` | `string` | `alpn` is non-empty only for TLS. |

An unknown field is a compile error listing the valid ones, which is the intended way to learn
this table rather than to consult it.

Two traps are worth knowing before writing a guard:

- **`event.wouldDeny` is never set on a `dns` finding.** A `dns` violation is advisory — a
  question was observed, and nothing would have been blocked — so it carries no counterfactual.
  An expression guarding on `event.wouldDeny` silently drops every DNS finding.
- **`event.pod.labels` can only be conditioned on.** An expression returns a bool, so no label
  value can reach a Report; the reporter's refusal to emit pod labels is not weakened by a
  filter that reads them.

### The filter environment

A filter expression sees the `event` variable plus the cel-go and Kubernetes rows of
[Environment](#environment) — the string, regex, list, and CIDR/IP libraries.

The Kyverno SDK row is deliberately absent. `http.get`, `resource.get`, and `json.unmarshal`
reach out to a cluster or a network endpoint, which is affordable once per
`spec.evaluationInterval` and catastrophic once per kernel event. An expression naming one
fails to compile.
