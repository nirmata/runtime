# CEL in RuntimePolicy

CEL appears in two places in a `RuntimePolicy`:

- `spec.variables[].expression` — a named expression, referenced elsewhere as `variables.<name>`.
- `spec.behaviors[].{network,exec,open}.{allow,deny}.expression` — the rule's dynamic list of
  targets.

Expressions are evaluated when the policy is evaluated against a matched pod, not once per
kernel event. The kernel sees only the resulting flat lists of IPv4 addresses, command paths,
or file paths. An expression that reads external state therefore returns a snapshot;
`spec.evaluationInterval` is the knob that refreshes it.

## Expression contract

An `expression` must type-check to a statically-typed `list(string)`. Its result is unioned
with the rule's literal `values`, so a rule can carry both.

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

Runnable version: [deny-sensitive-file-access](../../../examples/deny-sensitive-file-access/).

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

Runnable version: [blocklist-from-configmap](../../../examples/blocklist-from-configmap/).

## http library

`http.get(url)` returns a value shaped like `{"statusCode": ..., "body": ...}`. `body` is `dyn`,
so a rule consuming a JSON array of addresses has to coerce it:

```text
http.get("http://ip-server.default.svc.cluster.local:8080").body.map(x, string(x))
```

The fetch happens at policy evaluation time and on every re-evaluation, so
`spec.evaluationInterval` sets how often the feed is polled.

Runnable version: [blocklist-from-http](../../../examples/blocklist-from-http/).

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

Runnable version: [blocklist-from-json](../../../examples/blocklist-from-json/).
