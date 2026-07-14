# RuntimePolicy

## Table of Contents

- [Spec reference](#spec-reference)
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

`http.get(url)` returns a `dyn`-typed value shaped like `{"statusCode": ..., "body": ...}`.
Since the checker can't statically infer `.body`'s element type as `list(string)`,
coerce it explicitly with the CEL `map` macro. As with the ConfigMap example, this
pulls from external, mutable state, so set `evaluationInterval` to keep it fresh:

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
convenient place to stage the parsing before it's used in a behavior expression.

`json.unmarshal` returns `dyn`, so indexing into it (e.g. `variables.jsonObj["ips"]`) is
still `dyn`, not a statically-typed `list(string)` — the same issue as `http.get(...).body`
above. Coerce it explicitly with the CEL `map` macro, same as the `http` example:

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
