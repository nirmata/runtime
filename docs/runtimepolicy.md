# RuntimePolicy

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

- `network`: IP addresses for egress.
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
