# Plan

## Proposed API

### Overview

`RuntimePolicy` is a namespaced CRD (`runtime.kyverno.io/v1alpha1`) that attaches behavioral rules to pods via a label selector. Rules are expressed as either a hardcoded list of values or a CEL expression that may reference `variables`. Because enforcement happens at the kernel level (eBPF), variables cannot be evaluated inline at event time — they are re-evaluated on a configurable `evaluationInterval` and the results are pushed into the BPF maps between events.

### Core Tenets

- Rules can be defined with a **hardcoded array** (simple cases) or a **CEL expression** (dynamic cases) — both are valid on the same field; they are merged at evaluation time.
- **Variables** are top-level named CEL expressions re-evaluated every `evaluationInterval`; they are available inside behavior expressions as `variables.<name>`.
- Supported CEL extension functions include `resource.get(...)` (fetch a Kubernetes object) and `http.get(...)` / `json.unmarshal(...)` for external data sources.
- `mode: enforce` enforces the rules; `mode: monitor` only logs/audits.

### Spec Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `spec.podSelector` | `LabelSelector` | yes | Selects pods this policy applies to |
| `spec.mode` | `enforce` \| `monitor` | yes | Whether to block or only audit violations |
| `spec.evaluationInterval` | `duration` | no | How often variables are re-evaluated (default: on policy creation/update) |
| `spec.variables` | `[]Variable` | no | Named CEL expressions made available to behavior rules |
| `spec.behaviors` | `[]Behavior` | yes | List of behavioral constraints |

**Behavior types**

| Behavior | Deny/Allow fields | Value field |
|---|---|---|
| `network` | `deny`, `allow` | `ips: []string` or `expression` |
| `exec` | `deny` | `cmd: []string` or `expression` |
| `open` | `deny` | `files: []string` or `expression` |

### Examples

#### 1. Full example — hardcoded and expression-based rules with variables

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: demo-policy
spec:
  podSelector:
    matchLabels:
      app: agent
  mode: enforce
  evaluationInterval: 15s
  variables:
  - name: isProd
    expression: false
  behaviors:
  - network:
      allow:
        ips:
        - "0.0.0.0"
        - "1.1.1.1"
        expression: >-
          ["*"]
      deny:
        expression: >-
          variables.isProd ?
            ["1.1.1.1"] :
            ["1.2.1.2", "3.3.3.3", "10.0.0.0/16"]
  - exec:
      deny:
        cmd:
        - "/usr/bin/ssh"
        expression: >-
          variables.isProd ?
            ["/bin/sh", "/bin/bash"] :
            []
  - open:
      deny:
        files:
        - "/etc/shadow"
        - "/run/containerd/containerd.sock"
```

#### 2. Simple deny — hardcoded values only

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: demo-policy
spec:
  podSelector:
    matchLabels:
      app: agent
  mode: monitor
  behaviors:
  - network:
      deny:
        ips:
        - "0.0.0.0"
        - "1.1.1.1"
  - exec:
      deny:
        cmd:
        - "/usr/bin/ssh"
  - open:
      deny:
        files:
        - "/etc/shadow"
        - "/run/containerd/containerd.sock"
```

#### 3. Deny-all except IPs from a ConfigMap (re-evaluated every 10s)

The `ips` key in the ConfigMap is expected to be a comma-separated list of IP addresses.

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: deny-all-except-defined-in-cm
spec:
  podSelector:
    matchLabels:
      app: agent
  mode: monitor
  evaluationInterval: 10s
  behaviors:
  - network:
      deny:
        ips:
        - "*"
  - network:
      allow:
        expression: >-
          resource.get("v1", "configmaps", "default", "allowedIPs").data["ips"].split(",")
```

#### 4. Deny IPs from an external JSON endpoint (re-evaluated every 30s)

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: deny-json
spec:
  podSelector:
    matchLabels:
      app: agent
  mode: enforce
  evaluationInterval: 30s
  variables:
  - name: blockedIpsObj
    expression: >-
      json.unmarshal(http.get("blockips.com"))
  behaviors:
  - network:
      deny:
        expression: >-
          variables.blockedIpsObj["ips"]
```

---

## Phase 1

### Features

- Fully functioning implementation of the proposed API (see [Proposed API](#proposed-api))
  - All three behavior types: `network`, `exec`, `open`
  - Hardcoded array rules and CEL expression rules
  - `mode: enforce` and `mode: monitor`
- In `monitor` mode, violations are surfaced as **policy reports** (mechanism TBD — see [Open Questions](#open-questions))

### Acceptance Criteria

- A `RuntimePolicy` with any combination of hardcoded and expression-based rules can be created and is enforced against matching pods
- In `enforce` mode, violating events are blocked
- In `monitor` mode, violating events are allowed but recorded; a policy report is produced and observable by the user

## Phase 2

### Features

- **Hostname/FQDN banning** — the ability to ban hostnames (FQDNs) and all IP addresses they resolve to, enforced at the network behavior level
- **Pod identity enforcement** — the ability to ban or restrict a pod based on its identity (e.g. service account, labels) rather than just its selector match at policy creation time

### Acceptance Criteria

- A policy can specify blocked hostnames (FQDNs); all IPs returned by DNS resolution for those hostnames are denied
- Pod identity (service account, labels) can be used as a dimension in policy evaluation or as a target for restrictions
- Hostname bans work in both `enforce` and `monitor` modes

## Open Questions

- **Hostname resolution and pod identity mechanics** — The mechanism for how hostname banning and pod identity enforcement will work is undecided. Open questions include: how DNS resolution will be handled (inline resolution, caching strategy, handling dynamic IPs), how hostname lists can be managed (hardcoded, external source, expression-based), and how pod identity is resolved and matched at enforcement time.
- **Policy reporting** — How will violations in `monitor` mode be reported? Options include a `PolicyReport` CRD (Kubernetes Policy WG standard), events on the pod, a custom status subresource on the `RuntimePolicy`, or an external sink. The reporting mechanism and its configuration surface (e.g. per-policy, global operator config) are still to be decided.
