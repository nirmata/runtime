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
- In `enforce` mode, violating events are blocked and potentially reported/monitored
- In `monitor` mode, violating events are reported/monitored

## Phase 2

### Features

- **Hostname/FQDN banning** — the ability to ban hostnames (FQDNs) and all IP addresses they resolve to, enforced at the network behavior level
- **Pod identity enforcement** — the ability to ban or restrict a pod based on its identity (e.g. service account, labels) rather than just its selector match at policy creation time

### Acceptance Criteria

- A policy can specify blocked hostnames (FQDNs); all IPs returned by DNS resolution for those hostnames are denied
- Pod identity (service account, labels) can be used as as a target for restrictions
- Hostname/pod-identities bans work in both `enforce` and `monitor` modes

## Open Questions

This section covers parts of the project that haven't been architected yet. For topics that have an ongoing debate/discussions refer to the [Discussions](#discussions) section. 

- **Hostname resolution and pod identity mechanics** — The mechanism for how hostname banning and pod identity enforcement will work is undecided. Open questions include: how DNS resolution will be handled (inline resolution, caching strategy, handling dynamic IPs), how hostname lists can be managed (hardcoded, external source, expression-based), and how pod identity is resolved and matched at enforcement time.
- **Policy reporting** — How will violations in `monitor` mode be reported? Options include a `Report` CRD (Openreports), logs with a particular structure, reporting mechanism and its configuration surface (e.g. per-policy, global operator config) are still to be decided.


## Discussions

### The existence of allow/deny rules

As proposed in the API, a single behavior object under the `behaviors` key in the API may have an `allow/deny` sections.


**Arguments against**

- Significant overhead will be introduced both on the user and inside the project code.

**Arguments in favor**

- If we assume that the engine supports `deny` rules only, then in the scenario where a user wants to only allow certain endpoints the engine becomes unfeasible, vise versa if we assume there's a default deny and rules are allow rules. So having allow/deny means a more flexible user experience.
- In the context of learning mode, you are learning what the workload calls which means you are implicitly learning a group of `allow` rules. If you say you want deny anything apart from those then the initial assumption of the project (default allow and deny rules) is violated. If it's decided that learning mode is a special case, then this means the project becomes trickier to learn and easier to shoot yourself in the foot with due to an unintuitive implicit rule. It seems more favorable to expose a complex interface but with less surprises to the user.
- Complexity is an unavoidable consequence of rule enforcement engines, taking cloud IAM as an example. Which chooses correctness over simplicity.

## The `object` CEL variable

The object variable is currently not supported in the runtime policy because by habit, this object refers to the kubernetes object involved during an admission call or a background scan. In the context of kyverno-runtime, the event is a kernel level event. Userspace concepts such as a pod, an object and all those things don't apply, the event is just a pid sending a packet or opening a file. Even if you built a representation of it, its rather inefficient to consult user space for permission on a kernel event especially for networking.


**Arguments against**

- Significant overhead will be introduced inside the project code (evaluations will differ per pod).

**Arguments in favor**

- It's a feature that has an expected high favorability from the user community becaause having it would mean data in the pod spec can control what rules apply to the pod. The current structure just does one evaluation and applies it to all pods.

### Re-evaluation on an interval

The policy's `evaluationInterval` field which controls how often the CEL expressions in the policy are evaluated. The alternative is having a `configMapRef` field which points to a CM that contains rules. Evaluation happens on CRUD events for that configmap.


**Arguments against**

- Significant overhead will be introduced inside the project code.

**Arguments in favor**

- It hurts other CEL libraries. If say, you have a variable that is the result of a HTTP call, then evaluating the value of that variable becomes contingent on a configmap event happening which is a poor user experience.
- If the object variable gets adopted (by for example, saving pod specs and calling eval on them) then config map references may become non-static and relying on data in the pod spec.

A decision can be made to only support CEL expressions that can only use the resource library and the resulting resource must be a configmap, e.g: `resource.get("v1", "configmaps", object.namespace, object.metadata.labels["rule-cm"])` but that would be restrictive, and if decided and later reverted due to the need to support other libraries it would have been a futile decision.


### A second CR for configuring learning mode

**Arguments in favor**

Not having it leads to problems in configurability and rule lifecycle management

- If learning mode is configured on the runtime behavior, this ties the lifetime of the learned ruleset to the lifetime of the runtime behavior. Its expected that there will be users who wanna learn the behavior of some workload and apply it to multiple other workloads, or have a reference of those rules in the cluster so they apply it to the workload across restarts or a change in the workload identity (labels) without having to relearn the behavior every time because its more expensive both time and compute wise.
- The proposed structure of the runtime behavior and policy API already achieve the same thing (selecting workloads and applying rules on them). The runtime behavior offers nothing extra apart from learning mode. This means that there's already a second CR except with redundant functionality. The proposal so have a resource just for learning mode means elimination of functionality duplication and a more straightforward user experience. (avoiding questions like "when do i use a policy versus a runtime behavior?").

