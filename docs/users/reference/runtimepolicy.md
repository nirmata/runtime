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
| `spec.behaviors` | list | One entry per behavior kind; each entry configures exactly one of `network`, `exec`, `open`. Each `allow`/`deny` rule takes `values`, `expression`, and — on `network` only — `serviceRefs`. |

Each entry in `spec.behaviors` configures exactly one of `network`, `exec`, or `open`.
Each of those takes an `allow` and/or a `deny` rule, and each rule accepts a literal
`values` list, a CEL `expression` that evaluates to `list(string)`, a `serviceRefs` list
of in-cluster Services (`network` only), or any combination of them (the results are
unioned):

```yaml
spec:
  behaviors:
  - network:            # exactly one of network | exec | open per list item
      allow:
        values: [...]        # literal list of allowed items
        expression: "..."    # CEL expression returning list(string), unioned with values
        serviceRefs: [...]   # network only: Services resolved to addresses, unioned too
      deny:
        values: [...]
        expression: "..."
```

- `network`: IPv4 addresses and fully qualified domain names for egress.
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
- `serviceRefs` names in-cluster Services by `name` and `namespace`, on a `network`
  behavior's `allow` or `deny` rule. `RuntimePolicy` is cluster scoped, so `namespace` is
  required rather than implied. The API rejects `serviceRefs` on an `exec` or `open`
  behavior. See [Service references](#service-references).
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

## Service references

An allow list of literal ClusterIPs works only as long as they hold. A Service that is
redeployed, or whose backends move, changes addresses and the policy has no way to know.
`serviceRefs` names the Service instead, and the daemon resolves it from Service and
EndpointSlice informers.

This is a deny-all-then-allowlist egress policy expressed as references: the workload may
reach cluster DNS and an egress gateway, and nothing else. The `kubernetes` Service is
deliberately absent, so the API server is unreachable from these pods:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: egress-via-gateway-only
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: payments
  behaviors:
  - network:
      deny:
        values:
        - "*"
      allow:
        serviceRefs:
        - name: kube-dns
          namespace: kube-system
        - name: egress-gateway
          namespace: networking
```

What a reference resolves to:

- the Service's ClusterIP, when it has one, plus the addresses of its **ready**
  endpoints. A headless Service therefore resolves to its endpoints alone; a Service
  scaled to zero resolves to its ClusterIP alone.
- IPv4 only. IPv6 endpoint addresses are skipped, as everywhere else in `network`.
- re-resolved whenever the Service or one of its EndpointSlices changes, so scaling,
  rolling, or replacing the backends updates the programmed addresses without touching
  the policy. No `evaluationInterval` is needed for this; the informers drive it.

`serviceRefs` unions with `values` and `expression` on the same rule, so a policy can mix
references with addresses that have no Service in front of them:

```yaml
spec:
  behaviors:
  - network:
      deny:
        values:
        - "*"
      allow:
        values:
        - "192.0.2.10"     # an appliance outside the cluster
        serviceRefs:
        - name: kube-dns
          namespace: kube-system
```

## Limits of serviceRefs

A reference is resolved from watched cluster state, which bounds what it can express.
These are real, current limits:

- **In-cluster Services only.** A `serviceRefs` entry is looked up in the Service and
  EndpointSlice informers, so it cannot name anything outside the cluster. For an
  external destination, name it as a domain in `values` instead — a different mechanism
  with [different limits](#limits-of-domain-names).
- **No port or protocol granularity.** Allowing a Service allows *every* port on the
  addresses it resolves to, because the egress maps are keyed on a `u32` IPv4 address
  and nothing else. Naming a Service that exposes port 443 does not restrict the
  workload to port 443 on that address.
- **Both the ClusterIP and the endpoint addresses are programmed, and both are needed.**
  Which one the kernel actually matches depends on the client's network namespace: an
  ordinary pod's traffic is DNATed in the host namespace, after the egress hook has run in
  the pod namespace, so the hook matches the ClusterIP; a `hostNetwork` pod is DNATed in
  its own namespace before the hook, so the hook matches the backend address. A cluster
  using a socket-level load balancer instead of kube-proxy translates before the hook for
  every client, in which case only the endpoint addresses match.
- **Endpoint addresses are pod IPs, and they are programmed individually.** A matched pod
  can therefore reach those pod IPs directly, not only through the Service's ClusterIP.
  The grant is wider than "may talk to this Service": it is "may talk to this Service's
  addresses", and if another Service happens to share a backend pod, that pod is
  reachable through it too.
- **An unresolved reference programs nothing.** A reference to a Service that does not
  exist (a typo, a namespace that was never created, a Service deleted after the policy
  was written) contributes no addresses. Under default-deny that means the destination is
  fully blocked rather than quietly allowed, which is the safe direction but looks
  identical to a network outage from inside the workload. It is surfaced as a
  `TargetsValid=False` condition on the policy — check the status before concluding the
  cluster is broken:

  ```bash
  kubectl get rpol egress-via-gateway-only -o jsonpath='{.status.conditions}'
  ```

## Domain name targets

A `network` value may be a fully qualified domain name instead of an address. Unlike
`serviceRefs`, nothing about the name is resolved when the policy is written: the daemon
attaches a second eBPF program to the matched pod's cgroup that reads the pod's own DNS
answers, and an A record for a name the policy mentions makes that address allowed (or
denied) for that pod. The pod learns the address the same moment the kernel does.

The resolver has to stay reachable for any of this to happen, which is why cluster DNS is
allowed by reference alongside the name — under default-deny a workload that cannot reach
its resolver resolves nothing, and every domain in the allow list is dead:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: egress-to-payments-api
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: checkout
  behaviors:
  - network:
      deny:
        values:
        - "*"
      allow:
        values:
        - api.payments.example.com
        serviceRefs:
        - name: kube-dns
          namespace: kube-system
```

A name in `deny.values` works the same way in the other direction: without a default deny,
the addresses answered for that name are blocked and everything else is allowed.

## Limits of domain names

A domain allow-list is a convenience for naming destinations whose addresses change. It is
**not a containment boundary**, and it must not be relied on as one. These are real,
current limits:

- **Only unencrypted UDP/53 answers are seen.** The snooper parses UDP source port 53. A
  resolver reached over TCP/53, DNS over TLS, or DNS over HTTPS is invisible to it, and so
  is a client that skips resolution entirely and connects to a hardcoded address. In each
  of those cases the address is never attributed to a domain: under default-deny the
  connection is blocked (a false outage), and under a deny list it is allowed (a real
  bypass). A workload that must be contained needs its destinations named as addresses or
  `serviceRefs`.
- **No wildcards.** Every name is matched whole, against the question the pod actually
  asked. A CNAME chain is attributed to the question, not to the owner name of the A
  record, so naming the alias is correct and naming its target is not. `*.example.com`
  fails the whole policy to compile — the daemon logs the offending field path and
  enforces nothing from that policy, not even the values around it.
- **Expiry is eviction, not TTL.** Learned addresses live in a 4096-entry LRU map per pod
  and are dropped when it fills, not when the record expires. An address that has rotated
  away from a name stays allowed until something evicts it, which can be well past its
  TTL — and, on a quiet pod, indefinitely.
- **An address shared by two domains is ambiguous.** The last answer to name it wins, so
  one shared front end named by two policies is attributed to whichever name was resolved
  most recently. The attribution is at least visible: monitor-mode network observations
  carry the domain the address was learned under.
- **Bounded per pod: 256 names, 4096 addresses.** A pod whose policies name more than 256
  distinct domains rejects the excess with `TargetsValid=False`. A name that resolves to
  more addresses than the map holds loses the oldest of them to eviction. A name is also
  rejected if its DNS wire encoding exceeds 128 bytes.
- **IPv4 only, on both sides.** Only A records are read, and only from answers carried
  over IPv4, matching the IPv4-only egress maps.

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
| `TargetsValid` | `AllTargetsSupported`, `NoTargets`, `UnsupportedTargets`, `UnresolvedServiceRefs` | Whether every `network` target could be programmed. `UnsupportedTargets` lists the rejected values and why; `UnresolvedServiceRefs` lists the `serviceRefs` entries naming a Service that is not in cache. |
| `ObservationAvailable` | `ObservationUnavailable` | Set to `False` when a loaded LSM program has no observation maps, so a monitor-mode policy would silently produce no findings. |

A target the runtime cannot program is never silently skipped: it always reaches both an
operator-visible log line and a `TargetsValid=False` condition.

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
kernel programs, and it does not observe TLS SNI or HTTP. These are real, current limits,
not rounding errors:

- **Observation is poll-based, not streamed.** There is no ring buffer; counters are drained
  every 10 seconds, so a finding can lag the behavior by up to that interval, and only counts
  are preserved — not the ordering or timing of individual occurrences within a window.
- **Open/exec path counters cap per cgroup.** The per-cgroup path map holds 2048 distinct
  `(path, decision)` keys; a workload touching more than that within one poll interval loses
  the excess. The read-and-reset drain mitigates this but does not eliminate it.
- **Network observation is IPv4 only**, with no port or protocol, because the egress maps are
  keyed on a `u32` IPv4 address.
- **A destination is named only when the snooper learned it.** An observation carries a
  domain when the address came from a DNS answer for a name some policy already names
  (see [Limits of domain names](#limits-of-domain-names)); every other destination is
  reported by address alone.
- **Unsupported `network` targets are rejected, not skipped.** IPv6 literals, CIDRs wider than
  `/24`, and names whose wire encoding exceeds 128 bytes cannot be programmed. They are
  reported through `TargetsValid=False` with the reason per value. A CIDR of `/24` or
  narrower is expanded into individual addresses.
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
| [egress-via-service-refs](../../../examples/egress-via-service-refs/) | `allow.serviceRefs` under default deny, with the API server denied by omission | `enforce` | cgroup v2 |
| [egress-to-domain-name](../../../examples/egress-to-domain-name/) | A domain name in `allow.values`, with cluster DNS allowed by reference | `enforce` | cgroup v2 |
| [monitor-egress](../../../examples/monitor-egress/) | Same policy shape observed instead of blocked | `monitor` | cgroup v2 |
| [deny-sensitive-file-access](../../../examples/deny-sensitive-file-access/) | `open` deny with `values` unioned with a `variables` expression | `enforce` | BPF-LSM |
| [restrict-exec-allowlist](../../../examples/restrict-exec-allowlist/) | Default-deny `exec` with an allow-list | `enforce` | BPF-LSM |
| [monitor-workload-baseline](../../../examples/monitor-workload-baseline/) | `network`, `exec`, and `open` observed together | `monitor` | BPF-LSM for `open`/`exec`; egress findings alone need only cgroup v2 |
| [blocklist-from-configmap](../../../examples/blocklist-from-configmap/) | `resource.get` with `evaluationInterval` | `enforce` | cgroup v2 |
| [blocklist-from-http](../../../examples/blocklist-from-http/) | `http.get` with the `dyn` coercion | `enforce` | cgroup v2 |
| [blocklist-from-json](../../../examples/blocklist-from-json/) | `json.unmarshal` composed with `resource.get` | `monitor` | cgroup v2 |
| [enforce-workload-baseline](../../../examples/enforce-workload-baseline/) | All three behaviors under default-deny with `evaluationInterval` | `enforce` | BPF-LSM |

The full catalog, grouped by feature, is in [Examples](../examples.md).
