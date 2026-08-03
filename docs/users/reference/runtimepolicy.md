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
| `spec.behaviors` | list | One entry per behavior kind; each entry configures exactly one of `network`, `exec`, `open`. Each `allow`/`deny` rule takes `values` and `expression`. |

Each entry in `spec.behaviors` configures exactly one of `network`, `exec`, or `open`.
Each of those takes an `allow` and/or a `deny` rule, and each rule accepts a literal
`values` list, a CEL `expression` that evaluates to `list(string)`, or both (the results
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

- `network`: IPv4 addresses, IPv4 CIDRs, cluster Service DNS names, and fully qualified
  domain names for egress.
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
- A `network` value that is a name is resolved by one of two mechanisms, chosen by the
  shape of the name alone: a cluster Service DNS name resolves from API server informers
  (see [Cluster Service targets](#cluster-service-targets)), any other fully qualified
  domain name is learned from the pod's own DNS answers (see
  [Domain name targets](#domain-name-targets)).
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

## Cluster Service targets

An allow list of literal ClusterIPs works only as long as they hold. A Service that is
redeployed, or whose backends move, changes addresses and the policy has no way to know.
Naming the Service by its
[cluster DNS name](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#services)
instead lets the daemon resolve it from Service and EndpointSlice informers.

A `network` value in the form `<service>.<namespace>.svc.<cluster-domain>` is a Service
name and resolves that way. Any other fully qualified domain name is an external name,
learned from the pod's own DNS answers by the snooper. The two are chosen by shape, and
they are not equivalent: informer resolution is authoritative and watch-driven, whereas
DNS snooping is best-effort and [not a containment boundary](#limits-of-domain-names).

This is a deny-all-then-allowlist egress policy: the workload may reach cluster DNS and an
egress gateway, and nothing else. The `kubernetes` Service is deliberately absent, so the
API server is unreachable from these pods:

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
        values:
        - kube-dns.kube-system.svc.cluster.local
        - egress-gateway.networking.svc.cluster.local
```

What a Service name resolves to:

- the Service's ClusterIP, when it has one, plus the addresses of its **ready**
  endpoints. A headless Service therefore resolves to its endpoints alone; a Service
  scaled to zero resolves to its ClusterIP alone.
- IPv4 only. IPv6 endpoint addresses are skipped, as everywhere else in `network`.
- re-resolved whenever the Service or one of its EndpointSlices changes, so scaling,
  rolling, or replacing the backends updates the programmed addresses without touching
  the policy. No `evaluationInterval` is needed for this; the informers drive it.

A Service name is one value among others on the same rule, so a policy can mix it with
addresses that have no Service in front of them:

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
        - kube-dns.kube-system.svc.cluster.local
```

### Always write a Service name in full

**A short form matches nothing, and says nothing.** `redis.default` is accepted as an
external name, because it is shaped exactly like `example.com` — two labels — and no
syntactic rule can tell them apart without rejecting every two-label external domain along
with it. It then never matches anything: a pod's resolver expands an unqualified name
through its `resolv.conf` search domains before it asks, so the question the snooper
observes is `redis.default.svc.cluster.local`, never the `redis.default` the policy names.
The value looks valid, no condition reports it, and the destination is simply never
allowed. Write `redis.default.svc.cluster.local`.

### Accepted names

The cluster domain is the daemon's `--cluster-domain`, `cluster.local` unless it is set
otherwise.

| Value | Result |
| --- | --- |
| `kube-dns.kube-system.svc.cluster.local` | Service `kube-dns` in `kube-system`, resolved from informers |
| `api.payments.example.com` | external name, learned from the pod's DNS answers |
| `redis.default` | external name — resolves nothing, see above |
| `redis` | rejected: a single label is not a usable name |
| `10-1-2-3.default.pod.cluster.local` | rejected: pod record, not a Service |
| `web-0.web.default.svc.cluster.local` | rejected: headless per-pod record, not a Service |
| `kube-dns.kube-system.svc.example.com` | rejected, naming the expected cluster domain |
| `1redis.default.svc.cluster.local` | rejected: a service label must start with a letter |

A name that ends in the cluster domain but is not a Service name — a pod record, a
headless Service's per-pod record, a short form written with the cluster domain — is
rejected rather than treated as external, because falling through would hand the operator
the weaker of the two mechanisms for a destination that is plainly in-cluster. A name
whose third label is `svc` is held to the same rule even when its suffix is some other
domain, on the grounds that it is far more likely a mistyped cluster name than a real
host. The collateral is real: an external destination genuinely named
`api.prod.svc.mycompany.com` cannot be used as a target, and has to be reached by address.

The two labels have different rules, following Kubernetes' own: a service label is RFC
1035, so it must start with a letter, while a namespace label is RFC 1123 and may start
with a digit. Both are at most 63 characters of lowercase alphanumerics and `-`.

A rejected literal fails the whole policy to compile, reported as `Applied=False` with
reason `CompileFailed` and a message naming the field path, the value and the reason.
Nothing in that policy is applied while it is rejected, including the rules either side of
the offending value. A value produced by an `expression` is not seen until evaluation, so
the same mistake there is reported per value through `TargetsValid=False` and leaves the
rest of the policy in force.

## Limits of cluster Service targets

A Service name is resolved from watched cluster state, which bounds what it can express.
These are real, current limits:

- **In-cluster Services only.** A Service name is looked up in the Service and
  EndpointSlice informers, never in DNS, so it cannot name anything outside the cluster.
  For an external destination, name it as a domain instead — a different mechanism with
  [different limits](#limits-of-domain-names).
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
- **An unresolved name programs nothing.** A name whose Service does not exist (a typo, a
  namespace that was never created, a Service deleted after the policy was written)
  contributes no addresses. Under default-deny that means the destination is
  fully blocked rather than quietly allowed, which is the safe direction but looks
  identical to a network outage from inside the workload. It is surfaced as a
  `TargetsValid=False` condition with reason `UnresolvedServices` — check the status before
  concluding the cluster is broken:

  ```bash
  kubectl get rpol egress-via-gateway-only -o jsonpath='{.status.conditions}'
  ```

## Domain name targets

A `network` value that is a fully qualified domain name outside the cluster domain names an
external destination, and nothing about it is resolved when the policy is written: the
daemon attaches a second eBPF program to the matched pod's cgroup that reads the pod's own
DNS answers, and an A record for a name the policy mentions makes that address allowed (or
denied) for that pod. The pod learns the address the same moment the kernel does.

The resolver has to stay reachable for any of this to happen, which is why cluster DNS is
allowed alongside the name — under default-deny a workload that cannot reach its resolver
resolves nothing, and every domain in the allow list is dead:

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
        - kube-dns.kube-system.svc.cluster.local
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
  as [cluster Service names](#cluster-service-targets).
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
| `Applied` | `Enforcing`, `Monitoring`, `NoMode`, `CompileFailed` | Whether the daemon has the policy loaded, and in which mode. `NoMode` reports `False` for a policy that omits `spec.mode`, which is neither enforced nor reported. `CompileFailed` reports `False` when the spec could not be compiled, with the offending field path and value in the message; nothing in such a policy is applied, including the rules either side of the bad one. |
| `TargetsValid` | `AllTargetsSupported`, `NoTargets`, `UnsupportedTargets`, `UnresolvedServices` | Whether every `network` target could be programmed. `UnsupportedTargets` lists the rejected values and why; `UnresolvedServices` lists the Service names that are not in cache. |
| `ObservationAvailable` | `ObservationUnavailable` | Set to `False` when a loaded LSM program has no observation maps, so a monitor-mode policy would silently produce no findings. |

A target the runtime cannot program is never silently skipped. Which condition carries it
depends on where the value came from: a literal is checked when the policy compiles and a
bad one reports `Applied=False` with `CompileFailed`, while a value an `expression` produced
is checked when it is programmed and reports `TargetsValid=False`. Either way it also
reaches an operator-visible log line.

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
- **Unsupported `network` targets are rejected, not skipped.** A CIDR wider than `/24`, a
  name whose wire encoding exceeds 128 bytes, and a pod's 257th distinct domain are all
  accepted by the grammar and refused when programmed, so they are reported per value
  through `TargetsValid=False`. A CIDR of `/24` or narrower is expanded into individual
  addresses. An IPv6 literal is refused earlier, by the grammar, so as a literal value it
  fails the policy to compile instead.
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
| [egress-to-cluster-service](../../../examples/egress-to-cluster-service/) | Cluster Service DNS names in `allow.values` under default deny, with the API server denied by omission | `enforce` | cgroup v2 |
| [egress-to-domain-name](../../../examples/egress-to-domain-name/) | An external domain name in `allow.values`, alongside cluster DNS named as a Service | `enforce` | cgroup v2 |
| [monitor-egress](../../../examples/monitor-egress/) | Same policy shape observed instead of blocked | `monitor` | cgroup v2 |
| [deny-sensitive-file-access](../../../examples/deny-sensitive-file-access/) | `open` deny with `values` unioned with a `variables` expression | `enforce` | BPF-LSM |
| [restrict-exec-allowlist](../../../examples/restrict-exec-allowlist/) | Default-deny `exec` with an allow-list | `enforce` | BPF-LSM |
| [monitor-workload-baseline](../../../examples/monitor-workload-baseline/) | `network`, `exec`, and `open` observed together | `monitor` | BPF-LSM for `open`/`exec`; egress findings alone need only cgroup v2 |
| [blocklist-from-configmap](../../../examples/blocklist-from-configmap/) | `resource.get` with `evaluationInterval` | `enforce` | cgroup v2 |
| [blocklist-from-http](../../../examples/blocklist-from-http/) | `http.get` with the `dyn` coercion | `enforce` | cgroup v2 |
| [blocklist-from-json](../../../examples/blocklist-from-json/) | `json.unmarshal` composed with `resource.get` | `monitor` | cgroup v2 |
| [enforce-workload-baseline](../../../examples/enforce-workload-baseline/) | All three behaviors under default-deny with `evaluationInterval` | `enforce` | BPF-LSM |

The full catalog, grouped by feature, is in [Examples](../examples.md).
