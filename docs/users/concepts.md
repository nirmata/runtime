# Concepts

Nirmata Runtime extends Kyverno policy-as-code from admission into runtime. A
`kyverno-runtime daemon` runs as a DaemonSet on every node; each instance watches the
pods on its own node and the cluster-scoped `RuntimePolicy` objects, and attaches eBPF
programs to the pods a policy's `podSelector` matches. Four behavior kinds can be
enforced or observed: file `open`, process `exec`, `network` egress, and the application
`protocol` a flow carries. A fifth, `dns`, is observed only.

## How enforcement works

Network egress is enforced by a `cgroup_skb` eBPF program attached to the matched pod's
cgroup: on every outbound packet it looks up the destination IPv4 address in an
allow/deny map programmed for that pod and drops the packet if the lookup says to.
Packets that are not IPv4 pass through it unexamined, so on a dual-stack cluster IPv6
egress is neither denied nor observed — see
[limits of network enforcement](reference/runtimepolicy.md#limits-of-network-enforcement).

Application `protocol` is enforced by a second program on the same cgroup that
classifies each flow — IPv4 and IPv6 both — from the first data segment it carries, and
drops the flow when the classification is denied. `network` and `protocol` evaluate
independently and AND together.

When a policy names an in-cluster Service by its DNS name, the daemon resolves it from
Service and EndpointSlice informers and programs the addresses it resolves to, re-resolving
on every change — see
[cluster Service targets](reference/runtimepolicy.md#cluster-service-targets).

When a policy names an external destination by domain, a second program on the same cgroup
reads the pod's own UDP/53 answers and programs the addresses they carry, so the decision
still reduces to an address lookup. It sees only unencrypted UDP resolution, which makes a
domain allow-list a convenience and not a containment boundary — see
[limits of domain names](reference/runtimepolicy.md#limits-of-domain-names).

File `open` and process `exec` are enforced by BPF-LSM programs attached to the
`file_open` and `bprm_check_security` kernel hooks. Each program looks up the path (or
binary path) in a per-cgroup map built from the policy's `allow`/`deny` lists and
returns `-EPERM` to block it, so the operation never completes. File `open` and process
`exec` enforcement require a kernel booted with BPF-LSM active: `bpf` must appear in
`/sys/kernel/security/lsm` (set with the `lsm=` kernel boot parameter). Stock
distributions and hosted CI runners are typically not booted with it.

## Allow, deny, and default deny

Each behavior in `spec.behaviors` takes an optional `allow` and/or `deny`, each a
`values` list and/or a CEL `expression` returning `list(string)` (unioned with
`values`). A `network` value may be an IPv4 address, an IPv4 CIDR of `/24` or narrower
(expanded into its individual addresses when programmed; wider prefixes are rejected),
or a name; a name in the form
`<service>.<namespace>.svc.cluster.local` is an in-cluster Service, which the daemon
resolves to its ClusterIP and ready endpoint addresses from Service and EndpointSlice
informers; prefixing one more label,
`<hostname>.<service>.<namespace>.svc.cluster.local`, names a single endpoint of it. Any
other fully qualified domain name is external. Setting
`deny.values: ["*"]` on a behavior is a default-deny
sentinel: that behavior flips from allow-all-except-denied to deny-all-except-allowed.

When several policies match one pod, how they combine differs by behavior. For
`network` and `protocol`, one egress filter per pod aggregates every matching
enforce-mode policy: the `deny` entries of all policies are programmed together, the
`allow` entries of all policies are programmed together, and a default deny set by any
one policy applies to the pod, denying whatever matches no policy's `allow` entry. An
explicit `deny` entry always denies, whichever policy carries a matching `allow`. For
`open` and `exec`, each policy attaches its own LSM program and the kernel denies when
any program denies: a path denied by any policy is denied, and a default-deny policy
blocks every path absent from its own `allow` list, whatever any other policy allows —
multiple default-deny policies compose as an intersection of their allow lists, not a
union. See
[multiple policies on one pod](reference/runtimepolicy.md#multiple-policies-on-one-pod).

## Modes

| `spec.mode` | Kernel programs attached | Deny/allow maps programmed | Blocks | Emits findings |
| --- | --- | --- | --- | --- |
| `enforce` | yes | yes | yes | denials only |
| `monitor` | yes | **no** (maps stay empty) | no | yes |
| omitted | no | no | no | no |

A policy that omits `spec.mode` is loaded but inert: it neither enforces nor reports
anything. There is no default mode.

The two kinds of finding answer different questions. An `enforce` finding is the record that
the kernel blocked an operation, so there is one per denial and none for anything permitted.
A `monitor` finding is a counterfactual — an enforcing form of this policy would have blocked
this — which under `deny.values: ["*"]` is every occurrence, and is why a `monitorFilter`
exists for monitor policies and is refused on enforcing ones.

## What DNS reporting tells you

A `dns` behavior declares the names a workload is expected to resolve, and reports the
questions it asks that the declaration does not cover. Its allow list is inverted relative
to the other behaviors: `dns.allow` is the expected set, so a name matching none of its
entries is reported without any `deny` entry, and `deny.values: ["*"]` asks for every name —
the inventory an operator reads before there is an expected set to write.

It reports and does not block. Blocking a destination named by domain is a `network`
behavior, which programs the addresses the daemon learns from the pod's own answers for
that name; a policy pairing a `dns` behavior with `mode: enforce` fails to compile and the
error points there. The two are complementary: a `network` behavior decides about
destinations a policy already named, and only the question observation supplies a name no
policy named, because a connection to an address that was never associated with a
policy-named domain carries no name.

What `dns` tells you is intent, not traffic. A resolution is not a connection: the workload
asked for a name and may never have dialled the answer, an answer already cached or shared
produces no question at all, and a workload that dials a bare address asks nothing. Use it
to learn which providers and endpoints a workload reaches for, and a `network` behavior in
`enforce` mode to constrain where it actually goes. The full list is in
[limits of DNS reporting](reference/runtimepolicy.md#limits-of-dns-reporting).

## Scoping with podSelector

`spec.podSelector` is an optional label selector over pod labels, and `spec.namespaceSelector`
is one over namespace labels. They are ANDed, and on both an empty selector and an omitted
field mean every pod and every namespace — so a policy that sets neither applies everywhere
the agent runs.

That is the right default for `monitor` mode, where the point is to learn what a cluster
does. For `enforce` mode the API server refuses a policy that sets neither: write
`podSelector: {}` to enforce on every pod on the node, so the blast radius is visible in the
policy rather than inferred from a field that isn't there.

Relabeling a running pod re-evaluates which policies match it: the daemon's pod
watcher fires on pod updates too, so a label change on a live pod picks up or drops
policy attachments without recreating the pod.

## What monitor mode sees (and does not)

- `network`, `protocol`, `open`, and `exec` observation is poll-based: counters are
  drained every `--observe-interval` (default 10s), so a finding can lag the behavior by
  up to that interval. A `dns` question is delivered as it happens, so only the
  reporter's 10-second flush applies to it.
- Only counts are kept per poll window, not the ordering or timing of individual
  occurrences.
- Network observation is IPv4 only, with no ports, protocols, or TLS/HTTP visibility. A
  destination is reported by address, plus the domain it was answered for when the DNS
  snooper learned it from a name some policy already names.
- `dns` observation reads the question name out of UDP/53 queries and nothing else: no
  answers, no query types, no DNS over TLS, HTTPS, or TCP.
- The per-cgroup open/exec path counter caps at 2048 distinct `(path, decision)` keys
  per poll interval; a workload touching more than that loses the excess.
- Observations that cannot be attributed to a pod are dropped and counted in
  `attribution_misses_total`; host- and node-level activity is never attributed.

See [reference/runtimepolicy.md#limits-of-monitor-mode](reference/runtimepolicy.md#limits-of-monitor-mode)
for the authoritative list.

## Outputs

- **Reports** — findings, both monitor-mode matches and enforce-mode denials, are
  written as OpenReports `Report` objects in the
  offending pod's namespace. See
  [reference/runtimepolicy.md#findings-and-reports](reference/runtimepolicy.md#findings-and-reports).
- **Status and conditions** — each daemon writes its own shard of `status.nodes`, plus
  conditions reporting the running mode and any policy target it could not program. See
  [reference/runtimepolicy.md#status](reference/runtimepolicy.md#status).
- **Metrics** — Prometheus counters on `--metrics-addr`. See
  [reference/metrics.md](reference/metrics.md).

## Known gaps

Two boundaries worth reading twice before relying on enforcement:

- A default-deny `open` or `exec` policy cannot be relaxed by another policy's `allow`
  list: each policy's LSM program decides from its own maps, so the pod's effective
  allowed set is the intersection of every default-denying policy's allow list. See
  [multiple policies on one pod](reference/runtimepolicy.md#multiple-policies-on-one-pod).
- The egress filter reads IPv4 packets only, so on a dual-stack cluster a default-deny
  `network` behavior neither blocks nor observes IPv6 connections. See
  [limits of network enforcement](reference/runtimepolicy.md#limits-of-network-enforcement).
