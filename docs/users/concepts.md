# Concepts

Nirmata Runtime extends Kyverno policy-as-code from admission into runtime. A
`kyverno-runtime daemon` runs as a DaemonSet on every node; each instance watches the
pods on its own node and the cluster-scoped `RuntimePolicy` objects, and attaches eBPF
programs to the pods a policy's `podSelector` matches. Three behavior kinds can be
enforced or observed: file `open`, process `exec`, and network egress. A fourth, `dns`,
is observed only.

## How enforcement works

Network egress is enforced by a `cgroup_skb` eBPF program attached to the matched pod's
cgroup: on every outbound packet it looks up the destination IPv4 address in an
allow/deny map programmed for that pod and drops the packet if the lookup says to.

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
`values`). A `network` value may be an address, a CIDR, or a name; a name in the form
`<service>.<namespace>.svc.cluster.local` is an in-cluster Service, which the daemon
resolves to its ClusterIP and ready endpoint addresses from Service and EndpointSlice
informers; prefixing one more label,
`<hostname>.<service>.<namespace>.svc.cluster.local`, names a single endpoint of it. Any
other fully qualified domain name is external. Setting
`deny.values: ["*"]` on a behavior is a default-deny
sentinel: that behavior flips from allow-all-except-denied to deny-all-except-allowed. This is
evaluated across every `RuntimePolicy` matching a pod: if any matching policy sets
default-deny for a behavior, the effective allow list is the union of every matching
policy's `allow` entries; otherwise the effective deny list is the union of every
matching policy's `deny` entries.

For `network`, this union is enforced exactly as described: one egress filter per pod
aggregates every matching policy. For `open` and `exec`, each policy attaches its own
LSM program, so multiple enforcing policies on the same pod compose as an intersection
of what each program allows, not a union.

## Modes

| `spec.mode` | Kernel programs attached | Deny/allow maps programmed | Blocks | Emits findings |
| --- | --- | --- | --- | --- |
| `enforce` | yes | yes | yes | no |
| `monitor` | yes | **no** (maps stay empty) | no | yes |
| omitted | no | no | no | no |

A policy that omits `spec.mode` is loaded but inert: it neither enforces nor reports
anything. There is no default mode.

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

`spec.podSelector` is an optional label selector. Omitted, it matches every pod on the
node. Relabeling a running pod re-evaluates which policies match it: the daemon's pod
watcher fires on pod updates too, so a label change on a live pod picks up or drops
policy attachments without recreating the pod.

## What monitor mode sees (and does not)

- `network`, `open`, and `exec` observation is poll-based: counters are drained every
  `--observe-interval` (default 10s), so a finding can lag the behavior by up to that
  interval. A `dns` question is delivered as it happens, so only the reporter's 10-second
  flush applies to it.
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

- **Reports** — monitor-mode matches are written as OpenReports `Report` objects in the
  offending pod's namespace. See
  [reference/runtimepolicy.md#findings-and-reports](reference/runtimepolicy.md#findings-and-reports).
- **Status and conditions** — each daemon writes its own shard of `status.nodes`, plus
  conditions reporting the running mode and any policy target it could not program. See
  [reference/runtimepolicy.md#status](reference/runtimepolicy.md#status).
- **Metrics** — Prometheus counters on `--metrics-addr`. See
  [reference/metrics.md](reference/metrics.md).
