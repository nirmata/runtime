# Concepts

Nirmata Runtime extends Kyverno policy-as-code from admission into runtime. A
`kyverno-runtime daemon` runs as a DaemonSet on every node; each instance watches the
pods on its own node and the cluster-scoped `RuntimePolicy` objects, and attaches eBPF
programs to the pods a policy's `podSelector` matches. Three behavior kinds can be
enforced or observed: file `open`, process `exec`, and network egress.

## How enforcement works

Network egress is enforced by a `cgroup_skb` eBPF program attached to the matched pod's
cgroup: on every outbound packet it looks up the destination IPv4 address in an
allow/deny map programmed for that pod and drops the packet if the lookup says to.

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
`values`). Setting `deny.values: ["*"]` on a behavior is a default-deny sentinel: that
behavior flips from allow-all-except-denied to deny-all-except-allowed. This is
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

## Scoping with podSelector

`spec.podSelector` is an optional label selector. Omitted, it matches every pod on the
node. Relabeling a running pod re-evaluates which policies match it: the daemon's pod
watcher fires on pod updates too, so a label change on a live pod picks up or drops
policy attachments without recreating the pod.

## What monitor mode sees (and does not)

- Observation is poll-based: counters are drained every `--observe-interval` (default
  10s), so a finding can lag the behavior by up to that interval.
- Only counts are kept per poll window, not the ordering or timing of individual
  occurrences.
- Network observation is IPv4 destination-address only, with no ports, protocols, DNS
  names, or TLS/HTTP visibility.
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
