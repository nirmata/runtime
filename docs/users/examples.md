# Examples

Every example lives in its own directory under [`examples/`](../../examples/) with the
manifests it needs and a README that walks through what it shows, how to apply it, how to
verify the result, and how to clean up.

The manifests are the canonical form: each `RuntimePolicy` is a complete object that
decodes against the CRD and whose expressions compile against the daemon's CEL environment.
Every policy sets `spec.mode` explicitly, because a policy that omits it neither enforces
nor reports.

Each README's `## Verify` section checks both directions where it can — that the protected
thing is blocked *and* that everything else still works. A check that only looks for a
failure would also pass against a runtime that blocks everything.

## Requirements legend

**cgroup v2** — Network egress enforcement and observation require only a cgroup v2 host
and BPF support; a stock kind cluster on a Linux host qualifies.

**BPF-LSM** — File `open` and process `exec` enforcement require a kernel booted with
BPF-LSM active: `bpf` must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel
boot parameter). Stock distributions and hosted CI runners are typically not booted with
it.

If enforcement appears to do nothing, that distinction is the first thing to check — see
[troubleshooting](troubleshooting.md).

## Egress control

| Example | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [block-known-bad-egress](../../examples/block-known-bad-egress/) | Stop a pod from reaching one known-bad destination address, leaving the rest of its egress alone | enforce | cgroup v2 |
| [default-deny-egress](../../examples/default-deny-egress/) | Contain a compromised pod: block all egress except one approved service | enforce | cgroup v2 |
| [tls-only-egress](../../examples/tls-only-egress/) | Force a workload to speak only TLS, whatever port it uses | enforce | cgroup v2 |

`block-known-bad-egress` is the scenario the [quickstart](quickstart.md) walks through.

## File and process control

| Example | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [deny-sensitive-file-access](../../examples/deny-sensitive-file-access/) | Block reads of credential files (`/etc/shadow`, SSH keys) even from a shell inside the pod | enforce | BPF-LSM |
| [restrict-exec-allowlist](../../examples/restrict-exec-allowlist/) | Prevent shell or netcat execution in a hardened pod: default-deny exec with an allow-list | enforce | BPF-LSM |
| [enforce-workload-baseline](../../examples/enforce-workload-baseline/) | Lock a workload to its known-good files, binaries, and destinations | enforce | BPF-LSM |

## Monitor mode

| Example | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [monitor-egress](../../examples/monitor-egress/) | Audit where a workload actually connects before turning enforcement on | monitor | cgroup v2 |
| [monitor-workload-baseline](../../examples/monitor-workload-baseline/) | Record every file, binary, and destination a workload touches, without blocking | monitor | BPF-LSM for `open` and `exec`; `network` findings alone need only cgroup v2 |

Monitor mode reports through OpenReports `Report` objects and never blocks. What it can and
cannot see is listed in
[limits of monitor mode](reference/runtimepolicy.md#limits-of-monitor-mode).

## Dynamic lists (CEL libraries)

Allow and deny lists do not have to be literals. An `expression` can fetch them from the
cluster or from an HTTP endpoint at evaluation time, and `evaluationInterval` sets how often
that happens.

| Example | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [blocklist-from-configmap](../../examples/blocklist-from-configmap/) | The security team manages the egress blocklist in a ConfigMap, with no policy edits | enforce | cgroup v2, plus ConfigMap read for the daemon |
| [blocklist-from-http](../../examples/blocklist-from-http/) | Pull the deny list from a threat-intel HTTP feed | enforce | cgroup v2 |
| [blocklist-from-json](../../examples/blocklist-from-json/) | Parse a JSON blob from a ConfigMap into a deny list | monitor | cgroup v2, plus ConfigMap read for the daemon |

The chart's default ClusterRole grants the daemon no ConfigMap access, so the two examples
that use the `resource` library ship a `daemon.rbac.extraRules` values snippet and apply it
before the policy. See [installation](installation.md) for the values reference and
[the CEL reference](reference/cel.md) for the library signatures.
