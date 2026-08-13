# Security Policy

Nirmata Runtime runs as a privileged, root DaemonSet with `CAP_BPF` and related
capabilities on every node it is installed on, and it makes kernel-level
allow/deny decisions for the workloads it enforces. A bug here can mean a
workload bypasses enforcement it should be subject to, or that the daemon's
own privilege becomes an attacker's foothold. Treat anything in that category
as a vulnerability, not a bug report.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting: open this
repository's **Security** tab and select **Report a vulnerability**. This
creates a private advisory that only maintainers can see, and lets us
collaborate with you on a fix before anything is public.

If you cannot use that flow, email **<security@nirmata.com>**.

Include what you'd include in any good bug report, plus:

- The `RuntimePolicy` (or lack of one) and `spec.mode` involved
- The kernel version, `cat /sys/kernel/security/lsm` output, and node image
  (EKS, GKE, AKS, kind, bare metal, ...)
- Whether the behavior is a bypass of `enforce` mode, a data leak between
  pods, a crash, or something else
- Reproduction steps, or a policy/manifest that reproduces it

Do not open a public issue for a suspected vulnerability, and do not include
exploit details in a public pull request.

### Response targets

*Maintainers: confirm or adjust these numbers before launch.*

| Stage | Target |
| --- | --- |
| Acknowledgment | 3 business days |
| Initial assessment (severity, affected versions) | 10 business days |
| Fix or mitigation for a confirmed critical/high finding | 30 days, or an agreed interim mitigation communicated to the reporter |

We will keep you updated as we work on a fix and credit you in the advisory
unless you ask not to be named.

## Supported versions

Nirmata Runtime is pre-1.0. The `RuntimePolicy` API is `v1alpha1`, and only
the latest minor release receives fixes, security or otherwise. There is no
backport policy across minor versions yet.

| Version | Supported |
| --- | --- |
| Latest `v0.x` minor | yes |
| Any older minor | no |

## What counts as a vulnerability here

This project's job is enforcing behavior in the kernel and reporting on it
faithfully. A vulnerability report matters most when it breaks one of those
two guarantees. Examples, not an exhaustive list:

- A workload selected by an `enforce`-mode policy performs the `open`,
  `exec`, `network`, or `protocol` behavior the policy denies, and the
  operation is not blocked.
- Data from one pod's eBPF ring buffer event (argv, a DNS question, a path)
  appears attributed to a different pod, or an unzeroed kernel record leaks
  a previous event's bytes into a new one. See "Zero what the kernel hands
  to userspace" in [CLAUDE.md](CLAUDE.md) for the convention this would
  violate.
- A malformed `RuntimePolicy` crashes the daemon, or produces a program the
  kernel verifier should have rejected but didn't (an out-of-bounds map
  access, for example).
- A path to privilege escalation from the DaemonSet's mounts (`/host` at the
  node root, `/sys/fs/bpf`, `/sys/kernel/debug`, `/sys/kernel/tracing`) or
  its capabilities, beyond what running any privileged, root, `CAP_BPF`
  workload already implies.
- A `network` target that is programmed into the kernel maps but rejected at
  admission, or accepted at admission but never programmed — the two layers
  disagreeing about what a policy allows.

## What is not a vulnerability

These are documented design boundaries, not bugs. Please read them before
filing:

- **No TLS inspection.** Nothing here reads inside a TLS, QUIC, or SSH
  session — model names, prompts, HTTP paths, and JSON-RPC methods are all
  out of scope by design. See [Detecting shadow AI](docs/users/shadow-ai.md)
  and [Limits of protocol classification](docs/users/reference/runtimepolicy.md#limits-of-protocol-classification).
- **DNS over HTTPS/TLS is invisible.** Only cleartext UDP/53 questions are
  observed; a resolver using DoH or DoT produces no `dns` finding. See
  [Limits of domain names](docs/users/reference/runtimepolicy.md#limits-of-domain-names)
  and [Limits of DNS reporting](docs/users/reference/runtimepolicy.md#limits-of-dns-reporting).
- **Domain-to-address mappings expire by LRU eviction, not TTL.** A learned
  address can stay allowed well past the record's TTL on a quiet pod. See
  the same [Limits of domain names](docs/users/reference/runtimepolicy.md#limits-of-domain-names)
  section.
- **Egress is IPv4-only.** IPv6 destinations are neither enforced nor
  observed; this is a stated limitation, not a filter bypass.
- **`open` and `exec` enforcement require a BPF-LSM kernel.** A node not
  booted with `bpf` in `/sys/kernel/security/lsm` cannot enforce those two
  behaviors, and a policy still reports `Applied=True` on such a node — a
  known, tracked gap in that condition, not a silent bypass. See
  [Platforms](docs/users/platforms.md) and
  [Troubleshooting](docs/users/troubleshooting.md).
- **Observation is poll-based and can lag.** `network`, `open`, `exec`, and
  `protocol` findings are drained on `--observe-interval` (default 10s) and
  can lag the underlying behavior; this is documented latency, not a missed
  detection. See [Limits of monitor mode](docs/users/reference/runtimepolicy.md#limits-of-monitor-mode).

If you're not sure whether something you found is a documented limit or a
real vulnerability, report it privately anyway and we'll sort it out
together — that costs us little and costs you nothing.

## Repository configuration this policy depends on

*For maintainers:* private vulnerability reporting must be turned on in this
repository's settings (Settings > Code security and analysis > Private
vulnerability reporting) for the primary channel above to work. This has not
been verified as enabled as of this writing.
