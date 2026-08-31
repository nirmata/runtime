# Examples

Every example lives in its own directory under [`examples/`](../../examples/) with the
manifests it needs and a README that walks through what it shows, how to apply it, how to
verify the result, and how to clean up.

The directories are grouped five ways, and the sections below are those groups: each heading
is a folder under `examples/`, so a scenario found here is found at the same place on disk.

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

[`examples/egress/`](../../examples/egress/) — deciding which destinations a workload may
reach, and over which protocols.

| Example | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [block-known-bad-egress](../../examples/egress/block-known-bad-egress/) | Stop a pod from reaching one known-bad destination address, leaving the rest of its egress alone | enforce | cgroup v2 |
| [default-deny-egress](../../examples/egress/default-deny-egress/) | Contain a compromised pod: block all egress except one approved service | enforce | cgroup v2 |
| [egress-to-cluster-service](../../examples/egress/egress-to-cluster-service/) | Name the approved destinations by their cluster Service DNS names instead of addresses, leaving the API server unreachable by omission | enforce | cgroup v2 |
| [egress-to-domain-name](../../examples/egress/egress-to-domain-name/) | Allow an external fully qualified domain name, enforced from the pod's own DNS answers | enforce | cgroup v2 |
| [tls-only-egress](../../examples/egress/tls-only-egress/) | Force a workload to speak only TLS, whatever port it uses | enforce | cgroup v2 |
| [protocol-default-deny](../../examples/egress/protocol-default-deny/) | The same default deny, with the allowed and denied protocols exercised on one port | enforce | cgroup v2 |
| [egress-baseline-combined](../../examples/egress/egress-baseline-combined/) | Every network-side field in one annotated policy, with the accepted values for each | enforce | cgroup v2 |
| [overlapping-egress-policies](../../examples/egress/overlapping-egress-policies/) | Two policies over one pod, and a pod that starts after them | enforce | cgroup v2 |

`block-known-bad-egress` is the scenario the [quickstart](quickstart.md) walks through.

A value in the form `<service>.<namespace>.svc.cluster.local` is resolved from Service and
EndpointSlice informers; any other fully qualified domain name is learned from the pod's DNS
answers. The two mechanisms have different failure modes, listed in
[limits of cluster Service targets](reference/runtimepolicy.md#limits-of-cluster-service-targets)
and [limits of domain names](reference/runtimepolicy.md#limits-of-domain-names). A domain
allow list is not a containment boundary. A cluster Service written short, as
`<service>.<namespace>`, is neither: it is taken as an external name and matches nothing.

## File and process control

[`examples/files-and-processes/`](../../examples/files-and-processes/) — deciding which files
a workload may read and which binaries it may run.

| Example | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [deny-sensitive-file-access](../../examples/files-and-processes/deny-sensitive-file-access/) | Block reads of credential files (`/etc/shadow`, SSH keys) even from a shell inside the pod | enforce | BPF-LSM |
| [restrict-exec-allowlist](../../examples/files-and-processes/restrict-exec-allowlist/) | Prevent shell or netcat execution in a hardened pod: default-deny exec with an allow-list | enforce | BPF-LSM |
| [enforce-workload-baseline](../../examples/files-and-processes/enforce-workload-baseline/) | Lock a workload to its known-good files, binaries, and destinations | enforce | BPF-LSM |

## Shadow AI

[`examples/shadow-ai/`](../../examples/shadow-ai/) — finding the model providers, SDKs, agent
CLIs, and MCP servers a workload picked up on its own. These are walked through together,
with what each signal can and cannot establish, in
[detecting shadow AI](shadow-ai.md).

| Example | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [report-unexpected-dns](../../examples/shadow-ai/report-unexpected-dns/) | Report the provider hostnames a workload resolves outside its approved set, and discover the names it resolves at all | monitor | cgroup v2 |
| [trusted-and-untrusted-agents](../../examples/shadow-ai/trusted-and-untrusted-agents/) | Give a declared agent a hard TLS-to-one-Service boundary, and report which LLM providers an undeclared one resolves | enforce and monitor | cgroup v2 |
| [detect-ai-sdks](../../examples/shadow-ai/detect-ai-sdks/) | Report the AI SDKs, model files, model caches, and agent credentials a workload reads | monitor | BPF-LSM |
| [detect-agent-cli](../../examples/shadow-ai/detect-agent-cli/) | Report the coding-agent CLIs and self-hosted inference servers a workload launches | monitor | BPF-LSM |
| [monitor-claude-code](../../examples/shadow-ai/monitor-claude-code/) | Run Claude Code in a container and inventory its process, file, network, protocol, and DNS activity | monitor | BPF-LSM for `open` and `exec`; cgroup v2 for network-side findings |
| [detect-mcp-servers](../../examples/shadow-ai/detect-mcp-servers/) | Report every stdio MCP server a workload launches, identified by the package it was asked to run rather than the binary that ran it | monitor | BPF-LSM for the stdio half; cgroup v2 for the remote half |
| [detect-mcp-config-access](../../examples/shadow-ai/detect-mcp-config-access/) | Detect a process reading an MCP configuration file, credentials included, with an `open` deny list of absolute paths | monitor | BPF-LSM |

A `dns` behavior declares the names a workload is expected to resolve and reports the rest.
It observes only, and a policy that pairs it with `mode: enforce` is refused when it
compiles: blocking a destination named by domain is what a `network` behavior does, so
accepting `enforce` here would be a second way to spell one thing with only one of them
working. The two are complementary — a `network` behavior decides about destinations a
policy already named, while only the question observation supplies a name no policy named.

The allow list is inverted relative to `exec` and `open`: `dns.allow` is the expected set,
so a name matching none of its entries is reported without any `"*"` in `deny`. Values are
exact hostnames or left-wildcards such as `*.example.com`, which cover subdomains and not
the apex. A resolution is not a connection, and the rest of what this cannot see is in
[limits of DNS reporting](reference/runtimepolicy.md#limits-of-dns-reporting).

## Monitor mode

[`examples/monitoring/`](../../examples/monitoring/) — recording what a workload does without
blocking any of it, which is where an enforcement policy usually starts.

| Example | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [monitor-egress](../../examples/monitoring/monitor-egress/) | Audit where a workload actually connects before turning enforcement on | monitor | cgroup v2 |
| [monitor-workload-baseline](../../examples/monitoring/monitor-workload-baseline/) | Record every file, binary, and destination a workload touches, without blocking | monitor | BPF-LSM for `open` and `exec`; `network` findings alone need only cgroup v2 |
| [monitor-static-pods](../../examples/monitoring/monitor-static-pods/) | Confirm the daemon can observe kubeadm's static control-plane pods | monitor | cgroup v2 |

Monitor mode reports through OpenReports `Report` objects and never blocks. What it can and
cannot see is listed in
[limits of monitor mode](reference/runtimepolicy.md#limits-of-monitor-mode). The shadow AI
examples above are monitor-mode too; they live under `shadow-ai/` because the signal they
narrow to is what makes them worth reading, not the mode.

## Dynamic lists (CEL libraries)

[`examples/dynamic-lists/`](../../examples/dynamic-lists/) — allow and deny lists do not have
to be literals. An `expression` can fetch them from the cluster or from an HTTP endpoint at
evaluation time, and `evaluationInterval` sets how often that happens.

| Example | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [blocklist-from-configmap](../../examples/dynamic-lists/blocklist-from-configmap/) | The security team manages the egress blocklist in a ConfigMap, with no policy edits | enforce | cgroup v2, plus ConfigMap read for the daemon |
| [blocklist-from-http](../../examples/dynamic-lists/blocklist-from-http/) | Pull the deny list from a threat-intel HTTP feed | enforce | cgroup v2 |
| [blocklist-from-json](../../examples/dynamic-lists/blocklist-from-json/) | Parse a JSON blob from a ConfigMap into a deny list | monitor | cgroup v2, plus ConfigMap read for the daemon |

The chart's default ClusterRole grants the daemon no ConfigMap access, so the two examples
that use the `resource` library ship a `daemon.rbac.extraRules` values snippet and apply it
before the policy. See [installation](installation.md) for the values reference and
[the CEL reference](reference/cel.md) for the library signatures.
