# Examples

Each directory is a self-contained scenario: the manifests it needs, and a README that
walks through what it shows, how to apply it, how to verify the result, and how to clean
up. The verification step always checks both directions where it can — that the protected
thing is blocked *and* that everything else still works — because a check that only looks
for a failure would also pass against a runtime that blocks everything.

The manifests here are the canonical, runnable form. Every `RuntimePolicy` under
`examples/` is a complete object that decodes against the CRD and whose expressions compile
against the daemon's CEL environment; a snippet quoted in the documentation is a copy of
one of these files, not a sketch.

Every policy sets `spec.mode` explicitly. A policy that omits it neither enforces nor
reports.

## Requirements legend

**cgroup v2** — Network egress enforcement and observation require only a cgroup v2 host
and BPF support; a stock kind cluster on a Linux host qualifies.

**BPF-LSM** — File `open` and process `exec` enforcement require a kernel booted with
BPF-LSM active: `bpf` must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel
boot parameter). Stock distributions and hosted CI runners are typically not booted with
it.

DNS question reporting shares the cgroup v2 requirement and needs no BPF-LSM.

## Index

| Directory | Scenario | Features | Mode | Requires |
| --- | --- | --- | --- | --- |
| [block-known-bad-egress](block-known-bad-egress/) | Stop a pod from reaching one known-bad destination address, leaving the rest of its egress alone (used by the quickstart) | `network` deny, literal values, `podSelector`, status conditions | enforce | cgroup v2 |
| [default-deny-egress](default-deny-egress/) | Contain a compromised pod: block all egress except one approved service | `network` default deny with an allow-list, cross-policy union | enforce | cgroup v2 |
| [egress-to-cluster-service](egress-to-cluster-service/) | Force egress through a gateway without hardcoding its addresses | Cluster Service DNS names resolved from Service and EndpointSlice informers | enforce | cgroup v2 |
| [egress-to-domain-name](egress-to-domain-name/) | Allow an external destination by DNS name rather than address | A fully qualified domain name as a `network` value, matched from the pod's own DNS answers | enforce | cgroup v2 |
| [tls-only-egress](tls-only-egress/) | Force a workload to speak only TLS, whatever port it uses | `protocol` default deny, classification from the first data segment | enforce | cgroup v2 |
| [protocol-default-deny](protocol-default-deny/) | The same default deny, with the allowed and denied protocols exercised on one port | `protocol` allow list plus the `"*"` sentinel | enforce | cgroup v2 |
| [egress-baseline-combined](egress-baseline-combined/) | Every network-side field in one annotated policy, with the accepted values for each | `network` + `protocol` together, `variables`, `evaluationInterval`, Service DNS names | enforce | cgroup v2 |
| [overlapping-egress-policies](overlapping-egress-policies/) | Two policies over one pod, and a pod that starts after them | union of allow lists, per-address refcounting, pod-first ordering | enforce | cgroup v2 |
| [trusted-and-untrusted-agents](trusted-and-untrusted-agents/) | Give a declared agent a hard TLS-to-one-Service boundary, and report which LLM providers an undeclared one resolves | `network` + `protocol` default deny in one policy, `dns` deny list in another | enforce and monitor | cgroup v2 |
| [monitor-static-pods](monitor-static-pods/) | Confirm the daemon can observe kubeadm's static control-plane pods | `podSelector: {}`, monitor mode over pods no controller owns | monitor | cgroup v2 |
| [monitor-egress](monitor-egress/) | Audit where a workload actually connects before turning enforcement on | monitor mode, Reports, metrics | monitor | cgroup v2 |
| [deny-sensitive-file-access](deny-sensitive-file-access/) | Block reads of credential files (`/etc/shadow`, SSH keys) even from a shell inside the pod | `open` deny, `values` plus `expression`, `variables` | enforce | BPF-LSM |
| [restrict-exec-allowlist](restrict-exec-allowlist/) | Prevent shell or netcat execution in a hardened pod: default-deny exec with an allow-list | `exec` default deny with an allow-list, `variables` | enforce | BPF-LSM |
| [monitor-workload-baseline](monitor-workload-baseline/) | Record every file, binary, and destination a workload touches, without blocking | monitor mode across all three behaviors, `evaluationInterval`, Reports | monitor | BPF-LSM for `open` and `exec`; `network` findings alone need only cgroup v2 |
| [report-unexpected-dns](report-unexpected-dns/) | Report the DNS names a workload resolves that it was not expected to, and discover the names it resolves at all | `dns` behavior, inverted allow semantics, left-wildcards, `deny: ["*"]` discovery, advisory findings | monitor | cgroup v2 |
| [detect-mcp-config-access](detect-mcp-config-access/) | Detect a process reading an MCP configuration file, credentials included | `open` deny over absolute config paths, monitor mode | monitor | BPF-LSM |
| [blocklist-from-configmap](blocklist-from-configmap/) | The security team manages the egress blocklist in a ConfigMap, with no policy edits | `resource` CEL library, `evaluationInterval`, target validation | enforce | cgroup v2 |
| [blocklist-from-http](blocklist-from-http/) | Pull the deny list from a threat-intel HTTP feed | `http` CEL library, `dyn` coercion, `evaluationInterval` | enforce | cgroup v2 |
| [blocklist-from-json](blocklist-from-json/) | Parse a JSON blob from a ConfigMap into a deny list | `json` plus `resource` CEL libraries, `variables`, monitor mode | monitor | cgroup v2 |
| [enforce-workload-baseline](enforce-workload-baseline/) | Lock a workload to its known-good files, binaries, and destinations | all three behaviors enforced, default deny with allow-lists, `evaluationInterval` | enforce | BPF-LSM |

Two examples need extra RBAC because the `resource` library reads a ConfigMap through the
API server: `blocklist-from-configmap` and `blocklist-from-json` each ship the
`daemon.rbac.extraRules` values snippet their README applies.

For the field-by-field spec see the
[RuntimePolicy reference](../docs/users/reference/runtimepolicy.md), and for the expression
environment the [CEL reference](../docs/users/reference/cel.md).
