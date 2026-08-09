# Why a runtime layer

A cluster can already have a great deal of policy in it: an LLM or MCP gateway, a
TLS-intercepting proxy, admission control, a CNI with NetworkPolicy, and scoped RBAC. This
page is about the question none of them answer, and the one Nirmata Runtime exists to
answer — what the workload actually did — and about the questions it deliberately leaves to
the layers above.

## Cooperation is the dividing line

Every layer above the kernel decides about traffic the workload chose to send it.

- A **gateway** governs models, tool calls, budgets, and approvals for what is addressed to
  it, and sees nothing else.
- A **TLS-intercepting proxy** reads any HTTPS it intercepts rather than only what is
  addressed to it, which is what turns unsanctioned egress into inspectable content. It
  sees a call only where the workload routes through it and trusts its CA.
- **Admission control** verifies the spec. It can inject proxy environment variables and a
  CA bundle; it cannot make a process honor either.
- **NetworkPolicy** decides connectivity. Its drops carry no process identity, and no API
  surface reports whether the CNI enforces it at all.

A proxy's audit records arrivals, so no field in it can represent a call that never
arrived. A clean audit and a workload that never spoke to the proxy at all produce the same
report.

| Layer | Governs | Blind to |
| --- | --- | --- |
| Gateway | model, tools, prompts, budgets, approvals | anything not addressed to it |
| TLS-intercepting proxy | content of any intercepted HTTPS, including calls that skip the gateway | anything that does not route through it or does not trust its CA |
| Admission control | what may be created; injects env and CA | whether the process honors either |
| CNI NetworkPolicy | who may reach whom, L3/L4 and FQDN | attempts, process identity, its own enforcement status |
| Nirmata Runtime | per-pod facts decided in the kernel: destination and protocol of every flow, file and exec enforcement, and the attempts as findings | content, which requires the client's cooperation |

The mechanism — eBPF at `cgroup_skb` and BPF-LSM — is shared with other runtime tools. What
differs is the altitude: an admission-validated CRD, per-node status conditions, findings
as OpenReports `Report` objects in the offending namespace, and CEL, rather than tracing
primitives and a JSON event stream.

## Known and shadow workloads

**Known** — declared, labelled, selected by a `RuntimePolicy`, running a sanctioned image,
provisioned with the proxy CA.

**Shadow** — a debug container, a CI job, an unreviewed sidecar, a compromised process.
Nobody declared it, so nobody set its proxy environment or installed the CA. It will not
route through a gateway, and a proxy it does not trust cannot intercept it.

Known workloads get content inspection. Shadow workloads get detection and coarse
enforcement. Both are useful, they are not the same guarantee, and conflating them will not
survive contact with an operator.

### What still holds without cooperation

Each of these is decided in the kernel on the pod's own cgroup, and none of them asks the
workload for anything.

| Control | Effect |
| --- | --- |
| `network` default deny, allowing only cluster DNS and the approved gateway | The pod reaches those and nothing else. Ignoring `HTTPS_PROXY` does not help: there is nowhere else to go |
| `protocol` default deny | Only named protocols leave. SSH on 443, an h2c tunnel, and a custom binary channel all classify as something other than `tls` |
| `quic` denied | HTTP/3 is opaque to a proxy, and no provider SDK speaks it, so denying it costs little and forces the workload into a lane something can observe |
| `exec` default deny | The pod runs its own binaries and no others, enforced at `bprm_check_security` |
| `open` deny | Named credential paths are unreadable regardless of which process asks |

### What is recorded

| Signal | Granularity |
| --- | --- |
| Attempt | Per flow, with the classified protocol and the kernel's decision |
| Destination | Address, plus the domain when the pod's own DNS answer named it |
| Subject | Pod and container, in the offending pod's namespace |
| Delivery | `Report` objects, deduplicated by fingerprint, with counts per window |
| Content | None. Nothing here reads inside TLS |

An operator gets *this pod, in this namespace, attempted TLS to this destination, and it was
denied* for a workload that was never declared and never cooperated. What was said in that
connection is not knowable, and this documentation should not imply otherwise.

The enforcement itself is coarse in specific, stateable ways — an `exec` value selects a
binary and never a command, paths are absolute and exact, and a `protocol` denial lands
mid-connection, because a flow cannot be classified until its first data segment exists. A
`network` denial is decided on the destination address alone, so it drops the first packet
and the connection never establishes; either way the client sees a stall and a timeout
rather than a refusal, since a `cgroup_skb` program drops packets and cannot send a reset.
Those limits are listed in
[limits of monitor mode](reference/runtimepolicy.md#limits-of-monitor-mode) and
[limits of protocol classification](reference/runtimepolicy.md#limits-of-protocol-classification);
read them before writing a policy that an operator will rely on.

## Two things only this layer can do

**Make routing mandatory.** A default-deny egress policy that permits DNS and the gateway
and nothing else is the one enforcement a proxy cannot perform on its own behalf, because a
workload that ignores the proxy never reaches the proxy to be told otherwise. The policy is
in [compel AI traffic through a gateway](shadow-ai.md#compel-ai-traffic-through-a-gateway).

**Reconcile the two vantage points.** A gateway reports *N* calls for an identity; the
kernel observed *M* connections to providers from the pod backing it. `M > N` quantifies
bypass, and neither system produces that number alone — the gateway cannot see what evaded
it, and the kernel does not know what the gateway did with what it got.

## What this does not do

**Destination scoping belongs to the CNI**, which does it better: identity-based L3/L4,
FQDN-aware egress, ingress, encryption, and flow observability integrated with the
dataplane. A cluster with a good CNI should keep using it. `network` targets are here
because a destination is half of every finding and a name is what an operator reads — as
detection and attribution, plus static hard denies such as the instance metadata endpoint,
not as a replacement egress firewall.

**Semantic AI enforcement — which model, which tool, which prompt — belongs to a proxy that
terminates the connection.** A weaker duplicate, evaluated in userspace against traffic the
kernel cannot decrypt, would be strictly worse than what already exists.

**Ingress is out of scope.** Every hook here is egress or execution, so a pod *serving* a
model, an MCP server, or an agent card is not observed, and neither is a
`kubectl port-forward` reaching it. Admission control and RBAC on `pods/portforward` cover
those.
