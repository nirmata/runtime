# Positioning

What this project is for, given a cluster that already runs the rest of the stack.

## The assumed stack

Two distinct proxies, not one, and the difference matters throughout:

- **An LLM/MCP gateway.** Agents are pointed at it — `ANTHROPIC_BASE_URL`, an MCP broker
  endpoint. It governs models, tool calls, budgets and approvals for traffic addressed to
  it, and sees nothing else.
- **A MITM TLS proxy** (AIControls, CrabTrap). Intercepts arbitrary HTTPS egress rather
  than only what is addressed to a gateway, so it is what turns *unauthorized* egress into
  inspectable content — a CLI client calling a provider over HTTPS directly, a tool
  invocation that never went near the gateway. Without it, egress that skips the gateway is
  merely traffic.
- **Kyverno admission control** — pod security, image verification, generated
  NetworkPolicies, and injection of the proxy environment and CA bundle.
- **A CNI with NetworkPolicy** — identity-based L3/L4, FQDN-aware egress, ingress,
  encryption, flow observability.

The MITM proxy substantially widens coverage, and it does not change the shape of the
problem: it still needs the workload to route through it and to trust its CA. Both are
provisioning facts about a workload someone declared. Neither holds for a workload nobody
declared.

## The claim

Nirmata Runtime is the **non-cooperative plane**: the layer that verifies — and where
needed compels — what every cooperative control can only assume, expressed as one
validated policy object with pod-attributed findings.

Every other layer's guarantee is conditional on the workload's cooperation:

- **Both proxies** see a call only if the workload routes to them and, for TLS
  interception, trusts the CA. Their audit records arrivals; no field in it can represent a
  call that never arrived.
- **Admission** verifies the spec. It can inject proxy environment variables and a CA
  bundle; it cannot make a process honor them.
- **NetworkPolicy** decides connectivity. Its drops are invisible to the operator, it has
  no process identity, and no API surface reports whether the CNI enforces it at all.

Nothing in that stack answers *"is the rest of the stack actually in effect for this pod,
right now?"* — which is the question this project exists to answer.

## Layers

| Layer | Owns | Blind to |
| --- | --- | --- |
| LLM/MCP gateway | model, tools, prompts, budgets, approvals | anything not addressed to it |
| MITM TLS proxy | content of any intercepted HTTPS, including CLI tool calls that skip the gateway | anything that does not route through it or does not trust its CA |
| Kyverno admission | what may be created; injects env and CA | whether the process honors either |
| CNI NetworkPolicy | who may reach whom, L3/L4 and FQDN | attempts, process identity, its own enforcement status |
| **Nirmata Runtime** | **per-pod in-kernel fact: protocol identity of every flow, exec and file enforcement, attempts as Reports** | content, which requires the client's cooperation |

The mechanism — eBPF at `cgroup_skb` and BPF-LSM — is shared with other runtime tools. The
difference is altitude: an admission-validated CRD, status conditions per node, findings as
OpenReports objects in the offending namespace, and CEL expressions, rather than tracing
primitives and a JSON event stream.

### Enforcement mechanism

Runtime tools divide on a sharper line than eBPF-or-not: whether the operation is stopped,
or the process is killed after it starts.

| Tool | Mechanism | Guarantee |
| --- | --- | --- |
| Tetragon `Sigkill` | `bpf_send_signal` from BPF | Kills the calling process synchronously — but the operation may still complete. Its own docs note a SIGKILL during `write()` does not guarantee the data is unwritten |
| Tetragon `Override` | `bpf_override_return` | The function never runs. Restricted to syscalls and security-check functions, and needs `CONFIG_BPF_KPROBE_OVERRIDE` and the kernel error-injection framework |
| KubeArmor | AppArmor, BPF-LSM, SELinux for the host | Inline denial at an LSM hook. Positioned explicitly against killing a process once malicious intent is already observed |
| This project | BPF-LSM, `cgroup_skb` | `-EPERM` at `file_open` and `bprm_check_security`; packets dropped at the cgroup hook. No kill path and no error-injection dependency |

Neither Tetragon action is a userspace kill — both run in kernel BPF — but only `Override`
prevents the operation, which is why Tetragon documents combining the two when the
operation itself must not complete.

The same standard applied here: `open` and `exec` are genuinely inline, because an LSM hook
returns before the operation. `protocol` and `network` are not equivalent. A `cgroup_skb`
program cannot forge a reset, so a denied flow has already completed its handshake and gets
its first data segment dropped — the payload is prevented, the connection is not.

## Cooperation is the dividing line

Content inspection requires the client's cooperation. A TLS-intercepting proxy works only
where the workload trusts its CA and routes through it. A workload nobody provisioned does
neither, by definition.

**Known workload** — declared, labelled, selected by a RuntimePolicy, running a sanctioned
image, provisioned with the proxy CA.

**Shadow workload** — a debug container, a CI job, a sidecar, a compromised process.
Nobody declared it, so nobody set its proxy environment or installed the CA; it will not
route through either proxy, and a MITM proxy it does not trust cannot intercept it.

Known workloads get inspection. Shadow workloads get detection and coarse enforcement.
Both are useful; they are not the same guarantee, and conflating them in the reference or
in marketing will not survive contact with an operator.

Two mechanisms make the distinction pay:

- **Compelled routing** — per-pod cgroup default-deny egress permitting only DNS, the
  proxy, and an explicit allowlist. This is the one enforcement a proxy cannot perform on
  itself.
- **Reconciliation** — the proxy reports *N* calls for an identity; the kernel observed *M*
  provider connections from the pod backing it. `M > N` quantifies bypass. Neither system
  can produce that number alone: the proxy cannot see what evaded it, and the kernel does
  not know what the proxy did with what it got.

## A worked scenario: the poisoned ticket

An SRE remediation agent runs in-cluster with its own ServiceAccount. It is a known
workload: declared, labelled, selected by a RuntimePolicy, image sanctioned, provisioned
with the proxy CA. It calls an MCP tool to fetch incident tickets, and one ticket body
carries injected instructions.

Nothing here bypasses anything — the agent cooperates fully — so compelled routing and
reconciliation contribute nothing. That is what makes it a useful test.

**Recognizing the injection belongs to the proxies, and to nothing else.** The gateway sees
the tool response if the call was addressed to it; the MITM proxy sees it if the agent used
an HTTPS client it intercepts. To every layer below, this is a well-formed TLS response
from a sanctioned endpoint.

**Containment then depends on what the payload tries to do:**

| Injected action | Stopped by | How |
| --- | --- | --- |
| Spawn a shell, run a downloaded binary | this project | `exec` default-deny, `-EPERM` at `bprm_check_security` |
| Read another pod's secret, an SSH key | this project | `open` deny at `file_open` |
| Connect somewhere new to exfiltrate or fetch a payload | this project, and the CNI | Default-deny egress — and the attempt is reported with pod attribution, where a CNI drop is silent |
| Exfiltrate over a permitted port with an unexpected protocol | this project | `protocol` is port-independent: SSH or a custom channel on 443 does not pass a `tls` allowlist |
| Create a privileged pod or edit RBAC | Kyverno admission | Denied at the API server |
| Destructive API call with the agent's own SA | RBAC, Kyverno admission | Scope the SA; validate the mutation |
| Call a different, more dangerous tool | gateway, or MITM proxy if the call skips it | Tool authorization by name |
| The sanctioned tool with destructive arguments | gateway, or MITM proxy | CEL over the call's arguments — deny a target namespace, a scale-to-zero, a delete; require approval above a blast radius. This is argument-level policy, not just tool-level |
| A destructive action taken in-process rather than as a tool call | RBAC, Kyverno admission | No tool call exists to inspect; the API server is the only chokepoint left |
| **An in-policy action, chosen for the wrong reason** | **nothing** | Right tool, permitted arguments, wrong moment — no layer can see intent |

Argument-level policy is where most of this scenario is actually won, and it belongs to the
proxies: a CEL rule over the tool call can refuse `namespace: kube-system`, refuse a
scale-to-zero, or send anything above a blast-radius threshold to approval. Two conditions
bound it — the call has to reach a proxy, and the harm has to be visible in the arguments.

The last row is what survives both. If the agent's job is restarting deployments in
production and the injection says "restart the payments deployment", the arguments are
in-policy: the proxy sees an authorized call with permitted arguments, admission sees a
permitted mutation, and the kernel sees allowed traffic to an allowed address. Nothing in
the stack distinguishes that from the remediation it was hired to perform. What remains is
narrow RBAC, approval gates on the actions worth gating, and blast radius — none of which
is a detection.

The scenario also shows why the layers are worth having together: they fail in different
directions. The proxy catches the injection but not the process; admission catches the API
abuse but not the shell; the kernel catches the shell but not the intent.

In practice a workload like this is baselined in `monitor` mode first — a remediation
agent's legitimate exec, file and network profile is narrow, which is what makes converting
it into a default-deny allowlist tractable.

## Shadow workloads: coarse enforcement, fine observability

The poisoned ticket is a trusted workload behaving unexpectedly. The other half of the
problem is a workload nobody declared. It gets no content inspection — that is settled by
CA trust, not by effort — but it is not therefore ungoverned. Two things still hold,
because both are decided in the kernel on the pod's own cgroup and neither asks the
workload for anything.

**Coarse enforcement — what a non-cooperating workload can still be prevented from doing:**

| Control | Effect |
| --- | --- |
| `network` default deny with `serviceRefs` | The pod reaches DNS and the proxy and nothing else. Ignoring `HTTPS_PROXY` does not help: there is nowhere else to go. This is the enforcement a proxy cannot perform on itself |
| `protocol` default deny | Only named protocols leave. SSH on 443, an h2c tunnel, a custom binary channel and a split ClientHello all classify as something other than `tls` and are dropped |
| `quic` denied | HTTP/3 is opaque to every proxy. Denying it costs almost nothing — no provider SDK speaks h3 — and forces the workload into a lane something can observe |
| `exec` default deny | The pod runs its own binaries and no others, enforced at `bprm_check_security` |
| `open` deny | Credential paths — another pod's mounted secret, an SSH key — are unreadable regardless of what the process is |

**Fine observability — what is recorded, for enforced and observed policies alike:**

| Signal | Granularity |
| --- | --- |
| Attempt | Per flow, with the classified protocol and the kernel's decision |
| Destination | Address, plus the domain when the pod's own DNS answer named it |
| Subject | Pod and container, in the offending pod's namespace |
| Delivery | OpenReports `Report` objects, deduplicated by fingerprint, counts per window |
| Content | **Never.** Prompts and bodies are redacted on the way out by construction |

The point of the pairing: an operator gets *"this pod, in this namespace, attempted TLS to
this provider, and it was denied"* for a workload that was never provisioned, never
declared, and never cooperated. What was said in that connection is not knowable, and the
docs should not imply otherwise.

### Discover first

Absent a `podSelector` this selects every pod on the node, and `monitor` blocks nothing —
under a default deny every observed destination and protocol becomes a finding, which is
the inventory:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: egress-discovery
spec:
  mode: monitor
  behaviors:
  - network:
      deny:
        values: ["*"]
  - protocol:
      deny:
        values: ["*"]
```

### Then compel routing

For workloads that are supposed to use the proxy, this makes it non-optional. Note that
neither behavior depends on the workload honoring an environment variable or trusting a
CA:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: ai-egress-via-proxy
spec:
  mode: enforce
  podSelector:
    matchLabels:
      nirmata.io/ai-workload: "true"
  behaviors:
  - network:
      allow:
        serviceRefs:
        - name: aicontrols
          namespace: nirmata-aicontrols
        - name: kube-dns
          namespace: kube-system
      deny:
        values: ["*"]
  - protocol:
      allow:
        values: ["tls", "dns"]
      deny:
        values: ["*"]
```

`allow: [tls, dns]` is deliberately narrow. `quic` is excluded, so an HTTP/3 client is
denied rather than tunnelling past inspection; cleartext `http/1.1` is excluded, so a
plaintext call to a provider fails rather than leaking. A resolver pinned to DNS-over-TLS
needs `tls/dot` instead of `dns`.

### And bound the rest

For everything not designated an AI workload, a blocklist rather than an allowlist — no
default deny, so ordinary traffic is unaffected — closing the lanes that exist only to
evade inspection:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: baseline-evasion-lanes
spec:
  mode: enforce
  behaviors:
  - protocol:
      deny:
        values: ["quic", "ssh"]
  - network:
      deny:
        values: ["169.254.169.254"]
  - open:
      deny:
        values: ["/var/run/secrets/kubernetes.io/serviceaccount/token"]
```

The instance metadata address is the classic credential-theft destination and has no
legitimate caller in most workloads. The ServiceAccount token deny is the one to trial in
`monitor` first — plenty of in-cluster clients read it legitimately, and the finding tells
you which before anything is enforced.

## What this project does not do

Destination scoping belongs to the CNI, which does it better: identity-based L3/L4,
FQDN-aware egress, ingress, encryption, and flow observability integrated with the
dataplane. A cluster with a good CNI should keep using it.

`network` targets remain, because a destination is half of every finding and a provider
name is what an operator reads — but as **detection and attribution**, plus static
hard-denies such as the instance metadata endpoint, not as an egress firewall.

Semantic AI enforcement — which model, which tool, which prompt — belongs to the proxy. A
weaker duplicate evaluated in userspace against traffic the kernel cannot decrypt would be
strictly worse than what already exists.

## Self-attestation is a prerequisite, not polish

A product whose pitch is attesting other layers has to attest itself first. The recurring
defect class in this repository's history is *the control appears applied and enforces
nothing* — thirteen instances fixed across two reviews. Until a policy that cannot be
compiled, a pod whose cgroup cannot be resolved, and a policy with no mode each produce a
condition or a metric that says so, the claim above is not one this project can make about
itself.
