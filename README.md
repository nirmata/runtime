# Nirmata Runtime

Kyverno policies for eBPF runtime enforcement.

[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.29+-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://golang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## 🚀 What is Nirmata Runtime?

**Nirmata Runtime** monitors and enforces runtime behaviors with Kyverno-style CEL policies using eBPF. It provides a per-node DaemonSet that attaches eBPF programs to the pods selected by a cluster-scoped `RuntimePolicy`. The `RuntimePolicy` governs five kinds of workload behavior: the files a process opens, the binaries it executes, the destinations it sends traffic to, the application protocols it speaks, and the DNS names it resolves. Decisions are made in the kernel, so a denied operation never completes.

Like Kyverno, everything in Nirmata Runtime is Kubernetes-native: policies are custom resources defined in this project and support CEL (Common Expressions Language); findings are written as [OpenReports](https://openreports.io) `Report` objects in the offending pod's namespace, per-node state and conditions live in the policy's `status`, and counters are exposed to Prometheus.

### Why Nirmata Runtime?

- **Admission Controllers checks the spec; Runtime checks the behavior.** Kyverno at admission validates what a pod *declares* before it starts. Nirmata Runtime enforces what the running process actually *does* — the files it opens, the binaries it execs, the addresses it contacts — after admission has already said yes.
- **Egress control below the CNI.** NetworkPolicy needs a CNI that implements it and reasons about pod-to-pod identity. The egress filter here attaches to the pod's cgroup, so it has no CNI dependency and it also covers destinations outside the cluster.
- **Blocks, not just alerts.** Runtime detection tells you a sensitive file was read. `mode: enforce` returns `-EPERM` from a BPF-LSM hook, so the read never happens. `mode: monitor` gives you the detection workflow first, with the same policy object.
- **One small CRD, Kyverno CEL, deliberately narrow.** Tetragon is a general tracing and enforcement engine with its own policy grammar. Nirmata Runtime covers five behaviors with one `RuntimePolicy` CRD, allow and deny lists, and the same CEL libraries used across Kyverno — including deny lists fetched from ConfigMaps or HTTP feeds at evaluation time.

## ✨ Key Features

- **Five behaviors**: `open` (file paths), `exec` (binary paths), `network` (addresses,
  CIDRs, domain names, and cluster Service names), `protocol` (the application protocol a
  flow speaks), and `dns` (the names a workload resolves, observed only), in any
  combination in one policy.
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
- **Selector scoping**: a `podSelector` label selector, cluster-wide; omitting it selects
  every pod.
- **Periodic re-evaluation**: `evaluationInterval` re-runs the policy's expressions, so
  an externally sourced deny list stays current without editing the policy.

🚨 **WARNING**: This project is pre-1.0 and the API is `v1alpha1`. Here are some known limitations:

- Egress is keyed on IPv4 destination addresses. A domain name or cluster Service name is accepted as a value and resolved to addresses; an IPv6 literal is not.
- File `open` and process `exec` enforcement require a kernel booted with BPF-LSM active: `bpf` must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel boot parameter). Stock distributions and hosted CI runners are
typically not booted with it.
- `network`, `open`, and `exec` observation drains eBPF counters on a poll interval rather than streaming events, so a finding can lag the behavior and carries counts rather than ordering. A `dns` question is streamed as it happens.
- Nothing reads inside TLS. A destination is named by domain only when the pod's own DNS answer was observed, and no policy value has a port.
- Exceptions are not yet supported.

## 🏃 Quick Start

### Prerequisites

- A Kubernetes cluster on Linux nodes, plus `kubectl`, `helm`, and `git`. A stock
  [kind](https://kind.sigs.k8s.io/) cluster works.
- Network egress enforcement and observation require only a cgroup v2 host and BPF
  support; a stock kind cluster on a Linux host qualifies. That is all the sample below
  needs.

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

Start a client and an HTTP server, and note the server's address:

```bash
git clone https://github.com/nirmata/kyverno-runtime.git
cd kyverno-runtime/examples/egress/block-known-bad-egress
kubectl apply -f client.yaml -f targets.yaml
kubectl wait --for=condition=Ready pod/egress-client pod/egress-target-denied --timeout=90s
DENIED=$(kubectl get pod egress-target-denied -o jsonpath='{.status.podIP}')
```

The client can reach it, and prints `ok`:

```bash
kubectl exec egress-client -- wget -q -T 3 -O - "http://$DENIED:8080/"
```

Deny that one address. Egress matches on destination IPv4 address, so one `sed` fills in
the address the pod actually got:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: block-known-bad-egress
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: egress-client
  behaviors:
  - network:
      deny:
        values:
        - "10.244.0.8"
```

```bash
sed "s/DENIED_IP/$DENIED/" policy.tmpl.yaml | kubectl apply -f -
```

The same request now fails, because the packet is dropped in the kernel — while everything
else the pod does, such as cluster DNS, keeps working:

```bash
kubectl exec egress-client -- wget -q -T 3 -O - "http://$DENIED:8080/"  # times out
kubectl exec egress-client -- nslookup kubernetes.default               # still resolves
```

No CNI, iptables rule, or sidecar is involved, and nothing about the pod spec changed.

### See what a workload reaches for

Enforcement is half of it. The other half is finding out what a workload does that nobody
declared — a model provider it was never approved to call, an SDK nobody reviewed, an MCP
server not in the image contract. A `dns` behavior declares the names a workload is
*expected* to resolve and reports the rest, and it needs only the cgroup v2 host the sample
above already used:

```bash
cd ../shadow-ai/report-unexpected-dns
kubectl apply -f client.yaml
kubectl wait --for=condition=Ready pod/dns-client --timeout=90s
kubectl apply -f policy.yaml
```

```yaml
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
NODE=$(kubectl get pod dns-client -o jsonpath='{.spec.nodeName}')
kubectl get report "kyverno-runtime-${NODE}" \
  -o jsonpath='{range .results[?(@.rule=="dns")]}{.properties.dnsName}{"\n"}{end}'
```

`api.mistral.ai` appears; `api.openai.com` does not.

The question crosses the wire in cleartext, so this works without touching the workload,
its TLS, or its trust store. What was *said* over that connection is not knowable here —
see [detecting shadow AI](docs/users/shadow-ai.md) for the signals that are, and the ones
that are not.

Full walkthroughs: [network egress](docs/users/quickstart.md), including how to flip a
policy to `monitor` and read the resulting Report, plus
[file reads](examples/files-and-processes/deny-sensitive-file-access/) and
[process exec](examples/files-and-processes/restrict-exec-allowlist/), which need a BPF-LSM kernel.

## 📚 Documentation

### User Documentation

- **[Quickstart](docs/users/quickstart.md)** - kind cluster to a kernel-enforced egress block in under five minutes; runs on any Linux host
- **[Why a runtime layer](docs/users/why-runtime.md)** - what a gateway, a TLS proxy, admission control, and a CNI each cannot see, and what this leaves to them
- **[Concepts](docs/users/concepts.md)** - how enforcement works, allow and deny semantics, modes, scoping, and what monitor mode sees
- **[Installation](docs/users/installation.md)** - platform requirements, Helm chart values, daemon flags
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

Contributions are welcome. See **[docs/dev/DEVELOPMENT.md](docs/dev/DEVELOPMENT.md)** for
build and test mechanics, the test layout, and how generated artifacts are regenerated.
Sign your commits (`git commit -s`). Bugs and feature requests go to
[GitHub issues](https://github.com/nirmata/kyverno-runtime/issues).

## 📄 License

Nirmata Runtime is licensed under the [Apache License 2.0](LICENSE).

## 🔗 References

- [Common Expression Language (CEL)](https://github.com/google/cel-spec)
- [Kubernetes CEL libraries](https://kubernetes.io/docs/reference/using-api/cel/)
- [Kyverno CEL libraries](https://github.com/kyverno/sdk/tree/main/extensions/cel/libs)
- [OpenReports](https://openreports.io)
- [BPF LSM (Linux kernel documentation)](https://docs.kernel.org/bpf/prog_lsm.html)

---

<div align="center">

Built with ❤️ by the Nirmata team

[Report Bug](https://github.com/nirmata/kyverno-runtime/issues) · [Request Feature](https://github.com/nirmata/kyverno-runtime/issues)

</div>
