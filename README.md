# Kyverno Runtime

Kyverno Runtime extends Kyverno policy-as-code from admission into runtime. It enforces
and observes pod behavior (file access, exec, network egress) using eBPF, driven by a
cluster-scoped CRD.

## Concepts

- `RuntimePolicy`: cluster-scoped. Selects pods via `podSelector` and defines allow/deny
  rules for `network`, `exec`, `open`, or `ai` behaviors, either as a literal list of values
  or a CEL expression. `spec.mode` (`monitor`/`enforce`/`discover`) controls whether matched
  behavior is reported, enforced, or (for `ai`) rolled into a cluster inventory. Optionally
  re-evaluated on `evaluationInterval`.
- `spec.mode`: `enforce` blocks matching behavior in the kernel; `monitor` attaches the same
  eBPF programs with empty deny lists and *reports* what a workload does instead of blocking
  it — useful for trialling a policy before enforcing it.
- Shadow AI detection: the `ai` behavior classifies LLM/MCP/A2A traffic (provider, model,
  confidence-scored evidence) instead of matching raw IPs/commands/paths. See
  [docs/shadow-ai.md](docs/shadow-ai.md) for the reference and the current honest status of
  what is and isn't wired up yet.

## Components

- `kyverno-runtime daemon`: runs per node (requires `NODE_NAME`). Watches `RuntimePolicy`
  and `Pod` events, attaches eBPF LSM hooks (file open/exec) and an egress IP filter per
  matched pod's cgroup.

## Output

- **Reports**: monitor-mode matches are written as [OpenReports](https://openreports.io)
  `Report` objects in the offending pod's namespace (`kubectl get reports -A`), one per
  namespace and node, deduplicated and counted.
- **Status**: each daemon writes its own shard of a policy's `status.nodes` with observed and
  violating pod counts, plus conditions reporting the mode it is running in and any policy
  target it could not program.
- **Metrics**: Prometheus metrics on `--metrics-addr` (default `:9090`) covering ingested and
  dropped observations, attribution misses, findings, and report writes.

Monitor mode observes the counters the existing eBPF programs keep, polled every 10 seconds.
See [docs/runtimepolicy.md](docs/runtimepolicy.md#limits-of-monitor-mode) for what that does and
does not see — notably no DNS, TLS, or HTTP visibility, and IPv4-only egress observation.

## Installation

```bash
helm repo add kyverno-runtime https://nirmata.github.io/kyverno-runtime/
helm repo update
helm install kyverno-runtime kyverno-runtime/kyverno-runtime \
  --namespace kyverno-runtime --create-namespace
```

or from the OCI registry:

```bash
helm install kyverno-runtime oci://ghcr.io/nirmata/kyverno-runtime/kyverno-runtime \
  --namespace kyverno-runtime --create-namespace
```

Pick a published chart version from the [releases page](https://github.com/nirmata/kyverno-runtime/releases);
this project is pre-1.0 and versions move fast.

```bash
kubectl get pods -n kyverno-runtime
kubectl get runtimepolicies
```

## Example: RuntimePolicy

Deny loopback egress:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: detect-loopback-egress
spec:
  podSelector:
    matchLabels:
      app: nginx
  behaviors:
  - network:
      deny:
        values:
        - "127.0.0.1"
```

```bash
kubectl apply -f loopback-egress.yaml
kubectl get runtimepolicy detect-loopback-egress
```

See [docs/runtimepolicy.md](docs/runtimepolicy.md) for the full spec reference,
`allow`/`deny` with `values` and CEL `expression`, `mode: monitor` and its limits, status and
conditions, Reports, metrics, the `resource` and `http` CEL libraries, and
default-deny-with-allow-list patterns.
