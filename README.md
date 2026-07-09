# Kyverno Runtime

Kyverno Runtime extends Kyverno policy-as-code from admission into runtime. It enforces
and observes pod behavior (file access, exec, network egress) using eBPF, driven by two
cluster-scoped CRDs.

NOTE: learning mode is still incomplete

## Concepts

- `RuntimePolicy`: cluster-scoped. Selects pods via `podSelector` and defines allow/deny
  rules for `network`, `exec`, or `open` behaviors, either as a literal list of values or
  a CEL expression. Enforced continuously once matched pods are observed; optionally
  re-evaluated on `evaluationInterval`.
- `WorkloadProfile`: cluster-scoped. Specifies `behaviorsToLearn` and a `duration`, and
  triggers a bounded learning window during which matched behavior is recorded instead of
  enforced, without needing an a-priori allow/deny list.

## Components

- `kyverno-runtime daemon`: runs per node (requires `NODE_NAME`). Watches `RuntimePolicy`
  and `Pod` events, attaches eBPF LSM hooks (file open/exec) and an egress IP filter per
  matched pod's cgroup, and exposes a gRPC learning-mode API (`Start`/`Stop`/`Read`).
- `kyverno-runtime ctrl`: cluster-scoped controller. Watches `WorkloadProfile` and calls
  each daemon's gRPC API to start/stop learning windows. Pod-label targeting for this
  flow is currently a no-op (`Labels` isn't populated from the `WorkloadProfile` yet), so
  treat learning mode as functional but not yet scoped correctly.

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

## Example: WorkloadProfile (learning mode)

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: WorkloadProfile
metadata:
  name: nginx-learn
spec:
  behaviorsToLearn:
  - network
  - open
  duration: 10m
```

```bash
kubectl apply -f nginx-learn.yaml
kubectl get workloadprofile nginx-learn
```
