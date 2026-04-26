# Configuration

This document covers install paths, runtime flags, feature gates, and basic
runtime validation workflows.

## Prerequisites

- Linux Kubernetes nodes (required for eBPF collection)
- `kind`, `kubectl`, `helm`
- `ko` for local image builds (`go install github.com/google/ko@latest`)

## Quick Start (Kind)

```bash
# Create kind cluster, load image into kind nodes, and install chart
make kind

# Or, when using an existing kind cluster, target the active context explicitly.
kubectl config current-context

# Verify installation
kubectl get pods -n kyverno-runtime
kubectl get ds -A
kubectl describe pod -n kyverno-runtime -l app.kubernetes.io/name=kyverno-runtime | grep -E "Image:|Image ID:"
kubectl get crd runtimepolicies.runtime.kyverno.io
kubectl get crd runtimebehaviors.runtime.kyverno.io
kubectl get crd reports.openreports.io
```

## Installation

### Helm

```bash
helm upgrade --install kyverno-runtime ./charts/kyverno-runtime \
  --namespace kyverno-runtime --create-namespace --wait
```

For local kind development, use:

```bash
# Use a unique image tag and the active kind cluster name to avoid stale image reuse.
make kind-install KIND_CLUSTER_NAME=<kind-cluster-name> IMAGE_TAG=<unique-tag>
```

### Raw manifests

```bash
kubectl apply -f config/crd/bases/runtime.kyverno.io_runtimepolicies.yaml
kubectl apply -f config/crd/bases/runtime.kyverno.io_runtimebehaviors.yaml
kubectl apply -f https://raw.githubusercontent.com/openreports/reports-api/refs/heads/main/config/install.yaml
kubectl apply -f config/rbac/service_account.yaml
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/rbac/role_binding.yaml
kubectl apply -f config/manager/deployment.yaml
```

## RuntimePolicy Validation Example

`RuntimePolicy` is cluster-scoped. Create target namespaces and pods as needed,
then apply policy resources at cluster scope.

```bash
kubectl create ns runtime-demo
kubectl label ns runtime-demo runtime-monitor=enabled --overwrite
kubectl -n runtime-demo run demo --image=busybox:1.36 --restart=Never --command -- sh -c 'sleep infinity'
kubectl -n runtime-demo wait --for=condition=Ready pod/demo --timeout=120s

# File-open detection policy
kubectl apply -f samples/runtimepolicy-file-open-detection.yaml

# Trigger file-open events
kubectl -n runtime-demo exec demo -- sh -c 'for i in $(seq 1 25); do cat /etc/hosts >/dev/null; sleep 0.1; done'

# Network-egress detection policy
kubectl apply -f samples/runtimepolicy-network-egress-check.yaml

# Trigger network egress events
kubectl -n runtime-demo exec demo -- sh -c 'for i in $(seq 1 10); do nc -w 1 -zv 8.8.8.8 53 || true; done'

# Check reports (writes are buffered)
kubectl get reports -n runtime-demo
kubectl get reports -n runtime-demo -o yaml
```

Troubleshooting quick checks:

- Verify controller logs: `kubectl -n kyverno-runtime logs -l app.kubernetes.io/name=kyverno-runtime --tail=100 | grep -E "(policy-evaluator|evaluating)"`
- Verify policies exist: `kubectl get runtimepolicy -A`
- Re-check reports after 5-10 seconds if buffered writes have not flushed
- For end-to-end validation on the active cluster, use `CONTEXT=$(kubectl config current-context) make smoke-quickstart`

## Controller Flags

### Runtime configuration

- `--inspektor-gadget-timeout=8s`: Timeout for Inspektor Gadget runtime initialization.
- `--metrics-bind-address=:8080`: Address for metrics endpoint.
- `--health-probe-bind-address=:8081`: Address for probe endpoint.
- `--leader-elect`: Enable leader election for controller manager.

### RuntimeBehavior enrollment

- `--runtimebehavior-auto-create=true|false`: Enable or disable auto-creation.
- `--runtimebehavior-include-controllers=Deployment,StatefulSet,DaemonSet,Job,CronJob,ReplicaSet`: Eligible controller kinds.
- `--runtimebehavior-include-bare-pods=false`: Whether bare pods are eligible.
- `--runtimebehavior-include-namespaces=<csv>`: Optional namespace allow-list.
- `--runtimebehavior-exclude-namespaces=kube-system,kyverno-runtime,<csv>`: Namespace deny-list.
- `--runtimebehavior-initial-mode=learning|monitor`: Initial mode for new profiles.
- `--runtimebehavior-optout-label=<key>`: Label key for managed opt-out exceptions.

### Report buffering

- `--report-buffer-interval=5s`: Flush reports every interval.
- `--report-buffer-max-count=500`: Flush when finding count reaches this limit.

### Feature gates

| Gate | Default | Purpose |
| --- | --- | --- |
| `--feature-baseline-engine` | enabled | Baseline learning and anomaly detection via `RuntimeBehavior` |
| `--feature-signature-engine` | enabled | Built-in signature rules for known attack patterns |
| `--feature-alert-sinks` | disabled | Route findings to external systems |
| `--feature-alert-aggregation` | enabled | Alert cooldown and burst controls |

## Samples and E2E Scenarios

Runtime policy and behavior samples:

- [runtimepolicy-network-egress-check.yaml](../../samples/runtimepolicy-network-egress-check.yaml)
- [runtimepolicy-usecases.yaml](../../samples/runtimepolicy-usecases.yaml)
- [runtimepolicy-complete-examples.yaml](../../samples/runtimepolicy-complete-examples.yaml)
- [runtimepolicy-file-open-detection.yaml](../../samples/runtimepolicy-file-open-detection.yaml)
- [runtimepolicy-sample.yaml](../../samples/runtimepolicy-sample.yaml)
- [runtimebehavior-demo-network-baseline-enforce.yaml](../../samples/runtimebehavior-demo-network-baseline-enforce.yaml)
- [runtimebehavior-deny-loopback-metadata.yaml](../../samples/runtimebehavior-deny-loopback-metadata.yaml)
- [runtimebehavior-restrict-sensitive-files.yaml](../../samples/runtimebehavior-restrict-sensitive-files.yaml)

Threat-scenario test manifests:

- [runtimepolicy-ai-agent-credential-access.yaml](../../samples/runtimepolicy-ai-agent-credential-access.yaml)
- [runtimepolicy-ai-agent-aws-credentials.yaml](../../samples/runtimepolicy-ai-agent-aws-credentials.yaml)
- [runtimepolicy-ai-agent-data-exfil.yaml](../../samples/runtimepolicy-ai-agent-data-exfil.yaml)
- [runtimepolicy-ai-agent-c2-communication.yaml](../../samples/runtimepolicy-ai-agent-c2-communication.yaml)

See [E2E_TESTING.md](../../test/e2e/E2E_TESTING.md) for scenario walkthroughs.
