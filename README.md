# Kyverno Runtime

Kyverno Runtime evaluates runtime activity from running Pods against `RuntimePolicy` rules and writes findings to namespaced `PolicyReport` resources.

## Architecture

Kyverno Runtime now runs as a single DaemonSet component.

- One `kyverno-runtime` Pod runs per node.
- Each Pod watches Pods, collects events locally with embedded Inspektor Gadget runtime, evaluates matching runtime policies, and writes `PolicyReport` results.
- There is no separate runtime sensor service or secondary controller binary.

For runtime behavior baseline persistence and APIs, kyverno-runtime uses
`RuntimeBehavior` as the CR name.

## Prerequisites

- Linux Kubernetes nodes (required for eBPF collection)
- `kind`, `kubectl`, `helm`
- `ko` for local image builds (`go install github.com/google/ko@latest`)

## Quick Start (Kind)

```bash
# Build local image with ko
make ko-build

# Create kind cluster, load image into kind nodes, and install chart
make kind-create

# Verify
kubectl get pods -n kyverno-runtime
kubectl get ds -n kyverno-runtime
kubectl describe pod -n kyverno-runtime -l app.kubernetes.io/name=kyverno-runtime | grep -E "Image:|Image ID:"
kubectl get crd runtimepolicies.runtime.kyverno.io
kubectl get crd policyreports.wgpolicyk8s.io
```

## RuntimePolicy Example

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: detect-sensitive-open
spec:
  namespaceSelector:
    matchLabels:
      runtime-monitor: "enabled"
  validations:
  - name: detect-etc-hosts-open
    event: open
    message: Access to /etc/hosts detected
    severity: high
    matchConditions:
    - expression: event["fname"].contains("/etc/hosts") || event["file.path"].contains("/etc/hosts")
    actions:
    - type: generate_report
      message: Sensitive file access detected
```

Apply a test namespace and pod:

```bash
kubectl create ns runtime-demo
kubectl label ns runtime-demo runtime-monitor=enabled --overwrite
kubectl -n runtime-demo run demo --image=busybox:1.36 --restart=Never --command -- sh -c 'sleep 300'
kubectl -n runtime-demo wait --for=condition=Ready pod/demo --timeout=120s
```

Apply policy and trigger activity. The controller streams eBPF events continuously
for all matching pods, so no manual trigger is needed:

```bash
kubectl apply -f testdata/e2e-live-trace-policy.yaml
# Generate open events — the controller will detect them in real time.
kubectl -n runtime-demo exec demo -- sh -c 'for i in $(seq 1 25); do cat /etc/hosts >/dev/null; sleep 0.1; done'
kubectl get policyreport -n runtime-demo
```

If no report is created yet, check controller logs:

```bash
kubectl -n kyverno-runtime logs -l app.kubernetes.io/name=kyverno-runtime --tail=200
kubectl get policyreport -n runtime-demo
```

## Build and Test

```bash
make build
go test ./...
```

## Helm Install

```bash
helm upgrade --install kyverno-runtime ./charts/kyverno-runtime \
  --namespace kyverno-runtime --create-namespace --wait
```

For local kind development, use:

```bash
make kind-install
```

This target builds the local image, loads it into the kind cluster nodes, and
then runs the Helm install/upgrade with matching image values.

## Raw Manifests Install

```bash
kubectl apply -f config/crd/bases/runtime.kyverno.io_runtimepolicies.yaml
kubectl apply -f config/crd/bases/wgpolicyk8s.io_policyreports.yaml
kubectl apply -f config/rbac/service_account.yaml
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/rbac/role_binding.yaml
kubectl apply -f config/manager/deployment.yaml
```

## Controller Flags

- `--inspektor-gadget-timeout=8s`
- `--metrics-bind-address=:8080`
- `--health-probe-bind-address=:8081`
- `--leader-elect`
- `--zap-log-level=<level>` (for example `--zap-log-level=debug|info|warn|error`)
- `--zap-devel=true|false`

## Samples

- [testdata/runtimepolicy-usecases.yaml](testdata/runtimepolicy-usecases.yaml)
- [testdata/e2e-live-all-usecases.yaml](testdata/e2e-live-all-usecases.yaml)
- [testdata/e2e-live-trace-policy.yaml](testdata/e2e-live-trace-policy.yaml)
- [testdata/sample-runtimepolicy.yaml](testdata/sample-runtimepolicy.yaml)
