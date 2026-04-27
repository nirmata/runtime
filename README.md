# Kyverno Runtime

Kyverno Runtime extends [Kyverno](https://kyverno.io) policy as code from admission into runtime.
It gives security and platform teams a single way to detect known-bad behavior and
workload-specific anomalies for both traditional workloads and AI agents.

## ✨ Features

- Protect workloads with cluster-wide runtime signatures using `RuntimePolicy`.
- Detect workload drift with learned known-good baselines using `RuntimeBehavior`.
- Use one reporting surface (`Report` resources from OpenReports) for both signature and anomaly findings.
- Start safely with monitor-first auto-enrollment and promote to enforcement with confidence.

## 🧠 Key Concepts

Kyverno Runtime uses two complementary detection models:

| Resource | Scope | Function |
| --- | --- | --- |
| `RuntimePolicy` | Cluster-scoped | Detect known-bad patterns and define actions |
| `RuntimeBehavior` | Per workload profile | Learn and enforce known-good behavior |

1. `RuntimePolicy` provides reusable cluster-level signatures for known threats.
2. `RuntimeBehavior` provides workload-level anomaly detection from baseline behavior.
3. The controller can auto-create `RuntimeBehavior` profiles for enrolled workloads.
4. Findings from both engines are deduplicated and written to namespaced OpenReports `Report` resources.

## 🚀 Quick Start

### ✅ Prerequisites

- Kubernetes 1.24+ cluster (kind, EKS, GKE, etc.)
- `kubectl` configured to access your cluster
- `helm` 3.0+

### 📦 Installation

**1. Add the Kyverno Helm repository** (when available):

```bash
helm repo add kyverno-runtime https://nirmata.github.io/kyverno-runtime/
helm repo update
```

**Step 2: Install Kyverno Runtime with default policies**:

```bash
helm install kyverno-runtime oci://ghcr.io/nirmata/kyverno-runtime/kyverno-runtime \
  --version 0.0.1 \
  --namespace kyverno-runtime --create-namespace \
  --set defaultPolicies.enabled=true \
  --set defaultPolicies.policies.suspiciousDNS=false
```

**Step 3: Verify installation**:

```bash
kubectl get pods -n kyverno-runtime
kubectl get runtimepolicies  # View default policies
```

### 🐚 Example 1: Detect Suspicious Shell Execution

Default policies include detection for shell execution. Trigger this by running a shell in a pod:

```bash
# Create a test namespace
kubectl create namespace demo

# Deploy a sample workload
kubectl run nginx --image=nginx -n demo

# Exec into the pod and trigger shell detection
kubectl exec -it nginx -n demo -- /bin/bash

# View generated findings
kubectl get reports -n demo
kubectl describe report <report-name> -n demo
```

### 🔐 Example 2: Protect Against Credential Access

Use the default library policy `detect-credential-access` to detect when containers attempt to read sensitive files like SSH keys or credentials:

```bash
# Confirm the default library policy exists
kubectl get runtimepolicy detect-credential-access -n kyverno-runtime

# Test by trying to read credentials in a pod (non-interactive)
kubectl run test-pod --image=alpine -n demo --restart=Never --command -- \
  sh -c 'cat /root/.ssh/id_rsa 2>/dev/null || true'

# Check findings in the report
kubectl get reports -n demo
```

### 🔄 Example 3: Custom Loopback Egress Detection

Use a custom policy to detect suspicious loopback connections (`127.0.0.0/8`) that can indicate SSRF abuse or local pivot behavior inside compromised containers.

**Sample custom policy**:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: detect-loopback-egress
spec:
  validations:
  - name: loopback-ip-egress
    event: tcpconnect
    message: Connection to loopback address detected
    severity: high
    conditions:
    - name: loopback-pattern
      expression: |
        event["dst.ip"].startsWith("127.") ||
        event["dst.ip"] == "::1"
    actions:
    - type: audit
      message: Loopback egress observed - investigate for SSRF or local pivot
```

**Apply the sample custom policy**:

```bash
kubectl apply -f samples/runtimepolicy-loopback-egress-detection.yaml

# Trigger a loopback egress attempt from a pod
kubectl run loopback-egress-test --image=python:3.11-alpine -n demo --restart=Never -- \
  python -c "import socket; socket.create_connection(('127.0.0.1', 8080), 2)" || true

# Check findings and action records
kubectl get reports -n demo
kubectl get reports -n demo -o yaml
```

### 🌐 Example 4: RuntimeBehavior with Allowed Networks

Create a RuntimeBehavior profile with explicit allowed networks for nginx traffic, then deploy nginx in a different namespace and verify an auto-generated RuntimeBehavior appears for it.

**Sample RuntimeBehavior profile**:

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimeBehavior
metadata:
  name: nginx-network-baseline
  namespace: demo
spec:
  workloadSelector:
    matchLabels:
      app: nginx
  mode: monitor
  allow:
    network:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - kubernetes.default.svc:443
    - '*.svc.cluster.local'
```

**Apply the sample RuntimeBehavior profile with allowed networks**:

```bash
kubectl apply -f samples/runtimebehavior-nginx-allowed-networks.yaml

# Deploy nginx in a different namespace (controller-managed Deployment)
kubectl create namespace app-team-a --dry-run=client -o yaml | kubectl apply -f -
kubectl delete deployment nginx -n app-team-a --ignore-not-found=true
kubectl create deployment nginx --image=nginx -n app-team-a
kubectl label deployment nginx app=nginx -n app-team-a --overwrite
kubectl rollout status deployment/nginx -n app-team-a --timeout=180s

# Verify RuntimeBehavior auto-enrollment created a profile for this workload
kubectl get runtimebehaviors -n app-team-a
kubectl get runtimebehavior -n app-team-a -o yaml
```

### 🟢 Example 5: Promote to Enforce Mode and Check Findings

After validating monitor-mode behavior, switch the auto-generated RuntimeBehavior profiles in `app-team-a` to `enforce` and verify findings for out-of-policy network activity.

```bash
# Move auto-generated profiles to enforce mode and set allowed networks
kubectl get runtimebehavior -n app-team-a -l runtime.kyverno.io/managed=true -o name | \
  xargs -I{} kubectl patch -n app-team-a {} --type merge -p '{"spec":{"mode":"enforce","allow":{"network":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","kubernetes.default.svc:443","*.svc.cluster.local"]}}}'

# Create a pod that attempts disallowed network access
kubectl run enforce-test --image=python:3.11-alpine -n app-team-a --labels app=nginx --restart=Never -- \
  python -c "import socket; socket.create_connection(('8.8.8.8', 53), 2)" || true

# Check policy findings after enforce-mode evaluation
kubectl get reports -n app-team-a
kubectl get reports -n app-team-a -o yaml
```

### 🔎 Viewing Findings

All findings are reported in OpenReports `Report` resources:

```bash
# List all findings
kubectl get reports -A

# View detailed findings for a namespace
kubectl get reports -n demo -o yaml

# Watch findings in real-time
kubectl get reports -n demo --watch
```

### 👉 Next Steps

- **Configure policies per namespace**: See [Configuration](docs/users/configuration.md)
- **Explore default policies**: See [Policy Library](docs/users/library.md)
- **Advanced baseline learning**: See [Concepts](docs/users/concepts.md)

## 📚 User Docs

- [Concepts](docs/users/concepts.md)
- [Configuration](docs/users/configuration.md)
- [Policy Library](docs/users/library.md)

## 🛠️ Developer Docs

- [Design](docs/dev/DESIGN.md)
- [Plan](docs/dev/PLAN.md)
