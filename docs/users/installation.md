# Installation

## Requirements

Network egress enforcement and observation require only a cgroup v2 host and BPF
support; a stock kind cluster on a Linux host qualifies.

File `open` and process `exec` enforcement require a kernel booted with BPF-LSM
active: `bpf` must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel
boot parameter). Stock distributions and hosted CI runners are typically not booted
with it.

Also required: Linux nodes, and BTF at `/sys/kernel/btf/vmlinux` for CO-RE relocation
when the daemon loads its eBPF programs.

Check the node before installing:

```bash
stat -fc %T /sys/fs/cgroup       # must print cgroup2fs
cat /sys/kernel/security/lsm     # must contain "bpf" for open/exec enforcement
test -r /sys/kernel/btf/vmlinux && echo "BTF present"
```

## Install

The chart is published to GHCR as an OCI artifact. There is no chart repository to add.

```bash
helm install kyverno-runtime oci://ghcr.io/nirmata/charts/kyverno-runtime \
  --namespace kyverno-runtime --create-namespace
```

Helm resolves the newest published version. Pin one with `--version <x.y.z>`, and list
what is available with:

```bash
helm show chart oci://ghcr.io/nirmata/charts/kyverno-runtime
```

If the GHCR package is not public, authenticate first with a token that has `read:packages`:

```bash
echo "$GITHUB_TOKEN" | helm registry login ghcr.io -u <your-username> --password-stdin
```

The chart ships the CRDs in `crds/`, which Helm applies on first install. Helm does not
upgrade CRDs on a subsequent `helm upgrade`, so apply them yourself when a release changes
the API:

```bash
helm pull oci://ghcr.io/nirmata/charts/kyverno-runtime --untar
kubectl apply -f kyverno-runtime/crds
```

Tooling for the from-source paths below: Docker, [kind](https://kind.sigs.k8s.io/),
`kubectl`, `helm`, `git`, `make`, Go 1.26+, and [ko](https://ko.build/).

### From source, on a kind cluster

```bash
git clone https://github.com/nirmata/runtime.git
cd kyverno-runtime
make kind
```

`make kind` creates a kind cluster named `kyverno-runtime`, then builds the daemon image
with `ko`, loads it into the cluster, applies the CRDs from `charts/kyverno-runtime/crds`,
and runs `helm upgrade --install kyverno-runtime ./charts/kyverno-runtime --namespace
kyverno-runtime --create-namespace --wait`.

### Into an existing cluster, from the chart in this tree

```bash
kubectl apply -f ./charts/kyverno-runtime/crds
helm upgrade --install kyverno-runtime ./charts/kyverno-runtime \
  --namespace kyverno-runtime --create-namespace \
  --set image.repository=<your-repository> \
  --set image.tag=<your-tag>
```

Use this when running a daemon image you built yourself; the published chart above
defaults to `ghcr.io/nirmata/kyverno-runtime`.

## Chart values

| Value | Default | Purpose |
| --- | --- | --- |
| `image.repository` | `ghcr.io/nirmata/kyverno-runtime` | Daemon image. |
| `image.tag` | `""` (chart `appVersion`) | Image tag; empty uses the chart's `appVersion`. |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `serviceAccount.create` | `true` | Create a ServiceAccount for the daemon. |
| `serviceAccount.name` | `""` (generated) | Override the generated ServiceAccount name. |
| `rbac.create` | `true` | Create the ClusterRole and ClusterRoleBinding. |
| `daemon.podLabels` | `{}` | Extra labels on the daemon pod. |
| `daemon.podAnnotations` | `{}` | Extra annotations on the daemon pod. |
| `daemon.resources` | `{}` | Container resource requests/limits. |
| `daemon.nodeSelector` | `{}` | Node selector for the DaemonSet. |
| `daemon.tolerations` | `[]` | Tolerations for the DaemonSet. |
| `daemon.affinity` | `{}` | Affinity rules for the DaemonSet. |
| `daemon.metrics.port` | `9090` | Port the daemon serves `/metrics` on, passed through `--metrics-addr`. |
| `daemon.observeInterval` | `""` (daemon default `10s`) | Sets `--observe-interval`. |
| `daemon.eventBufferSize` | `""` (daemon default `4096`) | Sets `--event-buffer-size`. |
| `daemon.clusterDomain` | `""` (daemon default `cluster.local`) | Sets `--cluster-domain`, the DNS domain that makes a `network` value a cluster Service name. |
| `daemon.rbac.extraRules` | `[]` | Extra `PolicyRule` entries appended to the ClusterRole. Ignored if `rbac.create` is `false`. |

The default ClusterRole grants only `pods` (get/list/watch), `runtimepolicies` and
`runtimepolicies/status`, and `openreports.io` `reports`/`clusterreports` — it does not
grant access to ConfigMaps or any other resource. A `RuntimePolicy` expression that uses
the `resource` CEL library to read a ConfigMap or another CRD needs that access added
through `daemon.rbac.extraRules`:

```yaml
daemon:
  rbac:
    extraRules:
    - apiGroups: [""]
      resources: ["configmaps"]
      verbs: ["get", "list", "watch"]
```

## Daemon flags

| Flag | Default | Set by chart value |
| --- | --- | --- |
| `--log-level` | `0` | not exposed by the chart |
| `--metrics-addr` | `:9090` | `daemon.metrics.port` |
| `--observe-interval` | `10s` | `daemon.observeInterval` |
| `--event-buffer-size` | `4096` | `daemon.eventBufferSize` |
| `--source-restart-backoff` | `5s` | not exposed by the chart |
| `--cluster-domain` | `cluster.local` | `daemon.clusterDomain` |

`--cluster-domain` is the suffix that makes a `network` value a cluster Service name rather
than an external one, so a cluster whose DNS domain is not `cluster.local` rejects every
Service target until this matches — see
[cluster Service targets](reference/runtimepolicy.md#cluster-service-targets).

## Verify the install

```bash
kubectl get pods -n kyverno-runtime
kubectl get ds -n kyverno-runtime
kubectl get crd runtimepolicies.runtime.nirmata.io
kubectl get crd reports.openreports.io
kubectl get crd clusterreports.openreports.io
```

Apply a trivial policy and confirm the daemon picks it up:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: verify-install
spec:
  mode: monitor
  behaviors:
  - network:
      deny:
        values:
        - "127.0.0.1"
```

```bash
kubectl apply -f verify-install.yaml
kubectl get rpol verify-install
```

`Applied` should show `True` once a node's daemon has loaded the policy.

## Uninstall

```bash
helm uninstall kyverno-runtime --namespace kyverno-runtime
```

Helm does not remove CRDs on uninstall. The `RuntimePolicy` and OpenReports CRDs
shipped in `charts/kyverno-runtime/crds/` stay installed; delete them explicitly if you
want them gone:

```bash
kubectl delete crd runtimepolicies.runtime.nirmata.io reports.openreports.io clusterreports.openreports.io
```
