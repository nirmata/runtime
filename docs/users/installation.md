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

The daemon pod runs privileged with `hostPID: true`, which the `baseline` and
`restricted` Pod Security Standards forbid regardless of any future capability
scoping. If the target namespace enforces Pod Security admission, label it
`privileged` before installing:

```bash
kubectl label namespace kyverno-runtime pod-security.kubernetes.io/enforce=privileged --overwrite
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
| `daemon.resources` | `requests: {cpu: 100m, memory: 128Mi}, limits: {memory: 512Mi}` | Container resource requests/limits. No CPU limit avoids CPU quota throttling of the collector loop. |
| `daemon.priorityClassName` | `system-node-critical` | Pod priority class. Empty omits the field. |
| `daemon.nodeSelector` | `{}` | Node selector for the DaemonSet. |
| `daemon.tolerations` | `[]` | Tolerations for the DaemonSet. |
| `daemon.affinity` | `{}` | Affinity rules for the DaemonSet. |
| `daemon.securityContext` | `{privileged: true, runAsUser: 0, readOnlyRootFilesystem: true}` | Container `securityContext`. |
| `daemon.updateStrategy` | `{}` (Kubernetes default `RollingUpdate`) | DaemonSet `spec.updateStrategy`. |
| `daemon.metrics.port` | `9090` | Port the daemon serves `/metrics` and `/healthz` on, passed through `--metrics-addr`. |
| `daemon.observeInterval` | `""` (daemon default `10s`) | Sets `--observe-interval`. |
| `daemon.eventBufferSize` | `""` (daemon default `4096`) | Sets `--event-buffer-size`. |
| `daemon.clusterDomain` | `""` (daemon default `cluster.local`) | Sets `--cluster-domain`, the DNS domain that makes a `network` value a cluster Service name. |
| `daemon.push.target` | `""` (disabled) | Collector address findings are streamed to, `host:port`. Empty opens no connection. |
| `daemon.push.tls.secretName` | `""` | Secret holding `ca.crt`, `tls.crt` and `tls.key` for that connection. Required when `daemon.push.target` is set. |
| `daemon.reports.enabled` | `true` | Write findings to namespaced OpenReports `Report` objects. Set `false` for deployments that consume findings only through `daemon.push.target`. |
| `daemon.events.enabled` | `false` | Emit Kubernetes Events for policy violations and policy errors (see [Kubernetes Events](#kubernetes-events)). Requires `daemon.reports.enabled`; the chart refuses to render otherwise. |
| `daemon.rbac.extraRules` | `[]` | Extra `PolicyRule` entries appended to the ClusterRole. Ignored if `rbac.create` is `false`. |

The default ClusterRole grants only `pods` (get/list/watch), `runtimepolicies` and
`runtimepolicies/status`, and `openreports.io` `reports`/`clusterreports` — it does not
grant access to ConfigMaps or any other resource. Setting `daemon.events.enabled` adds
`events.k8s.io` `events` (create/patch). A `RuntimePolicy` expression that uses
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

## Why the daemon runs privileged

The daemon container sets `securityContext.privileged: true`. It loads and attaches BPF
LSM, raw tracepoint, and cgroup_skb programs — tracing-class program load needs broad
privilege on current kernels — and reads `/proc/<pid>/cgroup` across every process on
the node through `hostPID`, so the chart does not attempt to enumerate a narrower
capability set.

## Health probes

The daemon serves `/healthz` next to `/metrics` on `daemon.metrics.port`. It fails once
the runtime policy informer has not finished its initial sync, or once the event
collector's dispatch loop has gone quiet for longer than expected, and passes otherwise.
The DaemonSet points its `startupProbe` at it, gating the container as started once the
informer sync completes; there is no liveness or readiness probe — a stalled dispatch loop
after startup does not restart the container, and nothing routes traffic to the daemon.

## Daemon flags

| Flag | Default | Set by chart value |
| --- | --- | --- |
| `--log-level` | `0` | not exposed by the chart |
| `--metrics-addr` | `:9090` | `daemon.metrics.port` |
| `--observe-interval` | `10s` | `daemon.observeInterval` |
| `--event-buffer-size` | `4096` | `daemon.eventBufferSize` |
| `--source-restart-backoff` | `5s` | not exposed by the chart |
| `--cluster-domain` | `cluster.local` | `daemon.clusterDomain` |
| `--push-target` | `""` (disabled) | `daemon.push.target` |
| `--push-tls-ca` | `""` | `daemon.push.tls.secretName` |
| `--push-tls-cert` | `""` | `daemon.push.tls.secretName` |
| `--push-tls-key` | `""` | `daemon.push.tls.secretName` |
| `--reports-enabled` | `true` | `daemon.reports.enabled` |
| `--events-enabled` | `false` | `daemon.events.enabled` |

`--cluster-domain` is the suffix that makes a `network` value a cluster Service name rather
than an external one, so a cluster whose DNS domain is not `cluster.local` rejects every
Service target until this matches — see
[cluster Service targets](reference/runtimepolicy.md#cluster-service-targets).

## Streaming findings to a collector

Findings are always written to namespaced OpenReports `Report` objects. A cluster that wants
them live as well can point the daemon at a collector, and every finding is streamed as it is
produced:

```yaml
daemon:
  push:
    target: collector.observability.svc.cluster.local:9443
    tls:
      secretName: kyverno-runtime-push-tls
```

The Secret holds `ca.crt` (the CA that signs the collector's certificate), plus `tls.crt` and
`tls.key` (the client certificate every daemon presents). The connection is mutual TLS with no
plaintext mode, and the chart refuses to render a `target` without the Secret rather than
installing a daemon that exits at boot. The daemon is the client: it dials out and opens no
listening port of its own.

The queue in front of the stream is bounded. A collector that stops reading costs the oldest
queued findings, never the event path, and each drop is counted under
`nirmata_runtime_events_dropped_total{source="pushsink"}` — see
[metrics](reference/metrics.md). Nothing is dropped from the `Report` objects when this happens:
the two paths are independent.

Owner attribution on the wire (`ownerKind`, `ownerName`) is correlation metadata read from the
pod's `ownerReferences`, which Kubernetes does not verify. A receiver must not treat it as an
authenticated identity; restricting who may set `ownerReferences` is a cluster admission-policy
question, not something the daemon can settle.

## Kubernetes Events

Findings and policy status reach `kubectl describe pod` and the Events API only when
`daemon.events.enabled` is set:

```yaml
daemon:
  events:
    enabled: true
```

This emits `PolicyViolation` (Warning) events for enforce-mode violations, `PolicyWouldViolate`
(Normal) events for monitor mode's counterfactual findings, and `PolicyError` (Warning) events
when a `RuntimePolicy`'s `Applied` or `TargetsValid` condition goes `False`. Violation events fire
from the same deduplicated flush that writes a `Report` result — one Event per distinct cause per
flush interval, not one per kernel occurrence — and every Event message passes through the same
redaction boundary as everything else `pkg/reporter` emits.

`daemon.events.enabled` requires `daemon.reports.enabled`: violation events are wired onto the
reporter's flush, so the chart refuses to render the two together with reports disabled. It also
adds `events.k8s.io` `events` (create/patch) to the ClusterRole; leaving it `false` grants no
access to the Events API and writes no Events.

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
