# Quickstart

Block a pod's network egress to a specific address, in the kernel, on a throwaway kind
cluster. Five steps, and the only long wait is building the daemon image.

This is the path that runs on any Linux host, which is why it is the quickstart. The
`open` and `exec` samples enforce the same way but need a BPF-LSM kernel — see
[block reads of credential files](../../examples/files-and-processes/deny-sensitive-file-access/).

## Prerequisites

- Docker, [kind](https://kind.sigs.k8s.io/), `kubectl`, `helm`, `git`, `make`,
  Go 1.26+, and [ko](https://ko.build/).
- Network egress enforcement and observation require only a cgroup v2 host and BPF
  support; a stock kind cluster on a Linux host qualifies.

Nothing here needs BPF-LSM. File `open` and process `exec` do not require it either, but
they behave slightly differently without it — see [platform support](platforms.md).

## 1. Create a cluster and install

```bash
git clone https://github.com/nirmata/runtime.git
cd kyverno-runtime
make kind
```

`make kind` creates a kind cluster named `kyverno-runtime`, builds the daemon image and
loads it into the cluster, applies the CRDs, and installs the chart from
`charts/kyverno-runtime` with `helm --wait`. See
[installation](installation.md) for installing into an existing cluster.

One DaemonSet pod per node should be running:

```bash
kubectl get pods -n kyverno-runtime
```

## 2. Run a workload

Start a client and two HTTP servers. The rest of the commands run from the example's
directory, so they match
[`examples/egress/block-known-bad-egress/`](../../examples/egress/block-known-bad-egress/) exactly:

```bash
cd examples/egress/block-known-bad-egress
kubectl apply -f client.yaml -f targets.yaml
kubectl wait --for=condition=Ready pod/egress-client pod/egress-target-denied pod/egress-target-allowed --timeout=90s
```

The two servers are identical and serve `ok` on port 8080. One of their addresses goes
into the deny list and the other does not, so the only difference between them will be the
eBPF map state. Record both addresses and confirm the client can reach each one:

```bash
DENIED=$(kubectl get pod egress-target-denied -o jsonpath='{.status.podIP}')
ALLOWED=$(kubectl get pod egress-target-allowed -o jsonpath='{.status.podIP}')
kubectl exec egress-client -- wget -q -T 3 -O - "http://$DENIED:8080/"
kubectl exec egress-client -- wget -q -T 3 -O - "http://$ALLOWED:8080/"
```

Both print `ok`.

## 3. Apply the policy

`policy.tmpl.yaml` denies egress to one address, for pods carrying the label the client pod
has, in `enforce` mode. Egress matches on destination IPv4 address, and a pod's address is
only known once it is running, so one `sed` fills it in:

```bash
sed "s/DENIED_IP/$DENIED/" policy.tmpl.yaml | kubectl apply -f -
kubectl get rpol block-known-bad-egress
```

The applied policy is this, with `DENIED_IP` replaced:

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

```text
NAME                     MODE      APPLIED   REASON      AGE
block-known-bad-egress   enforce   True      Enforcing   20s
```

`APPLIED=True` with reason `Enforcing` means a daemon has the policy loaded and is
blocking on it. `rpol` is the short name for `RuntimePolicy`, which is cluster-scoped.

## 4. See the block

```bash
kubectl exec egress-client -- wget -q -T 3 -O - "http://$DENIED:8080/"
echo "exit=$?"
```

This prints a non-zero `exit=` and no `ok`. The daemon programs the kernel map on its own
schedule, so retry for a few seconds if the first attempt still prints `ok`.

The control address, which the policy does not deny, still answers:

```bash
kubectl exec egress-client -- wget -q -T 3 -O - "http://$ALLOWED:8080/"
```

That second check is the one that matters: a policy that broke all networking would also
pass the first.

What changed: the daemon attached a `cgroup_skb/egress` program to the client pod's
cgroup and put the denied address into its destination map, so the packet is dropped in
the kernel before it leaves the node. No CNI, iptables rule, or sidecar is involved, and
nothing about the pod spec changed.

## 5. Watch instead of block

The same policy can report what a workload does instead of blocking it. Flip the mode:

```bash
kubectl patch rpol block-known-bad-egress --type merge -p '{"spec":{"mode":"monitor"}}'
```

The request now succeeds again, because `monitor` attaches the same programs with empty
deny maps:

```bash
kubectl exec egress-client -- wget -q -T 3 -O - "http://$DENIED:8080/"
```

Within about twenty seconds (a 10s counter poll plus a 10s finding flush) the match shows
up as an [OpenReports](https://openreports.io) `Report` in the client pod's namespace, one
per pod, named `kyverno-runtime-<podName>`:

```bash
kubectl get reports -A
kubectl get reports -n default -o yaml
```

Each result names the policy, the behavior as its `rule`, the offending pod as its
subject, and carries the destination address and an occurrence count.
[`examples/monitoring/monitor-egress/`](../../examples/monitoring/monitor-egress/) is the full monitor-mode
walkthrough.

## Clean up

```bash
kubectl delete -f client.yaml -f targets.yaml
kubectl delete rpol block-known-bad-egress
kind delete cluster --name kyverno-runtime
```

## Next steps

- [Concepts](concepts.md) — what the eBPF programs see, how allow and deny compose, and
  what monitor mode cannot observe.
- [Examples](examples.md) — the full catalog, including `open` and `exec` policies and
  deny lists sourced from ConfigMaps and HTTP feeds.
- [RuntimePolicy reference](reference/runtimepolicy.md) — every field, condition, and
  limit.
- [Troubleshooting](troubleshooting.md) — start here if nothing is blocked.
