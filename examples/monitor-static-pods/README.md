# Observing a static pod

## What this shows

On a kind cluster the control-plane components — `etcd`, `kube-apiserver`,
`kube-controller-manager`, `kube-scheduler` — are static pods. The kubelet names a static
pod's cgroup directory after its config hash, while the pod object served by the API is a
mirror pod with a separately generated UID. A daemon searching for the cgroup by
`.metadata.uid` finds nothing, so these pods were never attached at all.

This policy selects them (`tier: control-plane` is set by kubeadm on all four) and observes
in `monitor` mode, which never blocks. It is the cheapest way to confirm the daemon can
reach a static pod's cgroup on your cluster.

## Requires

cgroup v2 and BPF — a stock kind cluster qualifies. No BPF-LSM needed.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy runs in `mode: monitor`: matched behavior is reported, never blocked. A default
deny in monitor mode means "report every destination", not "block every destination".

## Run it

```bash
kubectl apply -f policy.yaml
kubectl get rpol monitor-static-pods
```

## Verify

The daemon should report the policy applied, in monitoring mode:

```bash
kubectl get rpol monitor-static-pods -o jsonpath='{.status.conditions}'
```

Observations are drained every 10 seconds and written as OpenReports objects in the
observed pod's namespace:

```bash
kubectl get reports -n kube-system
kubectl get reports -n kube-system -o yaml | grep -A5 'policy: monitor-static-pods'
```

Each result names the pod as its subject, so a result whose subject is
`kube-apiserver-<node>` is proof the cgroup was resolved through the config hash — before
that, the daemon exhausted its requeues on these pods and produced nothing.

Confirm the daemon is not logging cgroup resolution failures for them:

```bash
kubectl logs -n kyverno-runtime -l app.kubernetes.io/name=kyverno-runtime --tail=200 | grep -i cgroup
```

## Clean up

```bash
kubectl delete rpol monitor-static-pods
```
