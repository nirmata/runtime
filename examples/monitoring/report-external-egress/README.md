# Report only traffic that leaves the cluster

## What this shows

A `network` monitor policy with `deny.values: ["*"]` reports every destination a pod reaches:
cluster DNS, every Service it calls, and every pod it talks to. The connections an operator
usually wants first are the ones that leave the cluster, and those are a set of addresses no
one can list in advance.

`policy.yaml` observes every destination and narrows the findings with a
[monitorFilter](../../../docs/users/reference/runtimepolicy.md#filtering-monitor-findings)
that uses the Kubernetes `CIDR` library: a finding is reported only if its `event.net.destIP`
falls outside all three RFC 1918 private ranges. Adjust the list to match your pod and Service
CIDRs.

## Requires

Network egress observation requires only a cgroup v2 host and BPF support; a stock kind
cluster on a Linux host qualifies, as does Docker Desktop.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: monitor`, so nothing is ever blocked.

## Run it

1. Start the in-cluster target and the client:

   ```bash
   kubectl apply -f target.yaml
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/egress-target pod/egress-client
   ```

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol report-external-egress
   ```

   `Applied=True` with reason `Monitoring`.

3. Reach one destination inside the cluster and one outside it:

   ```bash
   TARGET=$(kubectl get pod egress-target -o jsonpath='{.status.podIP}')
   kubectl exec egress-client -- wget -q -T 3 -O /dev/null "http://${TARGET}:8080/"
   kubectl exec egress-client -- wget -q -T 5 -O /dev/null http://example.com
   ```

## Verify

Observation is poll-based: counters are drained every `--observe-interval` (10s by default)
and findings are flushed every 10s, so allow about 20 seconds.

```bash
kubectl get report kyverno-runtime-egress-client \
  -o jsonpath='{range .results[?(@.policy=="report-external-egress")]}{.properties.destIP}{"\n"}{end}'
```

Both directions matter:

- **One public address**, the one `example.com` resolved to. It varies by location.
- **No result for `$TARGET`**, and none for the cluster DNS Service the client queried to
  resolve `example.com`. The policy observed both; the filter dropped them.

## Clean up

```bash
kubectl delete rpol report-external-egress
kubectl delete -f client.yaml -f target.yaml
```
