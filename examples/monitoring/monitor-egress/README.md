# Audit egress without blocking it

## What this shows

Where does this workload actually connect? `mode: monitor` attaches the same egress
program as `mode: enforce` but leaves the kernel maps empty, so nothing is ever blocked.
The daemon drains the program's destination counters, evaluates the policy's lists in
userspace, and writes each match as a result in an OpenReports `Report`.

The policy default-denies (`deny.values: ["*"]`) with no allow list, which in monitor mode
means every destination the pod touches is reported. That is the audit you want before
turning the same policy into `mode: enforce`.

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support;
a stock kind cluster on a Linux host qualifies.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: monitor`.

## Run it

1. Start the target and the client:

   ```bash
   kubectl apply -f target.yaml
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/egress-target pod/egress-client
   ```

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol monitor-egress
   ```

   `Applied=True` with reason `Monitoring`.

3. Make the client connect somewhere:

   ```bash
   TARGET=$(kubectl get pod egress-target -o jsonpath='{.status.podIP}')
   kubectl exec egress-client -- wget -q -T 3 -O /dev/null "http://${TARGET}:8080/"; echo "exit=$?"
   ```

## Verify

Two things have to be true: the connection succeeded, and it was still reported.

- `exit=0` above. Monitor mode never blocks, even under a default-deny list that would
  block everything in `mode: enforce`.
- A Report names the destination. Observation is poll-based: counters are drained every
  `--observe-interval` (10s by default) and findings are flushed every 10s, so allow up to
  ~20 seconds.

  ```bash
  kubectl get reports -A
  kubectl get report kyverno-runtime-egress-client \
    -o yaml
  ```

  One result carries `policy: monitor-egress`, `rule: network`, `result: fail`,
  `subjects[0]` naming `egress-client`, and properties including `destIP` equal to
  `$TARGET`, a `count`, and `enforced: "false"` — the finding is a counterfactual, not a
  record of a block.

- The daemon counted the finding:

  ```bash
  DAEMON=$(kubectl -n kyverno-runtime get pod -l app.kubernetes.io/name=kyverno-runtime \
    -o jsonpath='{.items[0].metadata.name}')
  kubectl -n kyverno-runtime port-forward "$DAEMON" 9090:9090 &
  curl -s localhost:9090/metrics | grep nirmata_runtime_findings_emitted_total
  ```

Monitor mode reports destination IPv4 addresses only — no ports, no protocols, no DNS
names or TLS server names. See
[limits of monitor mode](../../../docs/users/reference/runtimepolicy.md#limits-of-monitor-mode).

## Clean up

```bash
kubectl delete rpol monitor-egress
kubectl delete -f client.yaml -f target.yaml
```
