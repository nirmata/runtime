# Record a workload's baseline without blocking

## What this shows

What does this workload actually do? One policy in `mode: monitor` default-denies all
three behaviors — `network`, `exec` and `open` — which in monitor mode means every
destination, binary and file path the workload touches is reported instead of blocked.
That is how you collect the allow-lists for an enforcing policy from the workload itself
rather than from guesswork.

`evaluationInterval: 30s` re-evaluates the policy on a timer, so pods that come and go
under the selector are picked up without an edit to the `RuntimePolicy`.

Turning this into enforcement means keeping the same `behaviors` and adding the `allow`
entries the report showed, then switching `mode` to `enforce`. Compare
[enforce-workload-baseline](../enforce-workload-baseline/).

## Requires

File `open` and process `exec` enforcement require a kernel booted with BPF-LSM active:
`bpf` must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel boot
parameter). Stock distributions and hosted CI runners are typically not booted with it.

Network egress enforcement and observation require only a cgroup v2 host and BPF support;
a stock kind cluster on a Linux host qualifies.

Without BPF-LSM the `network` findings still appear; the `open` and `exec` behaviors
produce nothing, and the policy carries an `ObservationAvailable=False` condition.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy runs in `mode: monitor`.

## Run it

1. Start the workload and apply the policy:

   ```bash
   kubectl apply -f workload.yaml
   kubectl wait --for=condition=Ready pod/baseline-workload
   kubectl apply -f policy.yaml
   kubectl get rpol monitor-workload-baseline
   ```

   `Applied=True` with reason `Monitoring`.

2. Exercise the workload so there is something to observe — one file read, one binary, one
   outbound connection:

   ```bash
   kubectl exec baseline-workload -- /bin/cat /etc/hosts >/dev/null
   kubectl exec baseline-workload -- /bin/wget -q -T 3 -O /dev/null http://127.0.0.1:8080/
   ```

## Verify

Observation is poll-based: counters are drained every `--observe-interval` (10s by
default) and findings are flushed every 10s, so allow up to ~20 seconds.

```bash
kubectl get reports -A
kubectl get report "kyverno-runtime-$(kubectl get pod baseline-workload -o jsonpath='{.spec.nodeName}')" \
  -o yaml
```

- The workload kept running and every command above succeeded: monitor mode never blocks,
  even though all three behaviors default-deny.
- Results appear with `rule: open` and `rule: exec` (properties include `comm`, the
  observed command name) and with `rule: network` (property `destIP`). Every result
  carries `policy: monitor-workload-baseline`, `count`, `firstTimestamp`, `lastTimestamp`
  and `enforced: "false"`.

Extract the observed paths for the enforcing version of the policy:

```bash
kubectl get report "kyverno-runtime-$(kubectl get pod baseline-workload -o jsonpath='{.spec.nodeName}')" \
  -o jsonpath='{range .results[*]}{.rule}{"\t"}{.description}{"\n"}{end}'
```

A default-denied `open` behavior reports every path the workload reads, which is a lot.
The per-cgroup path map holds 2048 distinct keys per poll interval and the excess is lost,
so treat a single poll as a sample rather than a complete inventory — let the workload run
across several intervals before trusting the list. The authoritative list of what monitor
mode does and does not see is in
[limits of monitor mode](../../docs/users/reference/runtimepolicy.md#limits-of-monitor-mode).

## Clean up

```bash
kubectl delete rpol monitor-workload-baseline
kubectl delete -f workload.yaml
```
