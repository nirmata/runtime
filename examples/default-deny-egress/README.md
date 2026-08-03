# Default-deny egress with one approved destination

## What this shows

Contain a pod so it can only reach one approved service. `deny.values: ["*"]` on the
`network` behavior is the default-deny sentinel: it flips egress from
allow-all-except-denied to deny-all-except-allowed, and the `allow` list then names the
only destinations the pod may still reach. The sentinel is evaluated across every
`RuntimePolicy` matching a pod, so one policy setting it is enough to narrow the pod's
egress, and the effective allow list is the union of the `allow` entries of all matching
policies.

Two identical HTTP servers are used as targets and only one of them is allow-listed, so
the only difference between "reachable" and "not reachable" is the eBPF map state — not
DNS, not a Service, not the cluster network.

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support;
a stock kind cluster on a Linux host qualifies.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy runs in `mode: enforce`.

## Run it

1. Start the two targets and the client:

   ```bash
   kubectl apply -f targets.yaml
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/egress-target-allowed pod/egress-target-denied pod/egress-client
   ```

2. Record the target pod IPs and confirm both are reachable before any policy exists.
   If this step fails, the "blocked" result below would prove nothing:

   ```bash
   ALLOWED=$(kubectl get pod egress-target-allowed -o jsonpath='{.status.podIP}')
   DENIED=$(kubectl get pod egress-target-denied -o jsonpath='{.status.podIP}')
   kubectl exec egress-client -- wget -q -T 3 -O /dev/null "http://${ALLOWED}:8080/" && echo baseline-allowed-ok
   kubectl exec egress-client -- wget -q -T 3 -O /dev/null "http://${DENIED}:8080/" && echo baseline-denied-ok
   ```

3. Pod IPs are assigned at scheduling time, so the allow-listed address cannot be written
   into a committed manifest. `policy.tmpl.yaml` carries the placeholder `ALLOWED_IP`;
   substitute it and apply:

   ```bash
   sed "s/ALLOWED_IP/${ALLOWED}/" policy.tmpl.yaml | kubectl apply -f -
   kubectl get rpol default-deny-egress
   ```

   `kubectl get rpol` shows `Applied=True` with reason `Enforcing` once the daemon has
   programmed the pod's egress maps.

## Verify

Both directions matter. A check that only asserts the denied target is unreachable would
also pass against a program that drops every packet.

```bash
kubectl exec egress-client -- wget -q -T 3 -O /dev/null "http://${DENIED}:8080/"; echo "denied exit=$?"
kubectl exec egress-client -- wget -q -T 3 -O /dev/null "http://${ALLOWED}:8080/"; echo "allowed exit=$?"
```

- `denied exit=1` — the packets are dropped in the kernel and `wget` gives up after its
  3-second timeout. The daemon programs maps on its own schedule, so allow a few seconds
  after applying the policy before the first attempt fails.
- `allowed exit=0` — the allow-listed destination still answers under default deny.

## Clean up

```bash
kubectl delete rpol default-deny-egress
kubectl delete -f client.yaml -f targets.yaml
```
