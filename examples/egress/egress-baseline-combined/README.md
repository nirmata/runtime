# Every way to name an egress destination, in one policy

## What this shows

One `RuntimePolicy` using every network-side feature at once, so the interactions are
visible rather than described:

| Feature | Where it appears |
| --- | --- |
| Default deny | `network.deny.values: ["*"]` |
| Literal address | via `variables.approvedAppliances` |
| CEL `expression` | `network.allow.expression`, unioned with `values` |
| Named variable | `spec.variables[0]`, referenced as `variables.<name>` |
| Domain name | `combined-allowed.default.svc.cluster.local` in `values` |
| Service reference | `combined-gateway`, and `kube-dns` |
| Application protocol | the second behavior, `protocol` |
| Re-evaluation | `spec.evaluationInterval: 30s` |

**`network` and `protocol` are separate behaviors that AND together.** A connection must
pass both: reaching an allow-listed address over a disallowed protocol is denied, and
speaking an allowed protocol to an address nobody allowed is denied.

## The DNS trap this example exists to show

`protocol` classifies *every* flow, including UDP, and a protocol default deny covers all
of it. A policy that allows only `http/1.1` therefore blocks the pod's own name resolution
— at which point the domain name in the `network` allow list can never be learned, and the
Service references are the only thing still reachable.

That is why `dns` is in the protocol allow list here. It is a specific grant, not a
catch-all: it matches cleartext DNS over UDP, recognized by the query's shape rather than
by port. A resolver pinned to DNS-over-TLS would need `tls` (or `tls/dot`) instead, and a
workload that skips resolution entirely needs neither.

Traffic matching no signature classifies as `unclassified`, which is **not** a policy
value — findings and metrics report it, but no `allow` entry can cover it. Under the
default deny here it is denied, and there is no third option. The
[protocol-default-deny](../protocol-default-deny/) example shows that case on its own,
with a client that connects by address and needs no resolver.

## Requires

cgroup v2 and BPF — a stock kind cluster qualifies. No BPF-LSM needed. Cluster DNS must be
running.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: enforce`, and hardcodes the `default` namespace.

## Run it

1. Start three backends (an allow-listed one, a gateway named by reference, and one that
   nothing names) plus the client:

   ```bash
   kubectl apply -f backends.yaml -f client.yaml
   kubectl wait --for=condition=Ready \
     pod/combined-allowed-backend pod/combined-gateway-backend pod/combined-denied-backend pod/combined-client
   ```

2. Confirm all three answer before any policy exists:

   ```bash
   for s in combined-allowed combined-gateway combined-denied; do
     kubectl exec combined-client -- wget -q -T 3 -O /dev/null "http://${s}/" && echo "baseline ${s} ok"
   done
   ```

3. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol egress-baseline-combined
   kubectl get rpol egress-baseline-combined -o jsonpath='{.status.conditions}'
   ```

   `192.0.2.10` is a documentation address with nothing behind it — it is in the policy to
   show `expression` and `variables` working, and it should appear as a programmed target
   with no effect on reachability, not as a rejected one.

## Verify

Destination scoping, from the `network` behavior:

```bash
kubectl exec combined-client -- wget -q -T 3 -O /dev/null http://combined-allowed/;  echo "by domain exit=$?"
kubectl exec combined-client -- wget -q -T 3 -O /dev/null http://combined-gateway/;  echo "by serviceRef exit=$?"
kubectl exec combined-client -- wget -q -T 3 -O /dev/null http://combined-denied/;   echo "unnamed exit=$?"
```

Expect `0`, `0`, `1`. The first two are reachable by two different mechanisms — a name the
DNS snooper learned, and a reference resolved from the informers — and the third is
reachable by neither.

Protocol scoping, from the `protocol` behavior, against a destination the network behavior
already allows:

```bash
GATEWAY=$(kubectl get svc combined-gateway -o jsonpath='{.spec.clusterIP}')
kubectl exec combined-client -- sh -c "echo 'SSH-2.0-demo' | nc -w 3 ${GATEWAY} 80"; echo "ssh to allowed dest exit=$?"
```

Expect `1`. The address passes `network`, and the connection still dies because `ssh` is
not in the protocol allow list. That is the AND: passing one behavior is not enough.

## Clean up

```bash
kubectl delete rpol egress-baseline-combined
kubectl delete -f client.yaml -f backends.yaml
```
