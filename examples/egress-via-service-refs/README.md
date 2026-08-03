# Default-deny egress with destinations named as Services

## What this shows

The workload may reach cluster DNS and an egress gateway, and nothing else. The allow list
holds no addresses at all: `allow.serviceRefs` names `kube-dns` in `kube-system` and the
gateway Service in its own namespace, and the daemon resolves each to its ClusterIP plus
the addresses of its ready endpoints from Service and EndpointSlice informers. Scaling,
rolling or replacing the gateway's backends re-programs the maps with no policy edit and no
`evaluationInterval` — the informers drive it.

What the policy does not name matters as much as what it does. The `kubernetes` Service is
absent, so the API server is unreachable from these pods: a token stolen out of the pod
cannot be used from inside it. Nothing in the policy mentions the API server; it is denied
because the allow list is closed.

`RuntimePolicy` is cluster scoped, so each reference carries its `namespace` rather than
inheriting one.

A gateway and a client are both deployed here because a reference to a Service that does
not exist resolves to nothing, which under default deny blocks the destination outright —
that is the unresolved-reference failure, not this feature. The full set of constraints is
in [limits of serviceRefs](../../docs/users/reference/runtimepolicy.md#limits-of-servicerefs),
and the one worth reading before you rely on this shape is that allowing a Service allows
every port on the addresses it resolves to.

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support; a
stock kind cluster on a Linux host qualifies. BPF-LSM is not needed.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy runs in `mode: enforce`.

The gateway manifest creates the `egress-gateway` namespace. The client and the control
target go wherever your current context points; the policy selects the client by label, not
by namespace.

## Run it

1. Start the gateway, the control target and the client:

   ```bash
   kubectl apply -f gateway.yaml
   kubectl apply -f target.yaml -f client.yaml
   kubectl -n egress-gateway rollout status deployment/egress-gateway --timeout=90s
   kubectl wait --for=condition=Ready pod/unreferenced-target pod/gateway-client --timeout=90s
   ```

2. Record the two addresses the verification uses and confirm all three destinations are
   reachable before any policy exists. If this step fails, the "blocked" results below would
   prove nothing:

   ```bash
   DENIED=$(kubectl get pod unreferenced-target -o jsonpath='{.status.podIP}')
   APISERVER=$(kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}')
   kubectl exec gateway-client -- wget -q -T 3 -O /dev/null "http://egress-gateway.egress-gateway.svc.cluster.local:8080/"; echo "baseline gateway exit=$?"
   kubectl exec gateway-client -- wget -q -T 3 -O /dev/null "http://${DENIED}:8080/"; echo "baseline unreferenced exit=$?"
   kubectl exec gateway-client -- nc -z -w 3 "${APISERVER}" 443; echo "baseline apiserver exit=$?"
   ```

   All three print `exit=0`.

3. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol egress-via-service-refs
   ```

   `Applied=True` with reason `Enforcing` once the daemon has programmed the pod's egress
   maps.

4. Check that both references resolved. An unresolved reference contributes no addresses
   and is reported here, and under default deny it looks identical to a network outage from
   inside the workload:

   ```bash
   kubectl get rpol egress-via-service-refs -o jsonpath='{.status.conditions}'
   ```

   `TargetsValid=True` with reason `AllTargetsSupported`. A `TargetsValid=False` with
   `UnresolvedServiceRefs` names the reference that did not resolve, and nothing below is
   worth reading until it does.

## Verify

Three checks, because a one-sided result is not evidence. A policy that dropped every
packet would also pass the two "blocked" checks.

```bash
kubectl exec gateway-client -- wget -q -T 3 -O /dev/null "http://egress-gateway.egress-gateway.svc.cluster.local:8080/"; echo "gateway exit=$?"
kubectl exec gateway-client -- wget -q -T 3 -O /dev/null "http://${DENIED}:8080/"; echo "unreferenced exit=$?"
kubectl exec gateway-client -- nc -z -w 3 "${APISERVER}" 443; echo "apiserver exit=$?"
```

- `gateway exit=0` — the referenced Service still answers under default deny. It was
  reached by name, which also proves the `kube-dns` reference took effect: without it the
  lookup would fail and this would be a false negative.
- `unreferenced exit=1` — the control address is dropped in the kernel and `wget` gives up
  after its 3-second timeout. The daemon programs maps on its own schedule, so allow a few
  seconds after applying the policy before the first attempt fails.
- `apiserver exit=1` — the API server, denied by omission.

The gateway's backend pod IP is reachable too, since resolution programs the endpoint
addresses alongside the ClusterIP:

```bash
BACKEND=$(kubectl -n egress-gateway get pod -l app=egress-gateway -o jsonpath='{.items[0].status.podIP}')
kubectl exec gateway-client -- wget -q -T 3 -O /dev/null "http://${BACKEND}:8080/"; echo "backend exit=$?"
```

`backend exit=0`. Both are programmed because which one the kernel matches depends on where
the client's traffic is DNATed, and the grant is therefore "may talk to this Service's
addresses" rather than "may talk to this Service".

## Clean up

```bash
kubectl delete rpol egress-via-service-refs
kubectl delete -f target.yaml -f client.yaml
kubectl delete -f gateway.yaml
```
