# Default-deny egress with destinations named as cluster Services

## What this shows

The workload may reach cluster DNS and an egress gateway, and nothing else. The allow list
holds no addresses at all: it names `kube-dns.kube-system.svc.cluster.local` and the
gateway's own cluster DNS name, and the daemon resolves each to its ClusterIP plus the
addresses of its ready endpoints from Service and EndpointSlice informers. Scaling, rolling
or replacing the gateway's backends re-programs the maps with no policy edit and no
`evaluationInterval` — the informers drive it.

A value in the form `<service>.<namespace>.svc.cluster.local` is resolved this way. Any
other fully qualified domain name is an external destination, learned from the pod's own
DNS answers instead. `RuntimePolicy` is cluster scoped, so the namespace is part of every
Service name here rather than implied by where the policy lives.

Write the name in full. A short form such as `egress-gateway.egress-gateway` is a valid
external name and silently matches nothing: the pod's resolver expands it through its
search domains and asks for the four-label name the policy never mentioned.

What the policy does not name matters as much as what it does. The `kubernetes` Service is
absent, so the API server is unreachable from these pods: a token stolen out of the pod
cannot be used from inside it. Nothing in the policy mentions the API server; it is denied
because the allow list is closed.

A gateway and a client are both deployed here because a name whose Service does not exist
resolves to nothing, which under default deny blocks the destination outright — that is the
unresolved-Service failure, not this feature. The full set of constraints is in
[limits of cluster Service targets](../../../docs/users/reference/runtimepolicy.md#limits-of-cluster-service-targets),
and the one worth reading before you rely on this shape is that allowing a Service allows
every port on the addresses it resolves to.

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support; a
stock kind cluster on a Linux host qualifies. BPF-LSM is not needed.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: enforce`.

The names in `policy.yaml` end in `cluster.local`, the daemon's default cluster domain. On a
cluster whose DNS domain differs, the names change with it and the daemon needs
`--cluster-domain` set to match.

The gateway manifest creates the `egress-gateway` namespace. The client and the control
target go wherever your current context points; the policy selects the client by label, not
by namespace.

## Run it

1. Start the gateway, the control target and the client:

   ```bash
   kubectl apply -f gateway.yaml
   kubectl apply -f target.yaml -f client.yaml
   kubectl -n egress-gateway rollout status deployment/egress-gateway --timeout=90s
   kubectl wait --for=condition=Ready pod/unlisted-target pod/gateway-client --timeout=90s
   ```

2. Record the two addresses the verification uses and confirm all three destinations are
   reachable before any policy exists. If this step fails, the "blocked" results below would
   prove nothing:

   ```bash
   DENIED=$(kubectl get pod unlisted-target -o jsonpath='{.status.podIP}')
   APISERVER=$(kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}')
   kubectl exec gateway-client -- wget -q -T 3 -O /dev/null "http://egress-gateway.egress-gateway.svc.cluster.local:8080/"; echo "baseline gateway exit=$?"
   kubectl exec gateway-client -- wget -q -T 3 -O /dev/null "http://${DENIED}:8080/"; echo "baseline unnamed exit=$?"
   kubectl exec gateway-client -- nc -z -w 3 "${APISERVER}" 443; echo "baseline apiserver exit=$?"
   ```

   All three print `exit=0`.

3. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol egress-to-cluster-service
   ```

   `Applied=True` with reason `Enforcing` once the daemon has programmed the pod's egress
   maps.

4. Check that both names resolved. A name whose Service is not in the daemon's cache
   contributes no addresses and is reported here, and under default deny it looks identical
   to a network outage from inside the workload:

   ```bash
   kubectl get rpol egress-to-cluster-service -o jsonpath='{.status.conditions}'
   ```

   `TargetsValid=True` with reason `AllTargetsSupported`. A `TargetsValid=False` with
   `UnresolvedServices` names the value that did not resolve, and nothing below is worth
   reading until it does.

## Verify

Three checks, because a one-sided result is not evidence. A policy that dropped every
packet would also pass the two "blocked" checks.

```bash
kubectl exec gateway-client -- wget -q -T 3 -O /dev/null "http://egress-gateway.egress-gateway.svc.cluster.local:8080/"; echo "gateway exit=$?"
kubectl exec gateway-client -- wget -q -T 3 -O /dev/null "http://${DENIED}:8080/"; echo "unnamed exit=$?"
kubectl exec gateway-client -- nc -z -w 3 "${APISERVER}" 443; echo "apiserver exit=$?"
```

- `gateway exit=0` — the named Service still answers under default deny. It was reached by
  name, which also proves the `kube-dns` value took effect: without it the lookup would fail
  and this would be a false negative.
- `unnamed exit=1` — the control address is dropped in the kernel and `wget` gives up after
  its 3-second timeout. The daemon programs maps on its own schedule, so allow a few seconds
  after applying the policy before the first attempt fails.
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
kubectl delete rpol egress-to-cluster-service
kubectl delete -f target.yaml -f client.yaml
kubectl delete -f gateway.yaml
```
