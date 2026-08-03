# Default-deny egress to a domain name

## What this shows

A `network` value that is a fully qualified domain name rather than an address. Nothing
about the name is resolved when the policy is written: the daemon attaches a second eBPF
program to the matched pod's cgroup, that program reads the pod's own DNS answers, and an A
record for a name the policy allows makes that address allowed for that pod. The pod learns
the destination's address in the same moment the kernel does, which is what makes this
usable for destinations whose addresses change under you.

The `kube-dns` reference in the allow list is not incidental. Under default deny a workload
that cannot reach its resolver resolves nothing, the snooper never sees an answer, and every
domain in the allow list is dead — the pod's egress is fully closed and the policy looks
broken. Cluster DNS has to be allowed alongside the name, and `serviceRefs` is how, since
the resolver's addresses are not something a policy author should be pinning by hand.

The name here is another Service in the cluster, so the example runs on a kind cluster with
no internet egress. That means the policy is coupled to the `default` namespace: change the
namespace and the name in `policy.yaml` changes with it.

## This is not a containment boundary

A domain allow list names destinations conveniently. It does not contain a workload that
does not want to be contained. The snooper reads unencrypted UDP/53 answers, so a resolver
reached over TCP/53, DNS over TLS or DNS over HTTPS is invisible to it, and so is a client
that skips resolution and connects to a hardcoded address. Under default deny those cases
are blocked rather than allowed, but a deny list built from names is bypassable outright.
There are no wildcards, and learned addresses expire by LRU eviction rather than by TTL.

Read [limits of domain names](../../docs/users/reference/runtimepolicy.md#limits-of-domain-names)
before relying on this. A workload that must be contained needs its destinations named as
addresses or as
[serviceRefs](../../docs/users/reference/runtimepolicy.md#service-references).

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support; a
stock kind cluster on a Linux host qualifies. BPF-LSM is not needed.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy runs in `mode: enforce`.

The allowed value is `dns-target-allowed.default.svc.cluster.local`, so apply the manifests
in the `default` namespace.

## Run it

1. Start the two named targets and the client:

   ```bash
   kubectl apply -f targets.yaml -f client.yaml
   kubectl wait --for=condition=Ready pod/dns-target-allowed pod/dns-target-denied pod/dns-client --timeout=90s
   ```

2. Confirm the client resolves and reaches both names before any policy exists. If this
   step fails, the "blocked" result below would prove nothing:

   ```bash
   kubectl exec dns-client -- wget -q -T 3 -O /dev/null "http://dns-target-allowed.default.svc.cluster.local:8080/"; echo "baseline allowed exit=$?"
   kubectl exec dns-client -- wget -q -T 3 -O /dev/null "http://dns-target-denied.default.svc.cluster.local:8080/"; echo "baseline denied exit=$?"
   ```

   Both print `exit=0`.

3. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol egress-to-domain-name
   ```

   `Applied=True` with reason `Enforcing` once the daemon has programmed the pod's egress
   maps.

4. Check that the name and the resolver reference were both programmable. A name that was
   rejected also produces "blocked", which would make the verification pass for the wrong
   reason:

   ```bash
   kubectl get rpol egress-to-domain-name -o jsonpath='{.status.conditions}'
   ```

   `TargetsValid=True` with reason `AllTargetsSupported`.

## Verify

Both directions matter. A policy that dropped every packet would also pass the "blocked"
check on its own.

```bash
kubectl exec dns-client -- wget -q -T 3 -O /dev/null "http://dns-target-allowed.default.svc.cluster.local:8080/"; echo "allowed exit=$?"
kubectl exec dns-client -- wget -q -T 3 -O /dev/null "http://dns-target-denied.default.svc.cluster.local:8080/"; echo "denied exit=$?"
```

- `allowed exit=0` — the name resolved, the answered address was written into the pod's
  learned-address map, and the connection to it was permitted. Reaching it at all also
  proves the `kube-dns` reference took effect.
- `denied exit=1` — the other name resolves just as well, and the address it answers with
  is dropped in the kernel. The daemon programs maps on its own schedule, so allow a few
  seconds after applying the policy before the first attempt fails.

Only the answered address is allowed, not everything behind the Service. The allowed
target's own pod IP was never in a DNS answer for the allowed name, so it stays blocked:

```bash
BACKEND=$(kubectl get pod dns-target-allowed -o jsonpath='{.status.podIP}')
kubectl exec dns-client -- wget -q -T 3 -O /dev/null "http://${BACKEND}:8080/"; echo "backend exit=$?"
```

`backend exit=1`. This is the visible difference between a domain name and a `serviceRefs`
entry, which would have programmed the endpoint addresses too.

## Clean up

```bash
kubectl delete rpol egress-to-domain-name
kubectl delete -f targets.yaml -f client.yaml
```
