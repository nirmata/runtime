# Default-deny egress to a domain name

## What this shows

A `network` value that is a fully qualified domain name rather than an address. Nothing
about the name is resolved when the policy is written: the daemon attaches a second eBPF
program to the matched pod's cgroup, that program reads the pod's own DNS answers, and an A
record for a name the policy allows makes that address allowed for that pod. The pod learns
the destination's address in the same moment the kernel does, which is what makes this
usable for destinations whose addresses change under you.

The `kube-dns.kube-system.svc.cluster.local` value in the allow list is not incidental.
Under default deny a workload that cannot reach its resolver resolves nothing, the snooper
never sees an answer, and every domain in the allow list is dead — the pod's egress is fully
closed and the policy looks broken. Cluster DNS has to be allowed alongside the name, and a
cluster Service name is how: the resolver's addresses come from Service and EndpointSlice
informers rather than being pinned by hand.

The two values in this policy are the two mechanisms side by side. `example.com` is outside
the cluster's DNS domain, so it is snooped from the pod's answers; a name shaped
`<service>.<namespace>.svc.cluster.local` is looked up in the API server instead and
programs the Service's ClusterIP and endpoint addresses. Which one a value gets is decided
by its shape alone.

## This is not a containment boundary

A domain allow list names destinations conveniently. It does not contain a workload that
does not want to be contained. The snooper reads unencrypted UDP/53 answers, so a resolver
reached over TCP/53, DNS over TLS or DNS over HTTPS is invisible to it, and so is a client
that skips resolution and connects to a hardcoded address. Under default deny those cases
are blocked rather than allowed, but a deny list built from names is bypassable outright.
There are no wildcards, and learned addresses expire by LRU eviction rather than by TTL.

Read [limits of domain names](../../../docs/users/reference/runtimepolicy.md#limits-of-domain-names)
before relying on this. A workload that must be contained needs its destinations named as
addresses or as
[cluster Service names](../../../docs/users/reference/runtimepolicy.md#cluster-service-targets).

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support; a
stock kind cluster on a Linux host qualifies. BPF-LSM is not needed.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: enforce`.

The destinations are public names, so the cluster's pods need egress to the internet and a
resolver that answers for public names. `www.wikipedia.org` is the control: it is not in the
allow list, and its addresses have nothing to do with `example.com`'s.

## Run it

1. Start the client:

   ```bash
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/dns-client --timeout=90s
   ```

2. Confirm the client resolves and reaches both names before any policy exists. If this
   step fails, the "blocked" result below would prove nothing:

   ```bash
   kubectl exec dns-client -- nc -z -w 3 example.com 443; echo "baseline allowed exit=$?"
   kubectl exec dns-client -- nc -z -w 3 www.wikipedia.org 443; echo "baseline control exit=$?"
   ```

   Both print `exit=0`.

3. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol egress-to-domain-name
   ```

   `Applied=True` with reason `Enforcing` once the daemon has programmed the pod's egress
   maps.

4. Check that the name and the resolver were both programmable. A name that was rejected
   also produces "blocked", which would make the verification pass for the wrong reason:

   ```bash
   kubectl get rpol egress-to-domain-name -o jsonpath='{.status.conditions}'
   ```

   `TargetsValid=True` with reason `AllTargetsSupported`.

## Verify

Both directions matter. A policy that dropped every packet would also pass the "blocked"
check on its own.

```bash
kubectl exec dns-client -- nc -z -w 3 example.com 443; echo "allowed exit=$?"
kubectl exec dns-client -- nc -z -w 3 www.wikipedia.org 443; echo "control exit=$?"
```

- `allowed exit=0` — the name resolved, the answered address was written into the pod's
  learned-address map, and the connection to it was permitted. Reaching it at all also
  proves the cluster DNS value took effect.
- `control exit=1` — the control name resolves just as well, and the addresses it answers
  with are dropped in the kernel. The daemon programs maps on its own schedule, so allow a
  few seconds after applying the policy before the first attempt fails.

Only an address that arrived in an answer for an *allowed* name is allowed, so an address the
pod already holds gets nothing from this policy. Resolve the control name from the pod and
connect to the address it answers with:

```bash
CONTROL=$(kubectl exec dns-client -- nslookup www.wikipedia.org \
  | awk '/^Name:/{f=1} f && /^Address:/ && $2 ~ /^[0-9.]+$/ {print $2; exit}')
test -n "$CONTROL" || echo "the lookup returned no IPv4 address, so the check below would prove nothing"
kubectl exec dns-client -- nc -z -w 3 "${CONTROL}" 443; echo "control by address exit=$?"
```

`control by address exit=1`. The lookup succeeded and the answer reached the pod, but the
name is not in the allow list, so nothing was recorded for it and the address is dropped
exactly as the name was. Guard the address before using it: `nc` given an empty argument also
exits non-zero, which would look like the result you were hoping for.

## Clean up

```bash
kubectl delete rpol egress-to-domain-name
kubectl delete -f client.yaml
```
