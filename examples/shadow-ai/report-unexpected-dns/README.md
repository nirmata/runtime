# Report the DNS names a workload was not expected to resolve

## What this shows

A `dns` behavior declares the names a selected workload is *expected* to resolve. The
daemon attaches a `cgroup_skb/egress` program to the pod's cgroups, reads the question
name out of every UDP/53 query the pod sends, and writes a result for each name the
policy did not expect.

The allow list is inverted relative to `exec` and `open`. For those, an `allow` entry
only matters under a default deny; here `dns.allow` *is* the expected set, so a name
matching none of its entries is reported on its own, with no `"*"` in `deny`. Reporting
every name is a separate request: `deny.values: ["*"]`, the discovery form an operator
starts from before there is an allow list to write.

Values are exact hostnames or left-wildcards. `*.openai.azure.com` covers
`eastus.openai.azure.com` and not the apex `openai.azure.com` — the trap this example
verifies directly.

This policy reports and does not block. Blocking egress by name is a different behavior:
a domain value on a `network` behavior is enforced against the addresses the daemon learns
from the pod's own answers for that name — see
[egress-to-domain-name](../../egress/egress-to-domain-name/). The two are complementary rather than
redundant. A `network` behavior decides about destinations a policy already named; only the
question observation supplies a name the policy did *not* name, which is the question this
example answers. Pairing them is shown [below](#pairing-it-with-enforcement).

Findings here are advisory: `result: warn`, `enforced: "false"`, and no "would have been
denied" wording, because nothing was blocked and no enforcing form of this behavior exists.
A policy that pairs a `dns` behavior with `mode: enforce` is refused when it compiles, and
the error names the `network` behavior instead.

## Requires

DNS question observation needs only a cgroup v2 host and BPF support; a stock kind cluster
on a Linux host qualifies. It needs no BPF-LSM and no changes to the workload.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: monitor`.

## Run it

1. Start the client:

   ```bash
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/dns-client
   ```

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol report-unexpected-dns
   ```

   `Applied=True` with reason `Monitoring`. A pod is observed exactly while some policy
   with a `dns` behavior selects it, so nothing was being read out of this pod's queries
   before this apply.

3. Resolve four names — two the policy expects, two it does not:

   ```bash
   for name in api.openai.com. eastus.openai.azure.com. openai.azure.com. metrics.evil.example.com.; do
     kubectl exec dns-client -- nslookup "$name" >/dev/null 2>&1
   done
   ```

   The trailing dot matters. Without it a pod's resolver expands the name through the
   `search` domains in its `/etc/resolv.conf` first, and each expansion is a separate
   question the policy never named. The dot makes the name absolute, so exactly one
   question goes on the wire. Whether an answer comes back is irrelevant: the question is
   the observation.

## Verify

Three directions have to hold, and the third is the one an allow list is easy to get
wrong.

Questions reach the ring buffer as they happen, but findings are buffered and flushed
every 10 seconds, so allow about that long.

```bash
NODE=$(kubectl get pod dns-client -o jsonpath='{.spec.nodeName}')
kubectl get report "kyverno-runtime-${NODE}" -o jsonpath='{range .results[?(@.rule=="dns")]}{.properties.dnsName}{"\n"}{end}'
```

- **The unapproved name is reported.** `metrics.evil.example.com` appears.
- **The approved names are not.** Neither `api.openai.com`, which is an exact allow
  entry, nor `eastus.openai.azure.com`, which the `*.openai.azure.com` entry covers,
  appears.
- **The apex of the wildcard is reported.** `openai.azure.com` appears, because a
  wildcard matches subdomains and not the name itself. If the apex is a destination the
  workload really uses, list it as its own value.

The full result for the unapproved name:

```bash
kubectl get report "kyverno-runtime-${NODE}" -o yaml
```

```yaml
- source: kyverno-runtime
  policy: report-unexpected-dns
  rule: dns
  category: Runtime Security
  result: warn
  scored: true
  description: resolved unexpected DNS name metrics.evil.example.com, not expected by policy report-unexpected-dns
  subjects:
  - apiVersion: v1
    kind: Pod
    name: dns-client
    namespace: default
  properties:
    behavior: dns
    container: client
    count: "1"
    dnsName: metrics.evil.example.com
    enforced: "false"
    node: kind-worker
    serviceAccount: default
```

`result: warn` rather than `fail`, and there is no `comm`: a `cgroup_skb` program may not
call `bpf_get_current_comm`, so a question carries the pod it came from and no process
name.

### The discovery form reports everything

Before there is an allow list to write, ask for every name instead. The same pod, a
second policy, no allow entries:

```bash
kubectl apply -f discovery-policy.yaml
kubectl exec dns-client -- nslookup api.openai.com. >/dev/null 2>&1
```

After the next flush, `api.openai.com` — expected by `report-unexpected-dns` and so
absent from its results — is reported by `discover-dns`:

```bash
kubectl get report "kyverno-runtime-${NODE}" \
  -o jsonpath='{range .results[?(@.policy=="discover-dns")]}{.properties.dnsName}{"\n"}{end}'
```

Policies are evaluated independently, so both are in force on the same pod at once: one
reports the surprises, the other reports the inventory.

## Pairing it with enforcement

Reporting the surprises and blocking the destinations are two policies over the same pods,
because a `dns` behavior is legal only in `mode: monitor` and enforcement needs
`mode: enforce`. Apply this alongside `policy.yaml`:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: egress-to-approved-providers
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: dns-client
  behaviors:
  - network:
      deny:
        values:
        - "*"
      allow:
        values:
        - api.openai.com
        - api.anthropic.com
        - kube-dns.kube-system.svc.cluster.local
```

Now the workload can reach only the addresses answered for the two approved names, plus
cluster DNS so it can resolve them at all — and `report-unexpected-dns` still tells you
which other names it tried, which the egress filter alone cannot: a blocked connection to an
address no policy-named answer covered carries no name.

The `network` list has no wildcard entry, because a wildcard cannot be resolved to a finite
set of addresses. `*.openai.azure.com` is expressible as a `dns` value and not as a
`network` one, so the enforcing policy names each subdomain it actually allows. The limits
that come with naming a destination by domain are in
[limits of domain names](../../../docs/users/reference/runtimepolicy.md#limits-of-domain-names) —
a domain allow-list is a convenience, not a containment boundary.

## What this does not tell you

A resolution is not a connection. The workload asked for a name; it may never have dialled
the answer, and an answer already in a local or shared cache produces no question at all.
DNS over HTTPS and DNS over TLS are not read at this hook, nor is DNS over TCP/53, nor a
workload that dials an address it never resolved. The full list is in
[limits of DNS reporting](../../../docs/users/reference/runtimepolicy.md#limits-of-dns-reporting).

## Clean up

```bash
kubectl delete rpol report-unexpected-dns discover-dns
kubectl delete rpol egress-to-approved-providers --ignore-not-found
kubectl delete -f client.yaml
```
