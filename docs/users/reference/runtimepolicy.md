# RuntimePolicy reference

`RuntimePolicy` is the single CRD Nirmata Runtime reads. It names the pods to watch, the
behaviors to allow or deny, and whether the daemon blocks or only reports.

| Property | Value |
| --- | --- |
| Group/version | `runtime.nirmata.io/v1alpha1` |
| Kind | `RuntimePolicy` |
| Scope | Cluster |
| Short name | `rpol` |
| Status subresource | yes |
| Print columns | `Mode`, `Applied`, `Reason`, `Age` |

```bash
kubectl get rpol
kubectl get rpol <name> -o yaml
```

`network`, `protocol`, `exec`, and `open` are enforced or only reported depending on
`spec.mode`, not on which of the four it is: `enforce` blocks the operation in the
kernel, `monitor` only reports it (see [Modes](#modes-enforce-and-monitor)). A `network`
behavior in `enforce` mode does block traffic, the same as any other behavior's `deny`
rule — it is not detection-only. `dns` is the exception: it is monitor-only, and a
policy pairing it with `enforce` is refused by the API server (see
[Enforce mode is refused](#enforce-mode-is-refused)). What `network` and `protocol` are
not is a replacement for your CNI's NetworkPolicy: connectivity, identity-based policy,
FQDN egress, ingress, and encryption
stay with the CNI. What a `RuntimePolicy` adds over that is `protocol`, classified from a
flow's first data segment rather than its declared port; `exec` and `open`, enforced
alongside `protocol` and `network` in one policy object; and findings that attribute a
policy-violating attempt to the pod and container it came from, with the behavior's own
detail attached — the process for `exec`/`open`, the destination for `network`, the
classification for `protocol`. See
[why a runtime layer](../why-runtime.md#cooperation-is-the-dividing-line) for the layer
comparison and [known and shadow workloads](../why-runtime.md#known-and-shadow-workloads)
for what each behavior delivers depending on whether the workload cooperates.

## Spec reference

| Field | Type | Meaning |
| --- | --- | --- |
| `spec.podSelector` | `LabelSelector` | Pods this policy applies to. `{}` and absent both select every pod on the node. Relabeling a pod re-evaluates the match. An `enforce`-mode policy must set this or `namespaceSelector`. |
| `spec.namespaceSelector` | `LabelSelector` | Narrows `podSelector` to pods whose **namespace** carries these labels. `{}` and absent both select every namespace. ANDed with `podSelector`. Relabeling a namespace re-evaluates the pods in it. See [Targeting namespaces](#targeting-namespaces). |
| `spec.mode` | `monitor` \| `enforce` | What the daemon does with a matched pod. Optional, with no default. |
| `spec.evaluationInterval` | duration | How often matched pods are re-evaluated. Required to pick up changes behind a `resource` or `http` expression. |
| `spec.variables` | list of `name` + `expression` | Named CEL expressions, referenced as `variables.<name>` from any other expression. |
| `spec.behaviors` | list | One entry per behavior kind; each entry configures exactly one of `network`, `exec`, `open`, `protocol`, `dns`. Each `allow`/`deny` rule takes `values` and `expression`. At most 64 entries. |
| `spec.monitorFilter` | `expressions`: list of `name` + `expression` | A per-event CEL predicate deciding which monitor-mode findings are reported. 1 to 64 entries. Rejected on an `enforce` policy. See [Filtering monitor findings](#filtering-monitor-findings). |

Each entry in `spec.behaviors` configures exactly one of `network`, `exec`, `open`, `protocol`, or
`dns`. Each of those takes an `allow` and/or a `deny` rule, and each rule accepts a literal
`values` list, a CEL `expression` that evaluates to `list(string)`, or both (the results
are unioned):

```yaml
spec:
  behaviors:
  - network:            # exactly one of network | exec | open | protocol | dns per list item
      allow:
        values: [...]        # literal list of allowed items
        expression: "..."    # CEL expression returning list(string), unioned with values
      deny:
        values: [...]
        expression: "..."
```

- `protocol`: application protocols for egress, classified in the kernel from the first data
  segment of each flow rather than from the port. `network` and `protocol` evaluate
  independently and AND together: a connection must pass both. See
  [Limits of protocol classification](#limits-of-protocol-classification).

  | Value | Matches |
  | --- | --- |
  | `tls` | any TLS handshake, whatever the ALPN |
  | `tls/<alpn>` | TLS offering that exact ALPN, e.g. `tls/h2`, `tls/http/1.1`, `tls/dot` |
  | `quic` | QUIC, which includes HTTP/3 |
  | `ssh` | SSH, any version |
  | `dns` | cleartext DNS over UDP |
  | `http/1.1` | cleartext HTTP/1.x |
  | `http/2` | cleartext HTTP/2 |

  A `tls/` prefix means the classifier saw a TLS record layer on the wire. Its absence says
  nothing about whether the traffic is encrypted: `ssh` and `quic` both carry their own
  encryption, they just do not use TLS records.
- `exec`: command names/paths.
- `open`: file paths.
- `network`: IPv4 addresses, IPv4 CIDRs of `/24` or narrower, cluster Service DNS names,
  and fully qualified domain names for egress. The filter reads IPv4 packets only, which
  on a dual-stack cluster is a real boundary — see
  [Limits of network enforcement](#limits-of-network-enforcement).
- `dns`: the DNS names a workload is expected to resolve. Observation only, and its allow
  list is inverted relative to the other behaviors — see [DNS reporting](#dns-reporting).
- `deny.values: ["*"]` (or an expression that returns `["*"]`) is treated as a
  **default deny** for that behavior (`network`, `exec`, `open`, or `protocol`): the
  behavior flips from allow-all-except-denied to deny-all-except-allowed. On a `dns`
  behavior the same sentinel means "report every name". When several policies match
  one pod, how their lists combine differs by behavior — see
  [Multiple policies on one pod](#multiple-policies-on-one-pod).
- A `network` value that is a name is resolved by one of two mechanisms, chosen by the
  shape of the name alone: a cluster Service DNS name resolves from API server informers
  (see [Cluster Service targets](#cluster-service-targets)), any other fully qualified
  domain name is learned from the pod's own DNS answers (see
  [Domain name targets](#domain-name-targets)).
- `spec.variables` defines named CEL expressions that can be reused across behaviors via
  `variables.<name>` inside any `expression`.
- `expression` must evaluate to a statically-typed `list(string)`. Functions that return
  `dyn` (e.g. `http.get(...).body`, `json.unmarshal(...)`) need an explicit coercion, since
  the checker can't infer a concrete element type from `dyn` on its own:
  `someDynValue.map(x, string(x))`.
- `spec.mode` selects `enforce` or `monitor` (see below). It is optional; a policy that omits
  it neither enforces nor reports.

An entry that sets more than one of `network`, `exec`, `open`, `protocol`, `dns` — or none of them — is
rejected at admission by a CEL validation rule on the CRD.

Expression syntax, the available CEL libraries, and the `resource`/`http`/`json` helpers
are in [CEL in RuntimePolicy](cel.md).

## Multiple policies on one pod

Every `RuntimePolicy` matching a pod is in force on it at once. How their rules combine
differs by behavior, because the kernel objects differ, and the difference matters most
under a default deny.

For `network` and `protocol`, the daemon programs one egress filter per pod and merges
every matching enforce-mode policy into it: the `deny` entries of all policies are
programmed together, the `allow` entries of all policies are programmed together, and a
default deny set by any one policy applies to the pod. A connection is denied if it
matches any policy's `deny` entry, or if some policy sets a default deny and the
connection matches no policy's `allow` entry. An explicit `deny` entry always denies:
no `allow` entry overrides it, whichever policy carries either.

For `open` and `exec`, each policy keeps its own kernel program and maps, but every
program matching a pod evaluates as one chain that shares a verdict, so the rules
combine the same way as for `network`: a path in any policy's `deny` entries is denied,
a default deny set by any one policy applies to the pod, and a path in any policy's
`allow` entries survives a default deny — whichever policy set it. An explicit `deny`
entry always denies here too; no `allow` entry overrides it.

`dns` only reports, and each matching policy evaluates and reports on its own.

`monitor`-mode policies contribute no entries to the kernel maps under any behavior;
each one evaluates its own lists in userspace and reports independently of every other
policy. A monitor policy's findings therefore always reflect that one policy's lists,
never a combination.

## Targeting namespaces

`spec.namespaceSelector` narrows a policy to pods whose **namespace** carries the labels it
names. It is a standard `LabelSelector`, matched against the namespace's labels, and it is
ANDed with `podSelector`: a pod is selected when its namespace matches *and* its own labels
match.

```yaml
spec:
  namespaceSelector:
    matchLabels:
      tier: prod
  podSelector:
    matchLabels:
      app: agent
```

That policy selects `app=agent` pods, but only those running in a namespace labelled
`tier=prod`.

### Absent means everything, on both halves

| | absent | `{}` | set |
| --- | --- | --- | --- |
| `podSelector` | every pod | every pod | matching pods |
| `namespaceSelector` | every namespace | every namespace | matching namespaces |

A policy that names one half is scoped by that half alone, so `namespaceSelector` on its
own reaches every pod in the namespaces it matches. A policy that names neither reaches
every pod on every node the agent runs on.

An `enforce`-mode policy is required to say which of those it means: the API server
rejects it unless it sets `podSelector` or `namespaceSelector`, and `podSelector: {}` is
how you ask for every pod on the node in as many words. A `monitor`-mode policy has no
such requirement — omitting both is the ordinary way to learn what a cluster does.

The daemon refuses to compile an unscoped `enforce` policy as well, so one that was
already stored when the rule arrived reports the refusal in its status conditions instead
of widening to the whole cluster on upgrade.

### Targeting namespaces by name

There is no `namespaces` list. The API server labels every namespace with
`kubernetes.io/metadata.name`, so a name is just another label match — the same idiom
`ValidatingWebhookConfiguration` uses:

```yaml
spec:
  namespaceSelector:
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: In
      values: [payments, checkout]
  podSelector: {}
```

Excluding namespaces is the same selector with `NotIn`, which is how you keep a cluster-wide
policy off `kube-system`:

```yaml
spec:
  namespaceSelector:
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values: [kube-system, kube-public]
  podSelector: {}
```

Because this is a `LabelSelector`, names are matched exactly. There is no wildcard: a
`prod-*` prefix has to be expressed as a label you put on those namespaces.

### Relabeling a namespace re-evaluates its pods

Labeling a namespace into or out of a policy's scope takes effect without touching the pods
or the policy. The daemon watches namespaces and replays the pods it holds in the changed
namespace, so enforcement attaches and detaches the same way a pod relabel already works.

This needs `get`/`list`/`watch` on namespaces, which the chart's ClusterRole grants.

## Cluster Service targets

An allow list of literal ClusterIPs works only as long as they hold. A Service that is
redeployed, or whose backends move, changes addresses and the policy has no way to know.
Naming the Service by its
[cluster DNS name](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#services)
instead lets the daemon resolve it from Service and EndpointSlice informers.

A `network` value in the form `<service>.<namespace>.svc.<cluster-domain>` is a Service
name and resolves that way. Any other fully qualified domain name is an external name,
learned from the pod's own DNS answers by the snooper. The two are chosen by shape, and
they are not equivalent: informer resolution is authoritative and watch-driven, whereas
DNS snooping is best-effort and [not a containment boundary](#limits-of-domain-names).

This is a deny-all-then-allowlist egress policy: the workload may reach cluster DNS and an
egress gateway, and nothing else. The `kubernetes` Service is deliberately absent, so the
API server is unreachable from these pods:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: egress-via-gateway-only
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: payments
  behaviors:
  - network:
      deny:
        values:
        - "*"
      allow:
        values:
        - kube-dns.kube-system.svc.cluster.local
        - egress-gateway.networking.svc.cluster.local
```

Prefixing one more label names a single endpoint of that Service, which is how a
StatefulSet replica is addressed:

```yaml
      allow:
        values:
        - web-0.web.default.svc.cluster.local
```

What a Service name resolves to:

- the Service's ClusterIP, when it has one, plus the addresses of its **ready**
  endpoints. A headless Service therefore resolves to its endpoints alone; a Service
  scaled to zero resolves to its ClusterIP alone.
- IPv4 only. IPv6 endpoint addresses are skipped, as everywhere else in `network`.
- re-resolved whenever the Service or one of its EndpointSlices changes, so scaling,
  rolling, or replacing the backends updates the programmed addresses without touching
  the policy. No `evaluationInterval` is needed for this; the informers drive it.

A Service name is one value among others on the same rule, so a policy can mix it with
addresses that have no Service in front of them:

```yaml
spec:
  behaviors:
  - network:
      deny:
        values:
        - "*"
      allow:
        values:
        - "192.0.2.10"     # an appliance outside the cluster
        - kube-dns.kube-system.svc.cluster.local
```

### Always write a Service name in full

**A short form matches nothing, and says nothing.** `redis.default` is accepted as an
external name, because it is shaped exactly like `example.com` — two labels — and no
syntactic rule can tell them apart without rejecting every two-label external domain along
with it. It then never matches anything: a pod's resolver expands an unqualified name
through its `resolv.conf` search domains before it asks, so the question the snooper
observes is `redis.default.svc.cluster.local`, never the `redis.default` the policy names.
The value looks valid, no condition reports it, and the destination is simply never
allowed. Write `redis.default.svc.cluster.local`.

### Accepted names

The cluster domain is the daemon's `--cluster-domain`, `cluster.local` unless it is set
otherwise.

| Value | Result |
| --- | --- |
| `kube-dns.kube-system.svc.cluster.local` | Service `kube-dns` in `kube-system`, resolved from informers |
| `api.payments.example.com` | external name, learned from the pod's DNS answers |
| `redis.default` | external name — resolves nothing, see above |
| `redis` | rejected: a single label is not a usable name |
| `web-0.web.default.svc.cluster.local` | one endpoint of Service `web`, resolved from its EndpointSlice |
| `api.prod.svc.example.com` | external name — `svc` is not reserved outside the cluster domain |
| `redis` | rejected: a single label is not a usable name |
| `redis.default.svc` | rejected: a cluster name missing its DNS domain |
| `10-1-2-3.default.pod.cluster.local` | rejected: a pod record already carries its address |
| `1redis.default.svc.cluster.local` | rejected: a service label must start with a letter |

Naming one endpoint programs that backend's addresses alone — never the ClusterIP and
never a sibling — so `web-0.web.default.svc.cluster.local` grants exactly what its name
says. The endpoint is matched by the `hostname` its EndpointSlice carries, which is what
the DNS record is built from. A replica that is not running resolves to nothing rather
than being reported as unknown; a hostname no endpoint claims is `UnresolvedServices`,
because falling back to the Service would program addresses the policy never named.

A name is aimed at the cluster only by carrying the cluster's own domain. A name that
ends in it but is neither of the two forms above is rejected rather than treated as
external, because falling through would hand the operator the weaker of the two
mechanisms for a destination that is plainly in-cluster. Outside that domain nothing is
reserved, so an external destination genuinely named `api.prod.svc.mycompany.com` is a
normal name. The cost of that choice is that a name carrying some *other* cluster's
domain cannot be told apart from an external one, and is accepted as external.

The labels follow Kubernetes' own rules: a service label is RFC 1035, so it must start
with a letter, while namespace and endpoint hostname labels are RFC 1123 and may start
with a digit. All are at most 63 characters of lowercase alphanumerics and `-`.

A rejected literal fails the whole policy to compile, reported as `Applied=False` with
reason `CompileFailed` and a message naming the field path, the value and the reason.
Nothing in that policy is applied while it is rejected, including the rules either side of
the offending value. A value produced by an `expression` is not seen until evaluation, so
the same mistake there is reported per value through `TargetsValid=False` and leaves the
rest of the policy in force.

## Limits of cluster Service targets

A Service name is resolved from watched cluster state, which bounds what it can express.
These are real, current limits:

- **In-cluster Services only.** A Service name is looked up in the Service and
  EndpointSlice informers, never in DNS, so it cannot name anything outside the cluster.
  For an external destination, name it as a domain instead — a different mechanism with
  [different limits](#limits-of-domain-names).
- **No port or protocol granularity.** Allowing a Service allows *every* port on the
  addresses it resolves to, because the egress maps are keyed on a `u32` IPv4 address
  and nothing else. Naming a Service that exposes port 443 does not restrict the
  workload to port 443 on that address.
- **Both the ClusterIP and the endpoint addresses are programmed, and both are needed.**
  Which one the kernel actually matches depends on the client's network namespace: an
  ordinary pod's traffic is DNATed in the host namespace, after the egress hook has run in
  the pod namespace, so the hook matches the ClusterIP; a `hostNetwork` pod is DNATed in
  its own namespace before the hook, so the hook matches the backend address. A cluster
  using a socket-level load balancer instead of kube-proxy translates before the hook for
  every client, in which case only the endpoint addresses match.
- **Endpoint addresses are pod IPs, and they are programmed individually.** A matched pod
  can therefore reach those pod IPs directly, not only through the Service's ClusterIP.
  The grant is wider than "may talk to this Service": it is "may talk to this Service's
  addresses", and if another Service happens to share a backend pod, that pod is
  reachable through it too.
- **An unresolved name programs nothing.** A name whose Service does not exist (a typo, a
  namespace that was never created, a Service deleted after the policy was written)
  contributes no addresses. Under default-deny that means the destination is
  fully blocked rather than quietly allowed, which is the safe direction but looks
  identical to a network outage from inside the workload. It is surfaced as a
  `TargetsValid=False` condition with reason `UnresolvedServices` — check the status before
  concluding the cluster is broken:

  ```bash
  kubectl get rpol egress-via-gateway-only -o jsonpath='{.status.conditions}'
  ```

## Domain name targets

A `network` value that is a fully qualified domain name outside the cluster domain names an
external destination, and nothing about it is resolved when the policy is written: the
daemon attaches a second eBPF program to the matched pod's cgroup that reads the pod's own
DNS answers, and an A record for a name the policy mentions makes that address allowed (or
denied) for that pod. The pod learns the address the same moment the kernel does.

The resolver has to stay reachable for any of this to happen, which is why cluster DNS is
allowed alongside the name — under default-deny a workload that cannot reach its resolver
resolves nothing, and every domain in the allow list is dead:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: egress-to-payments-api
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: checkout
  behaviors:
  - network:
      deny:
        values:
        - "*"
      allow:
        values:
        - api.payments.example.com
        - kube-dns.kube-system.svc.cluster.local
```

A name in `deny.values` works the same way in the other direction: without a default deny,
the addresses answered for that name are blocked and everything else is allowed.

## Limits of domain names

A domain allow-list is a convenience for naming destinations whose addresses change. It is
**not a containment boundary**, and it must not be relied on as one. These are real,
current limits:

- **Only unencrypted UDP/53 answers are seen.** The snooper parses UDP source port 53. A
  resolver reached over TCP/53, DNS over TLS, or DNS over HTTPS is invisible to it, and so
  is a client that skips resolution entirely and connects to a hardcoded address. In each
  of those cases the address is never attributed to a domain: under default-deny the
  connection is blocked (a false outage), and under a deny list it is allowed (a real
  bypass). A workload that must be contained needs its destinations named as addresses or
  as [cluster Service names](#cluster-service-targets).
- **No wildcards.** Every name is matched whole, against the question the pod actually
  asked. A CNAME chain is attributed to the question, not to the owner name of the A
  record, so naming the alias is correct and naming its target is not. `*.example.com`
  fails the whole policy to compile — the daemon logs the offending field path and
  enforces nothing from that policy, not even the values around it.
- **Expiry is eviction, not TTL.** Learned addresses live in a 4096-entry LRU map per pod
  and are dropped when it fills, not when the record expires. An address that has rotated
  away from a name stays allowed until something evicts it, which can be well past its
  TTL — and, on a quiet pod, indefinitely.
- **An address shared by two domains is ambiguous.** The last answer to name it wins, so
  one shared front end named by two policies is attributed to whichever name was resolved
  most recently. The attribution is at least visible: monitor-mode network observations
  carry the domain the address was learned under.
- **Bounded per pod: 256 names, 4096 addresses.** A pod whose policies name more than 256
  distinct domains rejects the excess with `TargetsValid=False`. A name that resolves to
  more addresses than the map holds loses the oldest of them to eviction. A name is also
  rejected if its DNS wire encoding exceeds 128 bytes.
- **IPv4 only, on both sides.** Only A records are read, and only from answers carried
  over IPv4, matching the IPv4-only egress maps.

## Limits of network enforcement

The egress filter reads IPv4 packets and nothing else. That is a security boundary an
operator has to know about, not a missing convenience:

- **IPv6 traffic is not filtered.** The egress program passes any packet that is not
  IPv4 without looking at it, so on a dual-stack cluster a default-deny `network`
  behavior does not deny IPv6 connections: a destination reachable over IPv6 is
  reachable whatever the policy says, and nothing observes or reports the connection.
  A workload that must be contained by `network` rules needs to run without IPv6
  connectivity — a single-stack IPv4 cluster, or pods with no IPv6 address. A
  `protocol` behavior does classify and enforce IPv6 flows, so a protocol default deny
  still constrains what an IPv6 connection may carry, but never where it goes.
- **IPv6 literals are rejected as values**, at compile time when written literally and
  through `TargetsValid=False` when produced by an `expression`, so a policy cannot
  appear to cover a family the filter does not read.
- **A CIDR is expanded into addresses, not stored as a prefix.** The maps hold
  individual IPv4 addresses, so a CIDR of `/24` or narrower is expanded into its
  addresses — at most 256 per value — and a wider one is rejected with
  `TargetsValid=False` rather than partially covered. The per-pod allow and deny maps
  hold 1024 addresses each; a set of policies whose expansions exceed that fails to
  program and is surfaced through the policy's status conditions.
- **No port granularity.** An address allows or denies every port on it; no policy
  value carries a port.

## DNS reporting

A `dns` behavior declares the DNS names a selected workload is *expected* to resolve, and
reports the questions it asks that the declaration does not cover. It is the one behavior
that only ever observes.

It is not the way to block a destination named by domain — that is a domain value on a
`network` behavior, enforced against the addresses the daemon learns from the pod's answers
(see [Domain name targets](#domain-name-targets)). The two answer different questions and
are complementary. A `network` behavior decides about destinations a policy already named;
only the question observation supplies a name the policy did *not* name, because a
connection to an address no policy-named answer covered carries no name at all.

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: report-unexpected-dns
spec:
  mode: monitor
  podSelector:
    matchLabels:
      app: dns-client
  behaviors:
  - dns:
      allow:
        values:
        - api.openai.com
        - api.anthropic.com
        - "*.openai.azure.com"
```

A pod is observed exactly while some policy with a `dns` behavior selects it. The daemon
attaches a `cgroup_skb/egress` program to that pod's container cgroups and admits their
cgroup ids to a gate, so an unselected pod's questions are never read at all — they cannot
be dropped, decoded, or reported, and no node-wide stream of every pod's questions exists.
Relabeling a pod starts or stops observation like any other selector change.

### The allow list is inverted

For `network`, `protocol`, `exec`, and `open`, an `allow` entry only matters under a
default deny. For
`dns`, `allow` *is* the expected set, so a name matching none of its entries is reported on
its own:

| `allow` | `deny` | What is reported |
| --- | --- | --- |
| empty | empty | Nothing. The behavior is inert and the pod is not observed. |
| names | empty | Every observed name that matches no `allow` entry. |
| empty | names | Only names that match a `deny` entry. |
| names | names | A name matching a `deny` entry, or matching no `allow` entry. |
| any | `["*"]` | Every observed name. `allow` has no effect. |
| `["*"]` | empty | Nothing, but the pod is still observed. |

`deny.values: ["*"]` is the discovery form: it reports every name the workload resolves,
which is how an operator learns what to put in `allow` in the first place. It is not a
default deny with exemptions — an `allow` list alongside it is ignored, not applied.

An empty behavior is inert rather than all-reporting, because an undeclared expected set
means "nothing declared yet", not "every name is a surprise".

### Value forms

| Value | Matches |
| --- | --- |
| `api.openai.com` | exactly that name |
| `*.openai.azure.com` | any subdomain: `eastus.openai.azure.com`, `a.b.openai.azure.com` |
| `*` | every observed name (in `deny`), or nothing reported (in `allow`) |

A name is compared case-insensitively and without a trailing root dot: `API.Example.COM.`
and `api.example.com` are the same value. A value is at most 253 characters and may not
contain a NUL byte.

Wildcards are valid here and rejected as `network` values. The reason is the mechanism: a
`dns` value is only ever compared against an observed question name, whereas a `network`
target has to be resolved to addresses and programmed into a kernel map, and no finite set
of addresses corresponds to a wildcard. What a hostname *is* comes from one definition
shared by both, so the two cannot drift on anything else.

A wildcard is only the leftmost label. `api.*.example.com` and `example.com.*` are refused
with:

```text
a wildcard is only supported as the leftmost label: use "*.example.com", an exact name, or "*" to report every name
```

An address is not a name: `192.0.2.10` is refused as `not a hostname, a "*.<hostname>"
wildcard or "*"`, because a numeric last label is a truncated address rather than a
hostname.

### A wildcard does not match its apex

This is the authoring trap. `*.openai.azure.com` covers `eastus.openai.azure.com` and does
**not** cover `openai.azure.com`. A wildcard is stored as the suffix `.openai.azure.com`,
including the separating dot, which is also what keeps `evilopenai.azure.com` from
matching it.

If the apex is a name the workload really resolves, list it as its own value alongside the
wildcard. Otherwise it is reported as unexpected, and the report is correct.

### Enforce mode is refused

A `dns` behavior in `enforce` mode is refused by the API server: the spec carries a validation rule
for it, so the object is never created and `kubectl apply` fails with this message:

```text
a dns behavior reports the names a workload resolves, it does not block them: set spec.mode to "monitor", or express the destinations you want blocked as a network behavior, which enforces domain values
```

The daemon carries the same rule, so a cluster whose CRD predates it refuses the policy at compile
time instead, reporting `Applied=False` with reason `CompileFailed` and the same message at
`spec.behaviors[i].dns`.

The reason is not that a name cannot be enforced; a domain value on a `network` behavior
is enforced. It is that destinations belong to `network`, so honouring `enforce` here would
give an author two ways to spell one intent with only one of them working — and the
alternative, accepting `enforce` and quietly reporting, is worse still: an operator who
asked for a block would get an audit trail and believe they had containment.

To do both over one workload, use two policies over the same pods:
one in `enforce` mode carrying the `network` behavior, one in `monitor` mode carrying the
`dns` behavior. Policies compose per pod, so both are in force at once.

### What a finding looks like

A `dns` finding is advisory. It carries `rule: dns`, `result: warn` rather than `fail`,
`enforced: "false"`, and the observed name in the `dnsName` property:

```text
resolved unexpected DNS name metrics.evil.example.com, not expected by policy report-unexpected-dns
```

A repeated occurrence increments `count` rather than appending a result, as with every
other behavior. There is no `comm`: a `cgroup_skb` program may not call
`bpf_get_current_comm`, so a question is attributed to a pod and not to a process.

Unlike the `open`, `exec`, and `network` observations, questions are streamed rather than
polled, so `--observe-interval` does not apply to them. The only latency is the reporter's
10-second flush.

## Limits of DNS reporting

**A resolution is not a connection.** Everything below follows from that. A `dns` behavior
tells you what a workload asked to resolve, which is evidence of intent and not evidence of
traffic, and it is not a containment boundary. To constrain where a workload actually goes,
name the destination as a domain (or an address, or a Service) on a `network` behavior in
`enforce` mode. These are real, current limits:

- **A cached or shared answer produces no question at all.** An address the workload's
  resolver, its libc, or a sidecar already holds is used without asking, so a name the
  workload uses constantly can be observed once and then never again — or never, if the
  answer was warm before observation started.
- **A workload dialling a bare address asks nothing.** An address in a config file, an
  environment variable, or a hardcoded constant is reached with no question to observe. A
  `network` behavior is what sees, and blocks, that connection.
- **DNS over HTTPS and DNS over TLS are invisible.** Only UDP datagrams whose destination
  port is 53 are read, so a resolution carried inside TLS is not one of them; to a
  `network` behavior it is an ordinary encrypted connection to an address. A workload that
  resolves over DoH reports no questions while resolving normally.
- **DNS over TCP/53 is not observed.** Only UDP datagrams to port 53 are read. A large
  question, a retry after a truncated answer, or a resolver configured for TCP produces no
  observation.
- **A question longer than 128 bytes on the wire is not observed.** That is the name
  width of the kernel-side record, which is also the width policy names are interned into,
  so a question this drops is a question no policy value could have named. It is counted,
  not silent: see the `name_unreadable` loss reason in [Metrics](metrics.md).
- **Ring buffer loss is counted, not silent.** The kernel-side buffer holds roughly 450
  records; if userspace falls behind, the questions that do not fit are counted under the
  `ringbuf_full` loss reason rather than disappearing. A monitoring gap that reads as
  "nothing happened" is the failure mode this avoids.
- **A wildcard does not match its apex.** `*.example.com` covers subdomains only, so
  `example.com` is reported unless it is listed separately.
- **The pod's search domains produce extra questions.** A resolver expands a name through
  the `search` list in `/etc/resolv.conf` before, or after, asking for it absolutely, and
  each expansion is its own question. `api.openai.com` used by a workload can therefore be
  observed as `api.openai.com.default.svc.cluster.local` as well, which matches no `allow`
  entry and is reported. Read the discovery form's output before writing an `allow` list,
  rather than predicting the questions.
- **The cgroup gate holds 1024 entries.** That is the node-wide bound on container cgroups
  under DNS observation at one time.
- **Only questions, never answers.** The record carries the queried name and the cgroup it
  came from: no query type, no response code, no answer addresses, and no timing beyond the
  timestamp userspace stamps on arrival. Attributing an address to a name is the separate
  mechanism behind [domain name targets](#domain-name-targets).

## Modes: enforce and monitor

`spec.mode` selects what the daemon does with a matched pod:

| `spec.mode` | Kernel programs attached | Deny/allow maps programmed | Blocks | Emits findings |
| --- | --- | --- | --- | --- |
| `enforce` | yes | yes | yes | denials only |
| `monitor` | yes | **no** (maps stay empty) | no | yes |
| omitted | no | no | no | no |

An `enforce` finding is the record that the kernel blocked an operation, carrying
`enforced: "true"`; operations the policy permits produce nothing. A `monitor` finding is
a counterfactual — an enforcing form of this policy would have blocked this (see
[Findings and Reports](#findings-and-reports)).

A `dns` behavior exists only on the `monitor` row. Pairing it with `enforce` fails the
policy to compile and points at the `network` behavior, which is where a destination named
by domain is enforced (see [Enforce mode is refused](#enforce-mode-is-refused)).

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: nginx-baseline-monitor
spec:
  mode: monitor
  podSelector:
    matchLabels:
      app: nginx
  behaviors:
  - network:
      deny:
        values:
        - "198.51.100.23"
  - open:
      deny:
        values:
        - "/etc/shadow"
```

In `monitor` mode the same eBPF programs are attached to the same matched pods, but with
**empty** `banned`/`allowed` maps and default-deny left off, so nothing is ever blocked. What
the programs do is *count* what the workload touched:

- the LSM programs count every `file_open` / `bprm_check_security` path per cgroup;
- the egress program counts every destination IPv4 address per pod;
- the protocol classifier counts every classified `(protocol, decision)` per pod, once per flow.

The daemon polls those counters every 10 seconds, attributes each observation to a pod (via the
cgroup ID → pod index built from the local pod watch), and evaluates the policy's `allow`/`deny`
lists **in userspace**. A match produces a finding (see
[Findings and Reports](#findings-and-reports)). Because counters are read-and-reset, each observation carries the number of occurrences
since the previous poll.

Matching in monitor mode follows the same semantics as enforcement: an explicit `deny` entry
matches, and under a default deny (`deny.values: ["*"]`) anything absent from `allow` matches.
`monitor` and `enforce` are per policy, so a pod can be monitored by one policy while another
enforces on it. Switching a policy's `mode` rebuilds its attachments, because an observing
program must never inherit deny entries and an enforcing one must not start from empty maps.

## Status

`status` is written per node. Each daemon owns exactly one entry in `status.nodes` (keyed by
`nodeName`) and never touches another node's entry; each shard carries that node's compact
answers — `enforcementAvailable`, `observationAvailable`, `podsMatched`, and a `message` naming
what is unavailable there. `status.lastEvaluatedTime` is the newest shard timestamp, and the
cluster-scoped `Applied`, `EnforcementAvailable`, `ObservationAvailable` and `PodsMatched`
conditions are derived from the shards, so on a mixed cluster the top-level value states
something true of the cluster rather than of whichever node wrote last. Updates are flushed
every 30 seconds with conflict retry.

Per-pod detail is not in the status. Which pods a policy matched and which of them violated it are
in the Reports (which name them) and in the Prometheus counters; the status answers "is this policy
loaded, on which nodes, in which mode, and when was it last evaluated".

```yaml
status:
  lastEvaluatedTime: "2026-07-27T10:15:04Z"
  nodes:
  - nodeName: node-1
    lastEvaluatedTime: "2026-07-27T10:15:04Z"
    observationAvailable: true
    podsMatched: true
  - nodeName: node-2
  conditions:
  - type: Applied
    status: "True"
    reason: Monitoring
    message: the policy is observed and reported but never blocks
  - type: TargetsValid
    status: "False"
    reason: UnsupportedTargets
    message: '2 egress target(s) are not enforced: "example.com": not an IPv4 ...'
```

Conditions:

| Type | Reasons | Meaning |
| --- | --- | --- |
| `Applied` | `Enforcing`, `Monitoring`, `NoMode`, `CompileFailed`, `EnforcementUnavailable`, `ObservationUnavailable`, `NoMatchingPods` | Whether the daemon has the policy loaded, and in which mode. `NoMode` reports `False` for a policy that omits `spec.mode`, which is neither enforced nor reported. `CompileFailed` reports `False` when the spec could not be compiled, with the offending field path and value in the message; nothing in such a policy is applied, including the rules either side of the bad one. `EnforcementUnavailable` / `ObservationUnavailable` report `False` when the `EnforcementAvailable` / `ObservationAvailable` condition (below) is `False` for the policy's mode: a mode that promises enforcement or observation does not read as applied while any node's attachment behind it never took. `NoMatchingPods` reports `False` when the `PodsMatched` condition (below) is `False` — no node has a matching pod — and the mode's own `EnforcementAvailable` / `ObservationAvailable` is not — that is, is either `True` or was never recorded at all, which is the normal case for a policy whose behaviors never hit a programming failure. When both conditions are `False` at once, `EnforcementUnavailable` / `ObservationUnavailable` takes priority and `NoMatchingPods` is not reported. |
| `TargetsValid` | `AllTargetsSupported`, `NoTargets`, `UnsupportedTargets`, `UnresolvedServices` | Whether every `network` and `protocol` target could be programmed. `UnsupportedTargets` lists the rejected values and why; `UnresolvedServices` lists the Service and endpoint names that are not in cache. |
| `ExecRulesValid` | `AllPathsSupported`, `NoPaths`, `UnsupportedPaths` | Whether every `exec` path could be programmed. `UnsupportedPaths` lists the rejected values and why. |
| `OpenRulesValid` | `AllPathsSupported`, `NoPaths`, `UnsupportedPaths` | Whether every `open` path could be programmed. |
| `ObservationAvailable` | `ObservationAvailable`, `ObservationUnavailable` | Set to `False` when observation could not be attached on at least one node — a node not booted with `lsm=bpf`, or a loaded LSM program with no observation maps — with the failing nodes and their causes named in the message; a monitor-mode policy on such a node silently produces no findings until this clears. Set to `True` when every node reporting it has observation attached. Each node's own answer is `status.nodes[*].observationAvailable`. |
| `EnforcementAvailable` | `EnforcementAvailable`, `EnforcementUnavailable` | Set to `False` when a kernel map could not be programmed or attached on at least one node — a node not booted with `lsm=bpf`, a full map, a failed update — with the failing nodes and their causes named in the message, so part of the policy is not enforced there. Set to `True` when every node reporting it has enforcement programmed. Each node's own answer is `status.nodes[*].enforcementAvailable`. |
| `PodsMatched` | `PodsMatched`, `NoMatchingPods` | Whether any node currently has a pod selected by `spec.podSelector` / `spec.namespaceSelector`. `NoMatchingPods` catches a selector that is well-formed but matches nothing anywhere — otherwise indistinguishable from a policy that is enforcing on pods that simply never triggered it. Nodes where none of the policy's pods are scheduled do not make it `False`. Each node's own answer is `status.nodes[*].podsMatched`. |

A target or path the runtime cannot program is never silently skipped, and which condition
carries it depends on where the value came from: a literal is checked when the policy compiles
and a bad one reports `Applied=False` with `CompileFailed`, while a value an `expression`
produced is checked when it is programmed and reports the per-behavior condition. Either way it
also reaches an operator-visible log line.

## Findings and Reports

Findings — monitor-mode matches and enforce-mode denials alike — are written as
[OpenReports](https://openreports.io) `Report` objects in
the offending pod's namespace, one Report per pod, named
`kyverno-runtime-<podName>` (long pod names are truncated and suffixed with a
hash to fit the 63-character object-name limit), labeled
`runtime.nirmata.io/node: <nodeName>`.

```bash
kubectl get reports -A
kubectl get report kyverno-runtime-my-pod -n default -o yaml
```

Each result carries `policy` (the RuntimePolicy name), `rule` (the behavior: `network`,
`open`, `exec`, `protocol`, `dns`), `source: kyverno-runtime`, `category: Runtime Security`, the offending pod as
`subjects[0]`, and a fixed set of `properties`: `fingerprint`, `count`, `firstTimestamp`,
`lastTimestamp`, `behavior`, `target`, `enforced`, `node`, `container`, `owner`,
`serviceAccount`, and — where applicable — `destIP`, `destHost`, `dnsName`, `comm`, `argv`.

`result` is `fail` for `network`, `open`, and `exec`, and `warn` for `dns`: a question was
observed, nothing was blocked, and nothing would have been.

`enforced` distinguishes a blocked operation from one that only matched: it is `"true"`
on findings from an `enforce` policy, where the kernel denied the operation, and
`"false"` on findings from a `monitor` policy, where the behavior was observed but
allowed to proceed. It is always `"false"` on a `dns` finding.

Details worth knowing:

- Findings are buffered and flushed every 10 seconds, deduplicated by a stable fingerprint of
  (policy, behavior, pod, target), so a repeated observation increments `count` rather than
  appending a result.
- Reports are capped at 500 results; a truncated Report is annotated
  `runtime.nirmata.io/truncated-results: "true"`.
- Pod labels are never copied into a Report, and there is no mechanism to attach arbitrary
  key/values to one. Every emitted value is scrubbed on the way out. This is not configurable.
- A finding for a pod whose namespace is not a valid DNS-1123 label is dropped rather than
  written to an invalid object name.

Counters for ingested observations, dropped observations, and emitted findings are in
[Metrics](metrics.md).

## Filtering monitor findings

A `monitor` policy reports every observation its `allow`/`deny` lists match, and under a
default deny (`deny.values: ["*"]`) that is every file the workload opened, every program it
ran, or every address it reached. `spec.monitorFilter` decides which of those findings are
worth reporting, as a CEL predicate over the observation itself:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: report-mcp-file-access
spec:
  mode: monitor
  podSelector:
    matchLabels:
      nirmata.io/workload-class: ai-agent
  behaviors:
  - open:
      deny:
        values: ["*"]
  monitorFilter:
    expressions:
    - name: mcp-file-access
      expression: 'has(event.open) && event.open.path.matches("(?i)mcp")'
```

This is the thing a `deny` list cannot express. `open` and `exec` values are absolute literal
paths compared whole, with no substring, prefix, basename, or regex form, so an operator whose
target is a *shape* of path rather than a list of them had only two options: enumerate every
path in advance, or turn on `deny: ["*"]` and drown. A default deny plus a filter is the third.

| `spec.monitorFilter` | What is reported |
| --- | --- |
| absent | Every finding, unchanged. |
| present | A finding only if **every** expression is true. |

- Expressions are **ANDed**, evaluated in order, and short-circuit on the first false one. A
  disjunction goes inside a single expression with `||`.
- Each `expression` must type as `bool`, checked when the policy compiles. An unknown field is
  a compile error naming the valid ones, so the type checker — not a table — is how the `event`
  schema is discovered.
- `name` identifies the expression in compile errors, status conditions, and the eval-error
  metric. It is never written to a Report.
- A `dns` finding never has `event.wouldDeny` set, so an expression guarding on it silently
  drops every DNS finding. The full `event` schema, and the CEL environment these expressions
  run in, are in [CEL in RuntimePolicy](cel.md#monitorfilter-expressions).

### A broken filter reports anyway

An expression that fails at evaluation time, or returns anything other than a bool, reports the
finding and increments `nirmata_runtime_monitor_filter_eval_errors_total`, labeled with the
policy and the expression's `name` (see [Metrics](metrics.md)). The predicate selects what to
*show*, so the safe direction on failure is to show it: a filter that quietly dropped findings
would be a monitoring gap indistinguishable from "nothing happened".

### Monitor mode only

An `enforce` policy carrying a `monitorFilter` is refused by the API server, which carries a
validation rule for it, so `kubectl apply` fails with:

```text
a monitorFilter narrows what a monitor-mode policy reports; an enforce-mode policy reports only operations the kernel actually denied, and those are never suppressed
```

The daemon carries the same rule, so a cluster whose CRD predates it refuses the policy at
compile time instead, reporting `Applied=False` with reason `CompileFailed`.

The two kinds of finding are not equivalent. A monitor finding is a counterfactual — an
enforcing form of this policy would have blocked this — and under `deny.values: ["*"]` that is
every open and every exec. An enforce finding is the record that the kernel *did* block
something: each one is bounded and individually meaningful, and suppressing it destroys an
audit record. The remedy for not wanting one is to change the policy so the operation is not
denied.

A `monitor` policy selecting a pod that a *different*, `enforce` policy blocks still emits its
own counterfactual, so that finding stays filterable. `event.kernelDenied` says the kernel
denied the operation; it does not say this policy is what denied it.

### What a monitorFilter does not do

- **It is not enforcement.** The kernel decides from map lookups and cannot consult CEL, so a
  filter narrows what is observed into findings and never what is blocked. Sitting beside
  `behaviors` invites the other reading, and the other reading is wrong.
- **It does not relieve kernel map pressure.** Recording is unconditional, so a path a filter
  rejects still consumes a key in the per-cgroup map and still displaces others (see
  [Limits of monitor mode](#limits-of-monitor-mode)).

### Naming a set that cannot be enumerated

Two MCP targets have no absolute path a policy could list: a project-scoped `.mcp.json`, whose
location depends on where the repository was checked out, and the OAuth refresh-token cache
under `~/.mcp-auth/`, whose filenames are hashes. The alternatives are a disjunction, so they
go inside one expression:

```yaml
  monitorFilter:
    expressions:
    - name: mcp-config-or-credential-read
      expression: >-
        has(event.open) && (
          event.open.path.contains("/.mcp-auth/") ||
          event.open.path.endsWith("/.mcp.json") ||
          [
            "/mcp.json", "/mcp_config.json",
            "/claude_desktop_config.json", "/.claude.json",
          ].exists(f, event.open.path.endsWith(f))
        )
```

### Successive narrowing

Splitting a filter across expressions is where the AND and the short-circuit earn their place:
the guard is what lets the second expression dereference `event.exec` at all, because on an
`open` event the first expression is false and the second never runs.

```yaml
spec:
  mode: monitor
  behaviors:
  - exec:
      deny:
        values: ["*"]
  monitorFilter:
    expressions:
    - name: exec-events-only
      expression: 'has(event.exec)'
    - name: mcp-server-package
      expression: >-
        event.exec.argv.exists(a, a.startsWith("@modelcontextprotocol/")) ||
        event.exec.argv.exists(a, a.startsWith("mcp-server-")) ||
        event.exec.argv.exists(a, a.startsWith("mcp_server")) ||
        event.exec.argv.exists(a, a.startsWith("mcp/")) ||
        event.exec.argv.exists(a, a in ["mcp-remote", "supergateway", "mcpo"]) ||
        event.exec.argv.exists(a, !a.startsWith("-") && a.endsWith("-mcp"))
```

The `!a.startsWith("-")` guard is what stops `--no-mcp` matching the `-mcp` suffix rule: a flag
is never a package.

## Limits of monitor mode

The `network`, `open`, and `exec` observations are built on the counters the enforcement
eBPF programs already keep, and none of them observes TLS SNI or HTTP. `dns` is the
exception in shape — a program of its own, streamed rather than counted — and has its own
[limits](#limits-of-dns-reporting). These are real, current limits, not rounding errors:

- **`network`, `open`, and `exec` observation is poll-based.** Counters are drained every 10
  seconds, so a finding can lag the behavior by up to that interval, and only counts are
  preserved — not the ordering or timing of individual occurrences within a window. A `dns`
  question is a single record delivered as it happens, so only the reporter's flush
  interval applies to it.
- **Open/exec path counters cap per cgroup.** The per-cgroup path map holds 2048 distinct
  `(path, decision)` keys; a workload touching more than that within one poll interval loses
  the excess. The read-and-reset drain mitigates this but does not eliminate it.
- **Network observation is IPv4 only**, with no port or protocol, because the egress maps are
  keyed on a `u32` IPv4 address. An IPv6 connection is not observed at all — see
  [Limits of network enforcement](#limits-of-network-enforcement).
- **A destination is named only when the snooper learned it.** An observation carries a
  domain when the address came from a DNS answer for a name some policy already names
  (see [Limits of domain names](#limits-of-domain-names)); every other destination is
  reported by address alone.
- **Unsupported `network` targets are rejected, not skipped.** A CIDR wider than `/24`, a
  name whose wire encoding exceeds 128 bytes, and a pod's 257th distinct domain are all
  accepted by the schema and refused when programmed, so they are reported per value
  through `TargetsValid=False`. A CIDR of `/24` or narrower is expanded into individual
  addresses. An IPv6 literal is refused earlier, by the schema, so as a literal value it
  fails the policy to compile instead.
- **`open` and `exec` values are absolute literal paths, bounded at 127 bytes.** They are never
  split into tokens and never treated as globs; only the whole value `"*"` is the default-deny
  sentinel, and it must be written exactly — `" * "` is rejected, not treated as the wildcard. A
  longer value, an empty one, one carrying a NUL byte, or a relative one is rejected
  at admission and reported through `ExecRulesValid=False` / `OpenRulesValid=False` if it arrives
  from an `expression`.
- **`exec` selects a binary, never a command.** The key is the resolved program path, so allowing
  `/usr/bin/kubectl` allows every subcommand it has; arguments are not part of the key and cannot
  be enforced on. `kubectl` and `kubectl delete` are both rejected rather than accepted and then
  silently never matched — the kernel resolves paths with `bpf_d_path`, which always yields an
  absolute one.
- **Observations that cannot be attributed to a pod are dropped** and counted in
  `nirmata_runtime_attribution_misses_total`. Node-level and host-process activity is
  therefore not reported.
- **A `monitorFilter` narrows findings, not observation.** Recording in the kernel is
  unconditional, so a broad policy with a narrow filter costs exactly what the broad policy
  costs: the paths the filter rejects still occupy keys in the 2048-entry per-cgroup map and
  still displace others. What the filter buys is a Report a reader can use, and room under the
  500-result cap.

## Limits of protocol classification

The `protocol` behavior classifies each flow from its **first data segment**, in the kernel, and
nothing else. Its verdict is deferred until that segment exists, so a denial is a mid-connection
drop (the client sees a stalled connection and a timeout), not a `connect`-time error. These are
the honest boundaries of that design:

- **Traffic matching no signature classifies as `unclassified`.** It appears under that name in
  findings, metrics, and logs, but it is not a policy value: no `allow` entry can cover it, so
  under a default deny it is denied, and without one it is allowed. There is no third option.
- **Only client-speaks-first protocols are classifiable.** MySQL, SMTP, IMAP, POP3 and FTP start
  with a server banner the egress hook never sees; the client's first segment carries no usable
  signature, so those flows classify as `unclassified`.
- **`dns` is cleartext DNS over UDP only**, recognized by the query's shape — a clear QR bit,
  opcode 0, one question, no answers, and a well-formed name — never by port. DNS over TLS and
  DNS over HTTPS classify as `tls`, so a resolver pinned to DoT is covered by `tls` (or
  `tls/dot`), not by `dns`.
- **gRPC over TLS is indistinguishable from HTTPS.** Both negotiate ALPN `h2`; the header that
  separates them is inside the encryption. There is deliberately no `grpc` token — it would be a
  control that silently does nothing.
- **QUIC is identifiable as QUIC and nothing finer.** The Initial packet's ClientHello is
  encrypted under derived keys, so no SNI or ALPN survives. An HTTP/3 client is `quic`, never
  `tls/h3` — which is why `quic` is a first-class token: an `allow: ["tls"]` rule does not cover
  it.
- **`tls/<alpn>` matches the client's first (most-preferred) offered ALPN entry**, byte-exact. A
  ClientHello without an ALPN extension matches only the bare `tls` token. An Encrypted
  ClientHello hides SNI but not the outer ALPN.
- **A ClientHello that spans TCP segments classifies as `unclassified`**, not `tls` —
  post-quantum key shares routinely push it past one MTU. Under a default deny such a handshake
  is denied and reported as `unclassified`: a truncated handshake should not silently pass as
  TLS.
- **Classification happens once per flow** and the verdict is cached (an LRU map of 8192 flows
  per pod). Traffic that predates the policy, or an evicted entry, re-classifies on the next data
  segment, which for a mid-stream segment means `unclassified`.

## Worked examples

Each directory holds runnable manifests and a walkthrough. Every manifest under `examples/` is
validated in CI.

Network egress enforcement and observation require only a cgroup v2 host and BPF support; a
stock kind cluster on a Linux host qualifies.

File `open` and process `exec` enforcement need cgroup v2 and BPF as well, plus BTF at
`/sys/kernel/btf/vmlinux`. They use the BPF-LSM hooks where `bpf` appears in
`/sys/kernel/security/lsm`, and otherwise an `fmod_ret` program on `security_file_open`,
which additionally needs kernel 5.7 or later with BPF trampoline support. Only on the
BPF-LSM path is an exec also matched against `open` rules — see
[platform support](platforms.md).

| Example | Pattern it demonstrates | Mode | Requires |
| --- | --- | --- | --- |
| [block-known-bad-egress](../../../examples/egress/block-known-bad-egress/) | Deny a literal destination IPv4 with `deny.values` | `enforce` | cgroup v2 |
| [default-deny-egress](../../../examples/egress/default-deny-egress/) | `deny.values: ["*"]` plus an `allow` list | `enforce` | cgroup v2 |
| [egress-to-cluster-service](../../../examples/egress/egress-to-cluster-service/) | Cluster Service DNS names in `allow.values` under default deny, with the API server denied by omission | `enforce` | cgroup v2 |
| [egress-to-domain-name](../../../examples/egress/egress-to-domain-name/) | An external domain name in `allow.values`, alongside cluster DNS named as a Service | `enforce` | cgroup v2 |
| [monitor-egress](../../../examples/monitoring/monitor-egress/) | Same policy shape observed instead of blocked | `monitor` | cgroup v2 |
| [report-unexpected-dns](../../../examples/shadow-ai/report-unexpected-dns/) | A `dns` allow list with a left-wildcard, plus the `deny: ["*"]` discovery form | `monitor` | cgroup v2 |
| [detect-mcp-config-access](../../../examples/shadow-ai/detect-mcp-config-access/) | `open` deny over absolute MCP configuration paths, reported not blocked | `monitor` | BPF-LSM |
| [deny-sensitive-file-access](../../../examples/files-and-processes/deny-sensitive-file-access/) | `open` deny with `values` unioned with a `variables` expression | `enforce` | BPF-LSM |
| [restrict-exec-allowlist](../../../examples/files-and-processes/restrict-exec-allowlist/) | Default-deny `exec` with an allow-list | `enforce` | BPF-LSM |
| [tls-only-egress](../../../examples/egress/tls-only-egress/) | `protocol` default deny allowing only `tls` and `dns` | `enforce` | cgroup v2 |
| [monitor-workload-baseline](../../../examples/monitoring/monitor-workload-baseline/) | `network`, `exec`, and `open` observed together | `monitor` | BPF-LSM for `open`/`exec`; egress findings alone need only cgroup v2 |
| [blocklist-from-configmap](../../../examples/dynamic-lists/blocklist-from-configmap/) | `resource.get` with `evaluationInterval` | `enforce` | cgroup v2 |
| [blocklist-from-http](../../../examples/dynamic-lists/blocklist-from-http/) | `http.get` with the `dyn` coercion | `enforce` | cgroup v2 |
| [blocklist-from-json](../../../examples/dynamic-lists/blocklist-from-json/) | `json.unmarshal` composed with `resource.get` | `monitor` | cgroup v2 |
| [enforce-workload-baseline](../../../examples/files-and-processes/enforce-workload-baseline/) | All three behaviors under default-deny with `evaluationInterval` | `enforce` | BPF-LSM |

The full catalog, grouped by feature, is in [Examples](../examples.md).
