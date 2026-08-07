# Egress control

Deciding which destinations a workload may reach, and over which protocols. A `network`
behavior names destinations by address, CIDR, cluster Service DNS name, or external domain
name; a `protocol` behavior decides what may be spoken to them, classified from the first
data segment of each flow.

All of these need only a cgroup v2 host — no BPF-LSM kernel.

| Directory | Scenario | Mode |
| --- | --- | --- |
| [block-known-bad-egress](block-known-bad-egress/) | Stop a pod from reaching one known-bad destination address, leaving the rest of its egress alone | enforce |
| [default-deny-egress](default-deny-egress/) | Contain a compromised pod: block all egress except one approved service | enforce |
| [egress-to-cluster-service](egress-to-cluster-service/) | Force egress through a gateway without hardcoding its addresses | enforce |
| [egress-to-domain-name](egress-to-domain-name/) | Allow an external destination by DNS name rather than address | enforce |
| [tls-only-egress](tls-only-egress/) | Force a workload to speak only TLS, whatever port it uses | enforce |
| [protocol-default-deny](protocol-default-deny/) | The same default deny, with the allowed and denied protocols exercised on one port | enforce |
| [egress-baseline-combined](egress-baseline-combined/) | Every network-side field in one annotated policy, with the accepted values for each | enforce |
| [overlapping-egress-policies](overlapping-egress-policies/) | Two policies over one pod, and a pod that starts after them | enforce |

`block-known-bad-egress` is the scenario the
[quickstart](../../docs/users/quickstart.md) walks through. Start there.

To see where a workload actually connects before turning any of this on, use
[monitoring/monitor-egress](../monitoring/monitor-egress/). To keep a deny list current
without editing policies, see [dynamic-lists/](../dynamic-lists/).

A value in the form `<service>.<namespace>.svc.cluster.local` is resolved from Service and
EndpointSlice informers; any other fully qualified domain name is learned from the pod's own
DNS answers, which is not a containment boundary. The two mechanisms have different failure
modes — see
[limits of cluster Service targets](../../docs/users/reference/runtimepolicy.md#limits-of-cluster-service-targets)
and [limits of domain names](../../docs/users/reference/runtimepolicy.md#limits-of-domain-names).
