# Dynamic lists

Allow and deny lists do not have to be literals. A behavior's `expression` can fetch one from
the cluster or from an HTTP endpoint, and `spec.evaluationInterval` sets how often that
happens — so a list that changes faster than a release is maintained where it belongs rather
than in the policy.

An expression must type-check to `list(string)`; a `dyn` result needs `.map(x, string(x))`.
The `http`, `resource`, and `json` libraries are available here and deliberately **not**
inside a `monitorFilter`, which runs once per kernel observation. See
[the CEL reference](../../docs/users/reference/cel.md) for the signatures.

| Directory | Scenario | Mode | Requires |
| --- | --- | --- | --- |
| [blocklist-from-configmap](blocklist-from-configmap/) | The security team manages the egress blocklist in a ConfigMap, with no policy edits | enforce | cgroup v2, plus ConfigMap read for the daemon |
| [blocklist-from-http](blocklist-from-http/) | Pull the deny list from a threat-intel HTTP feed | enforce | cgroup v2 |
| [blocklist-from-json](blocklist-from-json/) | Parse a JSON blob from a ConfigMap into a deny list | monitor | cgroup v2, plus ConfigMap read for the daemon |

The chart's default ClusterRole grants the daemon no ConfigMap access, so the two examples
using the `resource` library each ship a `daemon.rbac.extraRules` values snippet their README
applies before the policy. See [installation](../../docs/users/installation.md) for the
values reference.
