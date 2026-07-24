# DESIGN

This document describes the architecture of kyverno-runtime **as implemented on `main`
today**. It intentionally does not cover planned or aspirational work — a `docs/dev/PLAN.md`
tracking future work does not currently exist in this repository (see
[Agents.md](../../Agents.md)); create one if forward-looking roadmap tracking is needed.

Every claim in this document is grounded in the current code: `api/v1alpha1/`, `cmd/kyverno-runtime/`,
`pkg/`, and `charts/kyverno-runtime/`. Where the implementation is incomplete or diverges from
what the API/docs imply, it is called out explicitly in [Known Gaps](#known-gaps--future-work)
rather than glossed over.

> Historical note: an earlier version of this project was built around Inspektor Gadget-based
> event collection with a `RuntimeBehavior` CRD and a detection/reporting pipeline. That design
> was replaced in commit `f806f25` ("kyverno-runtime alpha release") with the eBPF LSM + CEL
> architecture described below. The old `DESIGN.md`/`PLAN.md` were removed in that same commit;
> this document replaces them for the current architecture.

## Table of Contents

- [Overview](#overview)
- [Components](#components)
- [RuntimePolicy: schema and semantics](#runtimepolicy-schema-and-semantics)
- [Compilation and evaluation pipeline](#compilation-and-evaluation-pipeline)
- [CEL extension libraries](#cel-extension-libraries)
- [Enforcement: eBPF LSM hooks and egress filtering](#enforcement-ebpf-lsm-hooks-and-egress-filtering)
- [Helm chart / deployment shape](#helm-chart--deployment-shape)
- [Known Gaps / Future Work](#known-gaps--future-work)

## Overview

kyverno-runtime enforces and observes pod behavior — file opens, process execution, and network
egress — using eBPF, driven by a single cluster-scoped CRD:

- `RuntimePolicy` (`api/v1alpha1/runtimepolicy_types.go`): selects pods and declares allow/deny
  rules for `network`, `exec`, and `open` behaviors.

There is no admission webhook in this project; policies are enforced entirely at runtime via
eBPF programs attached from a per-node daemon.

## Components

The binary at `cmd/kyverno-runtime/` (`root.go`) exposes one subcommand:

### `kyverno-runtime daemon`

Implemented in `cmd/kyverno-runtime/daemon.go`. Deployed as a `DaemonSet`
(`charts/kyverno-runtime/templates/daemonset.yaml`), one instance per node, requiring `NODE_NAME`
and running privileged with `hostPID: true` (needed to attach LSM/cgroup eBPF programs and to
resolve container cgroup paths under `/host`, `/run`, `/sys/fs/bpf`, `/sys/kernel/debug`, and
`/sys/kernel/tracing`).

On startup it wires together:

- `pkg/compiler`: compiles `RuntimePolicy` objects into CEL programs (`compiler.NewCompiler`).
- `pkg/controller.NewRuntimePolicyMgr`: a `SharedInformerFactory`-based watcher for
  `RuntimePolicy` objects (cluster-scoped, so every daemon watches all policies).
- `pkg/controller.NewPodWatcher`: watches `Pod` objects filtered to `spec.nodeName=<NODE_NAME>`
  and `status.phase=Running`, resolving each pod's container cgroup info
  (`pkg/containers.ResolveCgInfos`).
- `pkg/lsmmgr.LsmManager` and `pkg/egressmgr.EgressManager`: the two `events.EventIface`
  implementations that receive `PodEvent` and `RuntimePolicyEvent` callbacks and drive the actual
  eBPF attachments (see [Enforcement](#enforcement-ebpf-lsm-hooks-and-egress-filtering)).

The daemon waits for the `RuntimePolicy` informer cache to sync before starting the pod watcher,
so newly-observed pods are evaluated against the full set of currently-known policies.

## RuntimePolicy: schema and semantics

`RuntimePolicySpec` (`api/v1alpha1/runtimepolicy_types.go`) has exactly these fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `podSelector` | `*metav1.LabelSelector` | Pods this policy applies to. |
| `evaluationInterval` | `*metav1.Duration` | If set, the policy is periodically re-evaluated (`controller.evaluateForInterval`) instead of only on create/update. |
| `variables` | `[]admissionregistrationv1.Variable` | Named CEL expressions reusable across behaviors via `variables.<name>`. |
| `behaviors` | `[]PolicyBehavior` | The allow/deny rules, one entry per behavior type. |
| `mode` | `*RuntimePolicyMode` | `monitor` or `enforce`. Added in `4a8bcb1`. Only `enforce` currently does anything — see [Known Gaps](#known-gaps--future-work). |

Each `PolicyBehavior` entry must set **exactly one** of `network`, `exec`, or `open`, enforced by
an `XValidation` rule: `(has(self.network) ? 1 : 0) + (has(self.exec) ? 1 : 0) + (has(self.open) ? 1 : 0) == 1`.
Each behavior (`Behavior` type) has an optional `allow` and/or `deny` (`BehaviorRule`), and each
rule has a literal `values []string` and/or a CEL `expression string` — the compiler unions the
two (`pkg/compiler/compiler.go: compileBehavior`, `pkg/compiler/policy.go: evalCompiledBehavior`).

Semantics (see `docs/runtimepolicy.md` for the full reference with examples):

- `network` values are IPv4 addresses (egress), `exec` values are command names/paths, `open`
  values are file paths.
- `deny.values: ["*"]` (or an expression producing `["*"]`) is a **default-deny** sentinel for
  that behavior type. This is evaluated **across all `RuntimePolicy` objects matching a pod**: if
  any matching policy sets default-deny for a behavior, that behavior becomes deny-all-except-allowed
  for the pod, and the allow list is the union of every matching policy's `allow` entries for that
  behavior. If no matching policy sets default-deny, the behavior defaults to allow-all-except-denied,
  with the deny list being the union of every matching policy's `deny` entries. This union-across-policies
  behavior is implemented per-behavior-type in `pkg/egressmgr` (network/IPs) and `pkg/lsmmgr` (open)
  by tracking, per pod, the set of policy UIDs that assert a default deny
  (`podAttachment.defaultDeny` / equivalent) and only clearing the default-deny eBPF flag once none
  remain.
- `expression` must evaluate to a statically-typed `list(string)`; the compiler rejects any other
  output type at `Compile` time (`ast.OutputType().IsExactType(types.NewListType(types.StringType))`).

## Compilation and evaluation pipeline

`pkg/compiler` turns a `RuntimePolicy` into a `CompiledRuntimePolicy` and, on evaluation, into an
`EvaluationResult`:

1. `compiler.NewCompiler(dynamic.Interface)` builds one shared `cel.Env` per daemon process
   (`pkg/compiler/env.go: newEnv`), extended with a custom `variables` object type
   (`pkg/compiler/variables.go`) whose fields are registered per-policy as `spec.variables` are
   compiled.
2. `Compiler.Compile(rp)` compiles `spec.variables` and each behavior's `allow`/`deny` expressions
   into `cel.Program`s, returning a `*CompiledRuntimePolicy` that also carries the raw
   `podSelector` and `evaluationInterval`.
3. `CompiledRuntimePolicy.Evaluate(ctx)` (`pkg/compiler/policy.go`) evaluates the variables (lazily,
   via `k8s.io/apiserver/pkg/cel/lazy.MapValue`) and each compiled behavior, unions literal
   `values` with the CEL expression's result, and returns an `EvaluationResult{UID, IPs, Open, Exec,
   Selector}` where `IPs`/`Open`/`Exec` are each an `AllowDenyPair{Allow, Deny []string}`.

`pkg/controller.RuntimePolicyMgr` (`runtimepolicy_informer.go`) drives this: on `RuntimePolicy`
create/update/delete informer events it compiles/evaluates the policy and fans the resulting
`EvaluationResult` out to every registered `events.EventIface` (currently `LsmManager` and
`EgressManager`) via `RuntimePolicyEvent`. If `evaluationInterval` is set, a background goroutine
re-evaluates and re-dispatches on that interval until the policy is deleted or the interval
changes.

`pkg/controller.podWatcher` similarly watches `Pod` objects on the local node and fans
`PodEvent(pod, cgInfos, eventType)` out to the same handlers, so pod lifecycle and policy
lifecycle are two independent event streams that both mutate the same manager state
(`LsmManager`/`EgressManager` each hold a mutex-guarded map of policies and pods, matching
selectors against pod labels on both sides).

## CEL extension libraries

The base CEL environment (`pkg/compiler/env.go: newBaseEnv`) registers the standard `cel-go`
extension libraries (`ext.Bindings`, `ext.Encoders`, `ext.Lists`, `ext.Math`, `ext.Protos`,
`ext.Sets`, `ext.Strings`) plus the Kubernetes CEL libraries from
`k8s.io/apiserver/pkg/cel/library` (`CIDR`, `Format`, `IP`, `Lists`, `Regex`, `URLs`, `Quantity`,
`SemverLib`). On top of that, `newEnv` adds three Kyverno SDK libraries
(`github.com/kyverno/sdk/extensions/cel/libs/...`):

- `resource.get(apiVersion, resource, namespace, name)` / list — backed by
  `pkg/compiler/resourceprovider.go`, which uses a `dynamic.Interface` client to fetch arbitrary
  cluster resources (e.g. a `ConfigMap`) at evaluation time.
- `http.get(url)` — returns `{"statusCode": ..., "body": ...}` for fetching allow/deny data from
  an external HTTP endpoint.
- `json.unmarshal(str)` — parses a JSON string into a CEL value.

Because `http.get(...).body` and `json.unmarshal(...)` return `dyn`, an expression using them
needs an explicit coercion (e.g. `.map(x, string(x))`) since the checker can't infer the
`list(string)` element type from `dyn`. See `docs/runtimepolicy.md` for worked examples of all
three libraries, including composing `json.unmarshal` with `resource.get`/`http.get` output.

Because `resource.get`/`http.get` results are only refreshed when the policy is (re-)evaluated,
any policy relying on external/mutable state should set `evaluationInterval` to periodically pick
up changes.

## Enforcement: eBPF LSM hooks and egress filtering

### File open (`pkg/lsmmgr`, `pkg/bpf/lsm`)

`LsmManager` (`pkg/lsmmgr/lsmmgr.go`) is the `events.EventIface` responsible for the `open`
behavior. On `RuntimePolicyEvent` create, if the evaluated policy has any `Open.Allow`/`Open.Deny`
entries, `rpCreated` (`pkg/lsmmgr/runtimepolicies.go`) instantiates one
`lsm.NewForAttachTarget(logger, "file_open")` enforcer (`pkg/bpf/lsm/lsm.go`), loads the compiled
`lsmGeneric` BPF object (`pkg/bpf/lsm/_cprog/lsm.bpf.c`, attach type `ebpf.AttachLSMMac`), attaches
it, populates its `Banned`/`Allowed` path maps from the policy's `Open` pair, and sets a
`DefaultDeny` map entry if the policy's deny list contains `"*"`. Matched pods' cgroup IDs
(resolved by `pkg/containers`) are added to the enforcer's `Cgids` map so the BPF program only
acts on those cgroups. `PodEvent` and `rpUpdated` incrementally add/remove cgids and path entries
as pods and policies change.

### Network egress (`pkg/egressmgr`, `pkg/bpf/egressfilter`)

`EgressManager` (`pkg/egressmgr/egressmgr.go`) is the `events.EventIface` for the `network`
behavior. Unlike `LsmManager` (one shared LSM program with a cgid allowlist), each matched pod
gets its own `egressfilter.EgressFilter` (`pkg/bpf/egressfilter/egressfilter.go`), a
`cgroup/skb egress` BPF program (`pkg/bpf/egressfilter/_cprog/probe.c`) attached per-container
cgroup path via `link.AttachCgroup(..., Attach: ebpf.AttachCGroupInetEgress)`. `AddIps`/`DeleteIps`
populate that pod's `AllowedIps`/`BannedIps` maps (parsed as IPv4 only —
`egressfilter.normalizeIP`), and `SetFlagIdx(egressfilter.DEFAULT_DENY, ...)` toggles default-deny
for that pod's filter. `pkg/egressmgr/runtimepolicies.go` implements the same
default-deny-union-across-policies bookkeeping described above, per pod (`podAttachment.defaultDeny`).

### Exec behavior

`exec` behaviors are fully supported through compilation and evaluation
(`CompiledRuntimePolicy.compiledExecs` / `EvaluationResult.Exec`) — see
[Known Gaps](#known-gaps--future-work) for the enforcement status.

## Helm chart / deployment shape

`charts/kyverno-runtime/` installs:

- A `DaemonSet` (`templates/daemonset.yaml`) running `kyverno-runtime daemon`, always installed,
  privileged, `hostPID: true`, with host mounts for `/`, `/run`, `/var/run`, `/sys/fs/bpf`,
  `/sys/kernel/debug`, and `/sys/kernel/tracing`, and `NODE_NAME` injected from
  `spec.nodeName`.
- A shared `ClusterRole`/`ClusterRoleBinding`/`ServiceAccount`
  (`templates/clusterrole.yaml`, `templates/clusterrolebinding.yaml`, `templates/serviceaccount.yaml`),
  with `values.daemon.rbac.extraRules` as an escape hatch for granting the daemon access to
  additional resource types referenced by the `resource` CEL library.
- The `RuntimePolicy` CRD (`charts/kyverno-runtime/crds/`), plus the
  vendored OpenReports CRDs (`openreports.io_*`) — the OpenReports API is registered into the
  daemon's scheme (`openreportsv1alpha1.Install(scheme)`) but is not otherwise used by any code
  path described above; no component in this repo currently creates or reconciles `Report`/`ClusterReport`
  objects.

## Known Gaps / Future Work

These are verified, current limitations — not planned features to build toward, which belong in a
future `PLAN.md`:

- **`spec.mode: monitor` silently disables a policy instead of observing it.** The `Mode` field
  was added to `RuntimePolicySpec` in `4a8bcb1` and is threaded through `pkg/compiler`
  (`CompiledRuntimePolicy.mode` → `EvaluationResult.Mode`), so the field and its print column now
  work. But both managers treat it purely as an on/off gate: `rpCreated` returns early unless the
  mode is exactly `enforce` (`pkg/egressmgr/runtimepolicies.go`, `pkg/lsmmgr/runtimepolicies.go`),
  and `rpUpdated` treats any non-`enforce` mode as a *delete*. Nothing else in the tree reads
  `Mode`. A `monitor`-mode policy therefore enforces nothing, reports nothing, and writes no
  status — it is indistinguishable from having no policy at all, which is the opposite of what a
  user trialling a policy before enforcing it would expect.

  Monitor mode is not implementable without three pieces that do not exist yet: a kernel→userspace
  event channel (both BPF programs are map-lookup enforcers with no ring buffer, and
  `events.EventIface` carries only pod and policy lifecycle callbacks), a finding sink
  (`openreportsv1alpha1.Install(scheme)` is called but no code ever writes a `Report`), and status
  reporting. Tracked in #42; the pipeline it needs overlaps #17 and #29.
- **`exec` behaviors compile and evaluate but are not enforced.** `PolicyBehavior.Exec` is
  compiled by `pkg/compiler` and appears in `EvaluationResult.Exec`, and the BPF LSM program
  (`pkg/bpf/lsm/_cprog/lsm.bpf.c`) supports a second attach target for this
  (`bprm_check_security`, `argTypeExecCheck` in `pkg/bpf/lsm/lsm.go`). But `pkg/lsmmgr` only ever
  instantiates an LSM enforcer for the `file_open` target (`lsm.NewForAttachTarget(&l.logger,
  "file_open")` in `pkg/lsmmgr/runtimepolicies.go`) and only ever reads/writes
  `compiledRp.Open`; `compiledRp.Exec` is never consulted by `lsmmgr` or `egressmgr`. A
  `RuntimePolicy` with only `exec` rules will compile, apply, and report success, but has no
  runtime effect. Tracked in #34.
- **Container attribution only covers containerd with the systemd cgroup driver.**
  `pkg/containers.buildCandidatePaths` only ever generates `cri-containerd-<id>.scope` leaf names,
  so on CRI-O or Docker nodes no candidate path resolves, no cgroup ID reaches the `cgids` maps
  both engines gate on, and **no policy is enforced on that node** — silently, with the policy
  still appearing healthy. cgroup v1 is likewise unhandled. Tracked in #38.
- **Non-IPv4 network targets are silently dropped.** `egressfilter.normalizeIP` accepts only bare
  IPv4 literals; IPv6 addresses, CIDR blocks, and hostnames fail to parse, are logged at `V(2)`,
  and are skipped. The BPF program is IPv4-only by construction (`u32` map key, reads only
  `ip->daddr`, no L4 parsing). Tracked in #41.
- **No reporting, metrics, or status.** Nothing writes `Report`/`ClusterReport` objects, no metrics
  are registered, and `RuntimePolicyStatus`'s `ObservedPods`/`ViolatingPods`/`LastEvaluatedTime`
  are declared and print-columned but never populated (#44). The only observable output today is
  `logger.V(2)` lines and the `-EPERM`/packet-drop side effects themselves. Tracked in #29 and #17.
- **No tests.** `go test ./...` reports `[no test files]` for every package, and eBPF paths are not
  exercised in CI at all. Tracked in #15.
- **No promotion workflow.** There is no code path that turns observed behavior into a proposed
  `RuntimePolicy` allow/deny list. The intent is for that promotion step to become a separate,
  LLM-assisted project rather than a CLI command added to this repository.
