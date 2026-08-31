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
>
> A second round of removals landed in `fd9dfe0` (#32): the `WorkloadProfile` CRD, the learning-mode
> gRPC API (`pkg/srv`), and the `ctrl` component are gone, so `RuntimePolicy` is now the only CRD
> this project owns and `daemon` is the only component. Some residue of learning mode is still
> visible in the BPF sources — see [Known Gaps](#known-gaps--future-work).

## Table of Contents

- [Overview](#overview)
- [Components](#components)
- [RuntimePolicy: schema and semantics](#runtimepolicy-schema-and-semantics)
- [Compilation and evaluation pipeline](#compilation-and-evaluation-pipeline)
- [CEL extension libraries](#cel-extension-libraries)
- [Enforcement: eBPF LSM hooks and egress filtering](#enforcement-ebpf-lsm-hooks-and-egress-filtering)
- [The event plane](#the-event-plane)
- [Redaction chokepoint](#redaction-chokepoint)
- [Status reporting](#status-reporting)
- [Metrics](#metrics)
- [Helm chart / deployment shape](#helm-chart--deployment-shape)
- [Known Gaps / Future Work](#known-gaps--future-work)

## Overview

kyverno-runtime enforces and observes pod behavior — file opens, process execution, network
egress, and DNS resolution — using eBPF, driven by a single cluster-scoped CRD:

- `RuntimePolicy` (`api/v1alpha1/runtimepolicy_types.go`): selects pods and declares allow/deny
  rules for `network`, `exec`, `open`, and `dns` behaviors. The first three are enforced or
  observed; `dns` is observed only.

There is no admission webhook in this project; policies are enforced entirely at runtime via
eBPF programs attached from a per-node daemon.

## Components

The binary at `cmd/kyverno-runtime/` (`root.go`) exposes one subcommand:

### `kyverno-runtime daemon`

Implemented in `cmd/kyverno-runtime/daemon.go`. Deployed as a `DaemonSet`
(`charts/kyverno-runtime/templates/daemonset.yaml`), one instance per node, requiring `NODE_NAME`
and running privileged with `hostPID: true`, which is what lets it attach LSM and cgroup eBPF
programs. Container cgroup paths are resolved from the cgroup mount found in
`/proc/self/mountinfo` (`pkg/containers`), not from a host filesystem mount.

On startup it wires together:

- `pkg/compiler`: compiles `RuntimePolicy` objects into CEL programs (`compiler.NewCompiler`).
- `pkg/controller.NewRuntimePolicyMgr`: a `SharedInformerFactory`-based watcher for
  `RuntimePolicy` objects (cluster-scoped, so every daemon watches all policies).
- `pkg/controller.NewPodWatcher`: watches `Pod` objects filtered to `spec.nodeName=<NODE_NAME>`
  and `status.phase=Running`, resolving each pod's container cgroup info
  (`pkg/containers.ResolveCgInfos`).
- `pkg/lsmmgr.LsmManager` and `pkg/egressmgr.EgressManager`: both an `events.PodEventHandler` and
  an `events.RuntimePolicyEventHandler`; they drive the actual eBPF attachments (see
  [Enforcement](#enforcement-ebpf-lsm-hooks-and-egress-filtering)).
- `pkg/dnsmgr.Manager`: the same pair of interfaces for the DNS question observer, deciding which
  pods it is attached to and gated in for (see [The event plane](#the-event-plane)). Wired only if
  `pkg/bpf/dnsquery` loads; a kernel that refuses the program leaves every other behavior working.
- `pkg/attribution.Index` is a `PodEventHandler`; `pkg/controller.StatusWriter` and
  `pkg/monitor.Monitor` are `RuntimePolicyEventHandler`s — the cgroup→pod index, the status writer,
  and the monitor-mode evaluator (see [The event plane](#the-event-plane)).
- `pkg/metrics`, `pkg/collector`, `pkg/reporter`: the Prometheus registry and `/metrics` server,
  the observation pipeline, and the OpenReports writer.
- `pkg/reportevents.Recorder`, wired only when `--events-enabled` is set: emits Kubernetes Events
  from the reporter's flush and from `StatusWriter`'s condition-change callback (see
  [Kubernetes Events](#kubernetes-events)).

`runDaemon` is the single wiring site; the two typed handler slices are what the compiler checks:

```text
metrics registry + Serve(--metrics-addr)    -> errgroup
attribution.NewIndex(WithMetrics)
reporter.New(controller-runtime client)     -> Run in errgroup
controller.NewStatusWriter(nodeName, 30s)   -> Run in errgroup
egressmgr.NewEgressManager(log, statusWriter, onLoss -> EventsDropped)
lsmmgr.NewLsmManager(log, statusWriter, onLoss -> EventsDropped)
monitor.New(log, reporter, metrics)
podHandlers    = [em, lsmm, attrIdx]        (+ dm when dnsquery loaded)
policyHandlers = [em, lsmm, statusWriter, monitor]  (+ dm when dnsquery loaded)
dnsquery.New() -> dnsmgr.New(dm) + dnsquery.NewSource(WithLossFunc -> EventsDropped)
collector: PollSource(egress-observe, 10s) + PollSource(lsm-observe, 10s)
           + Source(dnsquery, ring buffer)
           -> Stage(attrIdx) -> Sink(monitor)                -> Run in errgroup
RuntimePolicy informer -> wait for cache sync -> pod watcher  -> both in errgroup
```

Handler fan-out is ordered, so `attribution.Index` learns a pod's cgroups before `Monitor` can
be asked about that pod's events. Every long-running component joins one `errgroup` rooted at
the signal-handler context, so a fatal error in any of them shuts the daemon down.

The daemon waits for the `RuntimePolicy` informer cache to sync before starting the pod watcher,
so newly-observed pods are evaluated against the full set of currently-known policies.

## RuntimePolicy: schema and semantics

`RuntimePolicySpec` (`api/v1alpha1/runtimepolicy_types.go`) has exactly these fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `podSelector` | `*metav1.LabelSelector` | Pods this policy applies to. Absent and `{}` both select every pod. An `enforce`-mode policy must set this or `namespaceSelector`, enforced by an `XValidation` rule on the spec. |
| `namespaceSelector` | `*metav1.LabelSelector` | Narrows `podSelector` to pods in namespaces carrying these labels. Absent and `{}` both select every namespace. ANDed with `podSelector`. |
| `evaluationInterval` | `*metav1.Duration` | If set, the policy is periodically re-evaluated (`controller.evaluateForInterval`) instead of only on create/update. |
| `variables` | `[]admissionregistrationv1.Variable` | Named CEL expressions reusable across behaviors via `variables.<name>`. |
| `behaviors` | `[]PolicyBehavior` | The allow/deny rules, one entry per behavior type. |
| `mode` | `*RuntimePolicyMode` | `monitor` or `enforce`. `enforce` programs the deny/allow maps; `monitor` attaches the same programs with empty maps and evaluates observations in userspace (see [The event plane](#the-event-plane)). Defaults to `monitor` (`+kubebuilder:default=monitor`), so an omitted `mode` is observed and reported rather than inert. |
| `monitorFilter` | optional, `expressions` list of `name`/`expression` | A per-event CEL predicate narrowing which monitor-mode observations become findings (see [Filtering findings](#filtering-findings-specmonitorfilter)). Bounded by `MinItems=1`/`MaxItems=64`, and refused alongside `mode: enforce`. |

Each `PolicyBehavior` entry must set **exactly one** of `network`, `exec`, `open`, `protocol`, or
`dns`, enforced by an `XValidation` rule counting the five `has(self.*)` results. `spec.behaviors`
carries a `MaxItems` bound because the API server estimates a per-item rule's cost as the rule's
cost times the largest number of items a request could carry: unbounded, the five-way rule is
refused at apply time for exceeding the CEL cost budget.
Each behavior (`Behavior` type) has an optional `allow` and/or `deny` (`BehaviorRule`), and each
rule has a literal `values []string` and/or a CEL `expression string` — the compiler unions the
two (`pkg/compiler/compiler.go: compileBehavior`, `pkg/compiler/policy.go: evalCompiledBehavior`).

Semantics (see `docs/users/reference/runtimepolicy.md` for the full reference with examples):

- `network` values are IPv4 addresses, CIDRs, cluster Service DNS names and external domain names
  (egress), `exec` values are command names/paths, `open` values are file paths, `dns` values are
  hostnames or left-wildcards.
- `protocol` values are application-protocol tokens for egress flows, classified from the first
  data segment of a connection: `ssh`, `tls`, `tls/<alpn>`, `dns`, `http/1.1`, `http/2`, and
  `quic`. A token names the outermost thing the classifier recognized, not a security property:
  `tls/` means a TLS record layer was observed on the wire, and its absence says nothing about
  encryption (`ssh` and `quic` are both encrypted). Traffic
  matching no signature is classified `unclassified` — observation vocabulary only, visible in
  findings and metrics but rejected by the schema, so only a default deny covers it. The
  schema is defined once, in `pkg/compiler/protocolvalue.go: ParseProtocolValue`, and consumed
  by admission validation, program-time map filling (`protofilter.ParseTargets`) and
  monitor-mode matching.
- `deny.values: ["*"]` (or an expression producing `["*"]`) is a **default-deny** sentinel for that
  behavior type: that behavior becomes deny-all-except-allowed for matched pods, instead of the
  default allow-all-except-denied. On a `dns` behavior it means "report every name" instead, and
  short-circuits the allow list rather than exempting it.
- A `dns` behavior is observation only, and `pkg/compiler.validateDNSBehavior` rejects it in
  `enforce` mode with a message naming `monitor` and the `network` behavior. The two schemas are
  one function apart on purpose: `ParseDNSValue` accepts a left-wildcard and `ParseNetworkValue`
  rejects one, because a `network` target has to be resolved to addresses and programmed into a
  kernel map while a `dns` value is only ever compared against an observed question name. What a
  hostname *is* comes from a single `validHostname`, so nothing else can drift between them.
  Enforcing a destination named by domain is the `network` behavior's job
  (`egressfilter.ParseTargets` → the domain maps), which is why accepting `enforce` on `dns` would
  be a second spelling of one intent with only one of them working.
- `docs/users/reference/runtimepolicy.md` specifies the multi-policy case as a **union across all `RuntimePolicy`
  objects matching a pod** — any matching policy asserting default-deny flips the behavior, and the
  effective allow (or deny) list is the union of every matching policy's entries. The two enforcing
  managers implement it differently. `pkg/egressmgr` unions in userspace: one filter per pod, every
  matching policy's IPs merged into it, with the set of policy UIDs asserting default-deny tracked
  in `podAttachment.defaultDeny` so the eBPF flag is cleared only once none remain. `pkg/lsmmgr`
  unions in the kernel: each policy keeps its own enforcer and map set, but the enforcers for a
  hook run as one tail-call chain sharing a verdict in `ctx_map`, so one policy's explicit allow
  lifts another policy's default-deny (see
  [File open and exec](#file-open-and-exec-pkglsmmgr-pkgbpflsm)).
- A `monitorFilter` is refused on an `enforce` policy by a spec-level `XValidation` rule and again
  by the compiler. The asymmetry between the two kinds of finding is the reason: a monitor finding
  is a counterfactual, and under `deny: ["*"]` that is every open and every exec, while an enforce
  finding is the record that the kernel actually blocked something — bounded, individually
  meaningful, and an audit record that suppression would destroy. Rejecting the combination rather
  than ignoring the field also keeps it from being silently inert, since `handleEvent` sets
  `Enforced` only in the `ModeEnforce` branch and a filter there would compile, apply, and change
  nothing.
- A behavior or `variables` `expression` must evaluate to a statically-typed `list(string)`; the
  compiler rejects any other output type at `Compile` time
  (`ast.OutputType().IsExactType(types.NewListType(types.StringType))`). A `monitorFilter`
  expression is checked the same way against `types.BoolType`.

## Compilation and evaluation pipeline

`pkg/compiler` turns a `RuntimePolicy` into a `CompiledRuntimePolicy` and, on evaluation, into an
`EvaluationResult`:

1. `compiler.NewCompiler(dynamic.Interface)` builds one shared `cel.Env` per daemon process
   (`pkg/compiler/env.go: newEnv`), extended with a custom `variables` object type
   (`pkg/compiler/variables.go`) whose fields are registered per-policy as `spec.variables` are
   compiled.
2. `Compiler.Compile(rp)` compiles `spec.variables` and each behavior's `allow`/`deny` expressions
   into `cel.Program`s, returning a `*CompiledRuntimePolicy` that also carries the compiled
   `PodTarget` and `evaluationInterval`. Both selectors are converted here rather than per
   evaluation, so a malformed one is a `CompileFailed` condition rather than an error the
   re-evaluation loop retries.
3. `CompiledRuntimePolicy.Evaluate(ctx)` (`pkg/compiler/policy.go`) evaluates the variables (lazily,
   via `k8s.io/apiserver/pkg/cel/lazy.MapValue`) and each compiled behavior, unions literal
   `values` with the CEL expression's result, and returns an `EvaluationResult{UID, Name, Mode, IPs,
   Open, Exec, DNS, AppliesTo}` where `IPs`/`Open`/`Exec`/`DNS` are each an
   `AllowDenyPair{Allow, Deny []string}`. A policy carrying a `monitorFilter` also compiles each of
   its expressions to a `bool`-typed program, which rides the evaluation result out to the monitor
   like every other per-policy fact.

Both compile and evaluate run inside `utils.Guard`, which converts a panic from user-authored CEL
(or from a library binding reached through it) into an ordinary error carrying the operation name. `resource.toGVR` returns an error instead of panicking on an unparsable `apiVersion`, and
`compiler.ValidateNetworkValues` reports unusable `network` values with their field path. Nothing
reachable from a `RuntimePolicy` field, a pod object, or kernel-supplied bytes is allowed to panic
the daemon.

`pkg/controller.RuntimePolicyMgr` (`runtimepolicy_informer.go`) drives this: on `RuntimePolicy`
create/update/delete informer events it compiles/evaluates the policy and fans the resulting
`EvaluationResult` out to every registered `events.RuntimePolicyEventHandler` — `EgressManager`,
`LsmManager`, `StatusWriter`, `Monitor` — via `RuntimePolicyEvent`, each call wrapped in
`utils.Guard` so one handler's panic cannot take the informer down. If `evaluationInterval` is set, a background goroutine
re-evaluates and re-dispatches on that interval until the policy is deleted or the interval
changes.

Both informers queue a typed `queueKey{Type, Key}` rather than the object itself and re-fetch from
the lister at process time, so a requeue cap cannot be defeated by the lister returning a different
pointer for the same object between retries (#59); deletes are served from a tombstone map. Items
are dropped after five requeues.

`pkg/controller.podWatcher` similarly watches `Pod` objects on the local node and fans
`PodEvent(pod, nsLabels, cgInfos, eventType)` out to the same handlers, so pod lifecycle and
policy lifecycle are two independent event streams that both mutate the same manager state
(`LsmManager`/`EgressManager` each hold a mutex-guarded map of policies and pods, matching
targets against pod and namespace labels on both sides).

### Namespace targeting

`compiler.PodTarget` holds both compiled selectors and is the single answer to "does this
policy apply to this pod": `Matches(nsLabels, podLabels)` ANDs them, and a nil half matches
nothing so a target that failed to build never widens a policy's scope.

The watcher runs a second informer factory for namespaces — the pod factory carries a
`spec.nodeName` field selector no namespace has — and waits for both caches before the worker
starts, since a pod matched against an empty namespace label set would silently fall out of
every policy carrying a `namespaceSelector` with nothing to re-trigger it. A pod whose
namespace is not yet cached is requeued rather than delivered with empty labels.

Namespace labels reach handlers two ways, because the handlers differ in what they hold:

- **Pod-state handlers** (`LsmManager`, `EgressManager`, `dnsmgr.Manager`) cache `nsLabels`
  beside the pod labels they already cache, delivered on `PodEvent`. A namespace relabel
  replays that namespace's pods as ordinary updates, reusing the path each manager already
  has for re-evaluating a target.
- **`Monitor`** keeps no pod state — events carry their own attributed identity — so it
  implements `events.NamespaceEventHandler` and keeps a `namespace -> labels` map instead.
  The labels stay out of `runtimeevent.PodIdentity`: that type is embedded in
  `reporter.Finding`, and the reporter's guarantee is that an unredacted payload is not
  representable at the boundary, which a second user-controlled map would weaken.

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
`list(string)` element type from `dyn`. See `docs/users/reference/runtimepolicy.md` for worked examples of all
three libraries, including composing `json.unmarshal` with `resource.get`/`http.get` output.

Because `resource.get`/`http.get` results are only refreshed when the policy is (re-)evaluated,
any policy relying on external/mutable state should set `evaluationInterval` to periodically pick
up changes.

## Enforcement: eBPF LSM hooks and egress filtering

### File open and exec (`pkg/lsmmgr`, `pkg/bpf/lsm`)

`LsmManager` (`pkg/lsmmgr/lsmmgr.go`) is the pod and policy handler responsible for both the `open` and
the `exec` behavior. On `RuntimePolicyEvent` create, `rpCreated` (`pkg/lsmmgr/runtimepolicies.go`)
returns early unless the policy's mode is `enforce` or an observe mode
(`compiler.IsObserveMode`), then instantiates **one LSM enforcer per behavior type that has
entries** via `createForProgType`:

| Behavior | `lsm.NewForAttachTarget` target | LSM hook |
| --- | --- | --- |
| `open` | `lsm.PROG_TYPE_LSM_OPEN` | `file_open` |
| `exec` | `lsm.PROG_TYPE_LSM_EXEC` | `bprm_check_security` |

Per hook there is exactly one program attached to the kernel: a **dispatcher**
(`pkg/bpf/lsm/_cprog/dispatcher.c`, `lsm.Dispatcher`), loaded and attached once by `NewLsmManager`
via `link.AttachLSM` (`ebpf.AttachLSMMac`). The dispatcher is compiled per hook via `bpf2go` with
mutually exclusive `-DLSM_FILE_OPEN` / `-DLSM_EXEC_CHECK` flags (the source `#error`s if neither or
both are set) because it is the one program that reads the hook's argument to resolve the opened or
executed path with `bpf_d_path`. Enforcers — one per policy per behavior type — are never attached:
the dispatcher `bpf_tail_call`s through a bpffs-pinned prog array (`open_progs`/`exec_progs`), and
each enforcer in the chain tail-calls the next slot, with `prog_count` terminating the walk. The
per-CPU pinned `ctx_map` carries the resolved path and the running verdict (`deny`, `reason`,
`next_prog_idx`, `have_executed`) across the chain. `NewLsmManager` wipes the pin directory
(`lsm.ClearPins`) before loading, since a pin surviving from a previous process is only a stale map
spec — the links die with the process, so nothing keeps enforcing across a restart.

The enforcer (`pkg/bpf/lsm/_cprog/lsm.bpf.c`) is compiled once and never reads the hook argument,
but the kernel still forces a hook identity on it: an LSM program must be loaded with the
`attach_btf_id` of a real hook, and a program may only tail-call through prog arrays whose first
user had the same identity. A single object referencing both prog arrays is therefore unloadable
once both dispatchers exist. The enforcer instead references one placeholder array
(`chain_progs`), and `lsm.NewForAttachTarget` binds it to the chaining dispatcher's real array at
load time via `ebpf.CollectionOptions.MapReplacements`, keeping the C hook-agnostic.

Per enforcer, `createForProgType` populates the `banned`/`allowed` path maps from that behavior's
`AllowDenyPair` — **unless the mode is an observe mode, in which case both maps are left empty and
`default_deny` is never set** — sets the `default_deny` map entry if the deny list contains `"*"`,
and registers the program in the dispatcher's prog array (`Dispatcher.AddProgram`); on any failure
the partially-built enforcer is closed. Matched pods' cgroup IDs (resolved by `pkg/containers`) go
into that enforcer's `cgids` map, and an enforcer passes straight to the next chain slot for any
cgroup not in it. The decision composes across the chain through `ctx_map`: a path in a program's
`banned` map is an explicit deny and returns `-EPERM` immediately; a path in a program's `allowed`
map is an explicit allow; `default_deny` imposes an implicit deny only while no program in the
chain has explicitly allowed the path. The chain's tail returns `-EPERM` if the accumulated verdict
is deny.

State per policy lives in `lsmAttachment{progs map[string]*progState, selector, attachedPods}`,
where `progState` pairs an enforcer with the `AllowDenyPair` it was last programmed with, and
`observe` records which side of the observe/enforce line the attachment was built for. `rpUpdated`
treats a mode that is neither `enforce` nor an observe mode as a delete, rebuilds the whole
attachment if the mode crossed the observe/enforce line, otherwise runs `syncProgType` for each behavior type — creating an
enforcer that didn't exist, closing one whose behavior no longer has entries, or applying the
`DiffPair` of added/removed paths and re-setting default-deny — and then `syncPodAttachment`
reconciles cgids against the (possibly changed) selector. `rpDeleted` closes every enforcer for the
policy and drops it from each pod's `attachedLsms`. `PodEvent` adds/removes cgids across all of a
matching policy's enforcers.

The chain is what makes separate policies union rather than intersect: N enforce-mode policies
matching a pod put N enforcers in one hook's chain, and because the verdict accumulates in
`ctx_map`, one policy's explicit allow lifts another policy's `default_deny` for that path. An
explicit deny still short-circuits the chain, so `deny` entries beat `allow` entries across
policies.

The two exec-related kernel programs have complementary, non-overlapping capabilities:
`bprm_check_security` can return `-EPERM` but reads only `bprm->file->f_path`, so it cannot see
arguments; `sched_process_exec` (`pkg/bpf/exectrace`) sees argv but has no return contract. The
`exec` matcher is therefore path-only. There is no `args:` matcher, and adding one would ship a
matcher that enforcement silently ignores.

### Network egress (`pkg/egressmgr`, `pkg/bpf/egressfilter`)

`EgressManager` (`pkg/egressmgr/egressmgr.go`) is the pod and policy handler for the `network`
behavior. Where `LsmManager` keys its BPF state by policy, `EgressManager` keys it by pod: each
matched pod gets one `egressfilter.EgressFilter` (`pkg/bpf/egressfilter/egressfilter.go`), a
`cgroup/skb egress` BPF program (`pkg/bpf/egressfilter/_cprog/probe.c`) attached per-container
cgroup path via `link.AttachCgroup(..., Attach: ebpf.AttachCGroupInetEgress)`. `AddIps`/`DeleteIps`
populate that pod's `AllowedIps`/`BannedIps` maps (parsed by `egressfilter.ParseTargets`, which
expands `/24`-or-narrower CIDRs and returns IPv6/wider-CIDR/hostname values as typed
`RejectedTarget`s), and `SetFlagIdx(egressfilter.DEFAULT_DENY, ...)` toggles default-deny
for that pod's filter. `rpCreated`/`rpUpdated`/`rpDeleted` (`pkg/egressmgr/runtimepolicies.go`)
implement the default-deny-union-across-policies bookkeeping described above, per pod
(`podAttachment.defaultDeny`), and gate on `enforce`-or-observe exactly as `LsmManager` does; an
observe-mode policy programs no IPs and only sets the refcounted `OBSERVE` flag on its matched
pods' filters. Both managers also refresh a pod's labels on `PodEvent` update and re-match
selectors, so relabeling a pod attaches or detaches it (#58) with the default-deny refcount kept
correct.
`rpUpdated` mutates the stored `EvaluationResult`'s `IPs`/`Selector` in place rather than replacing
the pointer that pods' `attachedFilters` entries share (`82acb1f`), so a policy update does not leave
pods pointing at stale IP data.

### Application protocol (`pkg/egressmgr`, `pkg/bpf/protofilter`)

The `protocol` behavior is enforced by a second `cgroup_skb/egress` program,
`pkg/bpf/protofilter/_cprog/probe.c`, attached by `EgressManager` to the same per-container cgroup
paths as the IP filter (both programs run on every egress packet; the effective verdict is the AND
of their return values). Where the IP filter decides at `connect` time from `ip->daddr`, the
classifier's verdict is deferred to the **first data segment** of a flow, which is where the
protocol evidence lives:

- The IP family comes from `skb->protocol`, never from payload bytes, so IPv4 and IPv6 cannot be
  misread as each other. An IPv6 extension-header chain, ICMP, and every other unparseable L4 are
  classified `unclassified` rather than skipped.
- TCP packets with no payload pass (the verdict is deferred); the first data segment is matched
  against the SSH banner, the 24-byte cleartext HTTP/2 preface, the TLS record header (then a
  bounded walk of the ClientHello for the first offered ALPN entry), and the HTTP/1 method
  tokens. UDP classifies on the first packet: a QUIC v1 long header, a cleartext DNS query
  (header sanity plus a bounded QNAME walk; the port is never consulted), or `unclassified`. A
  ClientHello that does not fit in one segment classifies `unclassified`, deliberately: folding
  it into `tls` or the default would make the control untrustworthy.
- The decision comes from `allowed_protos`/`banned_protos` maps keyed by the padding-free
  `{proto id, alpn[16]}` pair — an empty ALPN key means "this protocol with any ALPN" — plus the
  same `flags` default-deny/observe bits the IP filter uses. Compute decision → record it in
  `proto_events` (decision in the key, once per flow) → cache the verdict in an LRU flow map →
  enforce, in that order.
- `EgressManager` tracks the protocol default-deny refcount per pod (`podAttachment.protoDefaultDeny`)
  independently of the network one, diffs the `Protocols` pair on policy update exactly as it diffs
  `IPs`, and drains `proto_events` in `CollectObservations` into `KindProtocol` events.

A denial is therefore a mid-connection drop of the first data segment (the client sees a stalled
connection), not `-EPERM` at `sendmsg` — which is exactly why `protocol` is a separate behavior
kind rather than another value shape in `network`.

## The event plane

Enforcement is a kernel-side map lookup and produces no userspace output. Monitor mode needs the
opposite: a stream of what a workload actually did, attributed to a pod, matched against policy
in userspace. That is the event plane. Most of it rides the counters the enforcing BPF objects
already keep; `pkg/bpf/exectrace` and `pkg/bpf/dnsquery` are the sources with a program and a ring
buffer of their own. The protocol classifier counts, so it polls.

### Choosing a transport: counter map or ring buffer

The two source shapes are not interchangeable, and the deciding question is what the observation
*is*:

- **A bounded enum rides a counter map.** An address, a resolved path, an exec filename, each
  paired with the kernel's decision: the key set is bounded by what the workload touches, the
  interesting quantity is "how many times", and a read-and-reset drain turns the map into deltas.
  Nothing is lost between polls that the counter does not record, and the kernel side costs one
  map update per event.
- **A variable-length string needs a ring buffer.** A DNS question name, or an exec's argv, is the
  payload rather than a key: its value is the whole observation, aggregation would destroy it, and
  a map keyed on it would be a map keyed on unbounded user data. Each occurrence is its own record,
  delivered as it happens, with `Count` fixed at 1.

The cost of the second shape is that a full buffer loses observations where a full counter map
merely stops distinguishing them, which is why the ring buffer sources carry loss counters and
the poll sources do not.

### Normalized events (`pkg/runtimeevent`)

`runtimeevent.Event` is the single currency of the plane: a `Kind`
(`net|dns|exec|open|protocol`), a timestamp, an optional cgroup ID / PID / comm, a `Count`
(a poll source's observations are deltas, not individual occurrences; a `dns` record is always
one question), two deliberately distinct deny flags —
`KernelDenied`, the kernel's actual enforcement decision, set only by the BPF poll sources from
the decision dimension of the observation maps, and `WouldDeny`, monitor mode's counterfactual,
set only by `pkg/monitor` on its per-policy copy — one non-nil facts struct
per kind, and a `PodIdentity`.

Three interfaces define the plumbing, all in `pkg/runtimeevent/iface.go`:

| Interface | Implemented by | Role |
| --- | --- | --- |
| `Source` | `collector.NewPollSource`, `exectrace.Source`, `dnsquery.Source` | Produces events until its context ends. |
| `Sink` | `monitor.Monitor` | Consumes fully-annotated events; must be fast and must not panic outward. |
| `PolicyStatusRecorder` | `controller.StatusWriter` | Receives status conditions from anywhere in the plane. |

### Observation: draining the existing maps

Both managers grew a `CollectObservations(ctx) ([]runtimeevent.Event, error)` method:

- `pkg/egressmgr/observe.go` walks the pods that have at least one observe-mode policy attached
  (the `OBSERVE` flag is refcounted per pod, so a pod with an empty observe set is not counting)
  and drains that pod's `ip_events` counters via `egressfilter.ReadIPEvents` and its
  `proto_events` counters via `protofilter.ReadProtoEvents`. Reads are
  destructive, so `Count` is the delta since the previous poll. The pod UID and labels are
  pre-filled, since the poll source knows the pod but not the cgroup.
- `pkg/lsmmgr/observe.go` walks **every** program type of **every** attachment and drains each
  enforcer's `open_events` hash-of-maps via `lsm.ReadEvents`. Reading only the first enforcer was
  the #52 bug class — it made exec counts invisible for any pod that also had an open enforcer —
  so the traversal is exhaustive by construction and covered by
  `TestCollectObservationsReadsAllEnforcers`.

Both sweeps are all-or-something rather than all-or-nothing: a per-pod or per-enforcer read
failure is joined into the returned error but never aborts the sweep, because a partial map read
still carries real observations. An `lsm.ErrObservationUnavailable` is special-cased: it is not
returned as a poll error (every subsequent poll would repeat it) but raised as an
`ObservationAvailable=False` condition on the policy, because a policy whose observation could
not be turned on produces no findings and must not look healthy.

In observe mode `createForProgType` leaves the `banned`/`allowed` maps **empty** and never sets
`default_deny`, and `egressmgr` programs no IPs at all — the only thing an observe-mode policy
changes in the kernel is that the pod's cgroup ID is in the `cgids` map (LSM) or that the pod has
a filter with `OBSERVE` set (egress). Crossing the observe/enforce line rebuilds the attachment
rather than mutating it, so an observing enforcer can never inherit deny entries and an enforcing
one never starts from an observer's empty maps.

### Exec tracing (`pkg/bpf/exectrace`)

`exectrace.Source` is the first streaming source: a `raw_tp/sched_process_exec` program that
reports one ring buffer record per exec — pid, comm, filename, and up to 8 argv slots of 128
bytes — decoded by `DecodeExecEvent` into an `Event` with `ExecFacts.Argv`. Production is gated
in the kernel by a `cgids` map that `LsmManager` mirrors from its exec attachments (the
`CgroupSink` seam), so a pod no exec policy selects produces no ring buffer traffic at all.
Kernel-side losses (ring buffer full, argv truncated or unreadable) are counted in a per-CPU
`stats` map and logged by the source's poller, because a record that was never written is
invisible to everything downstream.

Each reserved record is zeroed before it is filled: ring buffer memory is recycled and mmapped
to userspace, so an unzeroed tail would leak one pod's argv into another pod's event.

### The DNS question observer (`pkg/bpf/dnsquery`)

`cgroup_dns_egress` (`_cprog/query.bpf.c`) is a `cgroup_skb/egress` program that reads the QNAME
out of every UDP datagram a gated cgroup sends to port 53 and submits one ring buffer record per
question. Every path returns 1: a question this program cannot parse must still leave the pod.

The first thing it does is look the skb's cgroup id up in the `cgids` hash, and return if it is
absent. That gate is the whole reason the program can be attached to a container cgroup without
paying for it: an unselected pod's questions are never read, never reserved, never decoded.
`bpf_skb_cgroup_id` is preferred over `bpf_get_current_cgroup_id` because the socket's cgroup
stays correct when the skb is transmitted from softirq context; the current task's cgroup is the
fallback for an skb with no socket, and a question is sent from process context.

Two things about the name read are worth recording, because neither is visible from the code:

- **The name is read straight into the ring buffer record, not through a stack buffer.** A
  128-byte local plus the unrolled read's spill slots does not fit BPF's 512-byte stack. So the
  record is reserved *before* the name is known to be parseable, and an unparseable name is
  discarded rather than never reserved. The consequence is the `__builtin_memset` immediately
  after the reserve: ring buffer memory is recycled and mapped into userspace, so a partially
  filled record would otherwise hand a reader the tail of the previous one.
- **The record carries the same wire encoding `pkg/bpf/egressfilter` interns policy-named domains
  into**, from the same `struct domain_key` in `pkg/bpf/include/dnsname.h`. Length-prefixed
  labels, ASCII-lowercased, zero padded, one 128-byte width. In the egress snooper that means a
  map lookup needs no re-encoding on either side; here it means the width that bounds a decodable
  question is the same width that bounds a policy value, so a question this drops is a question no
  policy could have named.

`read_qname` is one flat pass over the wire bytes rather than a loop per label: `remaining` counts
down the current label, so a byte read with `remaining == 0` is the next length byte. Bounding the
pass at the key width bounds the label count too, and leaves the verifier a single unrolled loop
with constant indices. It uses `bpf_skb_load_bytes` rather than direct packet access because an
skb may be non-linear, and `data_end` would then cut the name off mid-way and lose it silently.

`Observer` (`dnsquery.go`) is deliberately a single instance for the whole daemon. `cgroup_skb`
programs attach per cgroup, so observing N pods means N links — but one loaded object means one
ring buffer and one reader goroutine instead of N of each, and one `cgids` gate every attachment
shares. `dnsquery.Source` (`source.go`) is that reader: it drains the buffer into the collector,
stamping each event's time on arrival (the record carries no timestamp), and closes the reader to
unblock the in-kernel `Read` on context cancellation. A record the decoder rejects is counted and
dropped rather than fatal — the Go and C layouts would have to disagree for that to happen, and
returning would lose every subsequent question too.

Loss is counted in three places, never silent, because a lost observation and an absent one are
indistinguishable at the sink:

| Reason | Side | Cause |
| --- | --- | --- |
| `ringbuf_full` | kernel | `bpf_ringbuf_reserve` failed; the reader is behind |
| `name_unreadable` | kernel | truncated, compressed, or over the key width |
| `undecodable` | userspace | `DecodeQueryEvent` rejected the record's bytes |

The two kernel counters live in a per-CPU array, are cumulative and never reset; `pollStats` sums
them across CPUs every `--observe-interval` and reports the delta through the `LossFunc` the
daemon wires to `EventsDropped{source="dnsquery"}`.

### Gating observation (`pkg/dnsmgr`)

`dnsmgr.Manager` decides which pods the observer sees, from both event streams: it is an
`events.PodEventHandler` and an `events.RuntimePolicyEventHandler`, and every decision is
recomputed from the same predicate — a pod is observed exactly while some policy with a `dns`
behavior, in a mode the detection engine reports in, selects it.

That is an efficiency boundary and a privacy boundary at once. An unselected pod's questions never
enter the ring buffer, so they cannot be dropped, decoded, or reported, and no node-wide firehose
of every pod's questions exists to fall behind.

Attachment and gate admission are separate steps because they fail differently. A link is per
container cgroup and its absence means no packets are seen at all; a cgroup id in `cgids` is what
lets an attached program emit. The ordering is asymmetric on purpose: `attach` links first and
admits after, so a cgroup that failed to attach never sits in the gate reading as "observed" while
producing nothing; `detach` revokes first and closes after, because an id left admitted after its
link is gone is harmless while a link left open after revocation runs the program for nothing.

`podState.cgInfos` is retained even while a pod is unobserved: the policy informer delivers no
container information, so a policy that starts selecting an existing pod would otherwise have
nothing to attach to. `reports(mode)` mirrors the engine's own mode switch rather than testing for
"not empty", so a mode added to the API without an engine branch does not silently start
observation.

### Collector (`pkg/collector`)

`Collector` is a small fan-in/fan-out pipeline: N `Source`s → a buffered channel → an ordered
list of `Stage`s → N `Sink`s, all driven by `Run(ctx)`.

- `NewPollSource(name, interval, poll)` adapts the managers' `CollectObservations` into a
  `Source`. Poll-based collection is a deliberate consequence of decision 2 above for the
  observation sources: the enforcing programs expose counters, not a stream. `exectrace.Source`
  and `dnsquery.Source` implement `Source` directly over their ring buffers and join the same
  pipeline.
- A `Stage` (`Name() string; Process(*Event) bool`) may annotate an event and returns false to
  drop it. Stages run in insertion order; the daemon installs exactly one, `attribution.Index`.
- Drops are always counted, labeled by source and reason (`buffer_full`, `unattributed`, and the
  DNS source's three), and exposed via `Dropped()` and `nirmata_runtime_events_dropped_total`. A
  full buffer drops the newest event rather than blocking a source.
- Sources are restarted with backoff if they fail.

### Attribution (`pkg/attribution`)

`attribution.Index` is the only component that appears twice in the wiring, because it is both:

- an `events.PodEventHandler`: `PodEvent` upserts (create/update are idempotent) the pod's labels,
  owner, and cgroup set from `containers.ResolveCgInfos`, evicting cgroups the pod no longer owns;
  delete evicts the pod and everything it owned. Label refresh on update is what lets a
  relabeled pod be re-matched.
- a `collector.Stage`: `Process`/`Annotate` resolves an event to a `PodIdentity` by cgroup ID,
  then by pod UID (the egress source pre-fills it), then by PID (parsing
  `<procRoot>/<pid>/cgroup`), and **drops** the event if none of those hit, counting
  `nirmata_runtime_attribution_misses_total`. Dropping unattributed events is only defensible
  because the miss is counted — a silent drop would hide an attribution regression, which is
  exactly what #38 was.

Owner derivation needs no extra RBAC: it reads `pod.OwnerReferences[0]`, and when the owner is a
`ReplicaSet` whose name ends in the pod's `pod-template-hash`, reports the `Deployment` instead.

`PodIdentity.Labels` is the index's own map — replaced, never mutated — and is documented
read-only so the plane does not copy a label map per event. Sinks must not mutate it.

### Monitor (`pkg/monitor`)

`Monitor` is the `Sink` that turns observations into findings, handing each one to every
registered `FindingSink` under its own `utils.Guard` so one sink's panic does not cost the others
the finding. It tracks monitor- AND
enforce-mode policies in a per-event-ready form (`trackedPolicy`: mode, compiled selector plus
`netBehavior`/`pathBehavior`/`nameBehavior` matchers), replacing the whole value on every
`RuntimePolicyEvent` rather than mutating it — both so `HandleEvent` can read one outside the lock
and so it is immune to `egressmgr` mutating the `EvaluationResult` it shares.

Per event it gates on `Kind`, then on the policy's selector against `ev.Pod.Labels`, then
evaluates the matching behavior with the same semantics the kernel would apply: an explicit deny
entry matches; under default-deny anything absent from `allow` matches. A match records a
violation through the `PolicyStatusRecorder` **first and unconditionally** (the violation
happened whether or not it can be reported) and then emits a `reporter.Finding`.

What a match means depends on the policy's mode. For a monitor-mode policy it is the
counterfactual: the finding says the operation *would have been* denied (`Finding.Enforced` is
false, the event copy carries `WouldDeny`), independent of `KernelDenied`. For an enforce-mode
policy a match only matters when `ev.KernelDenied` is set: the kernel already denied, and the
userspace re-evaluation is what attributes that deny to the policy whose lists produced it — the
kernel maps are per-pod flat sets with no policy dimension, so policy identity cannot come from
the kernel. Those findings say the operation *was* denied (`Finding.Enforced` is true). A kernel
deny that no tracked enforce-mode policy explains bumps
`nirmata_runtime_events_dropped_total{source="monitor",reason="unattributed_kernel_deny"}` and is
logged at V(2): a kernel deny must never vanish silently.

#### Filtering findings (`spec.monitorFilter`)

`spec.monitorFilter.expressions` is compiled in `pkg/compiler` alongside the behavior
expressions, each one type-checked to `bool` against an environment carrying the `event`
variable and the base libraries but **not** the Kyverno SDK's `http`/`resource`/`json`: a
cluster read or an HTTP fetch is affordable once per `evaluationInterval` and not once per
kernel event. The compiled predicates travel to the monitor on the evaluation result and are
held on `trackedPolicy` with the matchers.

They are applied in `record()`, where the candidate finding is formed — before it reaches the
reporter, because the reporter is the [redaction chokepoint](#redaction-chokepoint) and must
not acquire policy logic. `event` is the observation itself, a discriminated union whose kind
field is also the `has()` guard; `docs/users/reference/cel.md` is the schema.

Expressions are ANDed in order and short-circuit on the first false one, which is what lets a
`has(event.exec)` guard protect a later expression dereferencing `event.exec` on an `open`
event. An eval error or a non-`bool` result **reports the finding anyway** and increments
`nirmata_runtime_monitor_filter_eval_errors_total{policy,expression}`, labeled with the
expression's `name`: the predicate selects what to show, so failing closed would turn a broken
filter into a monitoring gap indistinguishable from silence. The `name` reaches compile errors,
status conditions and that metric, and never a Report, so the reporter's fixed key set stays
closed to user-controlled strings.

There is no runtime mode guard. `mode: enforce` alongside a `monitorFilter` is refused both at
admission and by the compiler, so the enforce branch of `handleEvent` can never reach a filter
and a guard there would be unreachable.

#### The name matcher and the advisory finding

`nameBehavior` is the third matcher shape, and its `eval` is not a variant of the other two. For
`netBehavior` and `pathBehavior` the allow list only matters under `deny.star`; for `nameBehavior`
the allow list is the expected set, so a name matching none of its entries is a violation on its
own:

```text
deny.star || deny.matches(name)                    -> violation
allow.empty() || allow.star || allow.matches(name)  -> no violation
otherwise                                           -> violation
```

Two consequences follow from that order. `deny.star` short-circuits, so `deny: ["*"]` reports every
name and an allow list alongside it is ignored rather than exempted — the discovery form is a
different request, not a default deny with holes. And a behavior with nothing on either side is
inert rather than all-reporting, because an empty expected set means "nothing declared yet", not
"every name is a surprise"; `compileNameBehavior` returns nil for it and `dnsmgr` never selects the
pod.

`newNameMatcher` stores a wildcard as `".<name>"`, including the separating dot. That single
leading dot is what confines a wildcard to subdomains: `*.openai.azure.com` matches
`foo.openai.azure.com` and neither the apex `openai.azure.com` nor `evilopenai.azure.com`. Both
sides of every comparison are lowercase without further work — policy values through
`ParseDNSValue`, observed names through the kernel program that lowercases them on the wire.

The finding shape is the other divergence. `handleEvent` special-cases `BehaviorDNS` before the
mode switch, so a `dns` violation takes neither branch: not the monitor-mode counterfactual
(`WouldDeny` is never set on it) and not the enforce-mode kernel-deny attribution (there is no
enforcing form of this behavior to attribute). `result()` grades it `warn` rather than `fail`, and
`message()` writes "resolved unexpected DNS name ..., not expected by policy ..." with no
"would have been denied" wording. `reporter.DNSSummary{QName}` carries the observed name into the
`dnsName` property, and no `ProcessSummary` is attached: a `cgroup_skb` program may not call
`bpf_get_current_comm`, so a question is attributed to a pod and not to a process.

### Reporter (`pkg/reporter`)

`Reporter` buffers findings, deduplicates them by `Finding.Fingerprint()` (a SHA-256 over policy,
behavior, pod, and target), and flushes every 10 seconds into one namespaced OpenReports `Report`
per pod named `kyverno-runtime-<podName>`, truncated and hash-suffixed when the pod name would
push it past the 63-character object-name limit. Merging preserves `count`,
`firstTimestamp`, and `lastTimestamp`; results are capped at 500 with a
`runtime.nirmata.io/truncated-results` annotation; a flush whose results are byte-identical to
what is already stored is skipped rather than written. `Run(ctx)` flushes once more after
cancellation, on a fresh bounded context, so the last window is not lost on shutdown. It writes
through a `sigs.k8s.io/controller-runtime/pkg/client.Client` built from the daemon's `rest.Config`
with the OpenReports types installed in the scheme.

`Options.FlushSink`, when set, is called once per deduplicated finding on every flush — after
dedup is drained, independent of whether the `Report` write that follows succeeds — with the raw,
unredacted `Finding` and its merged occurrence count. `pkg/reportevents` is the only current
subscriber (see [Kubernetes Events](#kubernetes-events)); a nil `FlushSink` costs nothing.

### Push sink (`pkg/pushsink`)

`GRPCSink` is the second `FindingSink`: it streams findings to a collector as they are produced,
for a cluster that wants them live rather than through `Report` objects a consumer has to poll.
It is enabled by `--push-target` alone; empty means no queue, no connection, and no cost.

The daemon is always the gRPC *client*. `Report(stream Finding) returns (Ack)` is client
streaming, so a node opens no listening port — this pod is privileged and `hostPID`, and the
egress-only direction is the point. Transport is mutual TLS with no plaintext mode: the
collector CA and the daemon's client certificate are file paths, and a missing or unreadable one
fails at construction rather than at the first violation. `Report` never blocks the event path.
The send queue is bounded (4096); an overflow drops the *oldest* finding and counts it, the same
never-block/count-what-is-lost discipline `pkg/collector` and `runtimeevent.LossFunc` follow, so
a collector that stops reading costs the newest observations rather than the daemon. A broken
stream is reopened after a backoff that doubles from 5s to a 1-minute cap and resets once a
stream establishes, so a collector that is gone rather than restarting does not become
fleet-wide connection churn; a cancelled context drains what is queued and closes the stream,
so the last window is not lost. That shutdown is bounded rather than best effort: `Send` blocks
on the stream's own context while the flow control window is shut, which a collector that
accepts a stream and stops reading holds indefinitely, so cancellation arms a deadline that
closes the stream out from under a blocked send. The daemon's errgroup is what a DaemonSet
rollout waits on.

`Finding.Pod.OwnerKind`/`OwnerName` ride this stream as best-effort correlation metadata, not as
identity. `pkg/attribution.deriveOwner` reads `pod.OwnerReferences[0]` verbatim, and Kubernetes
validates that field structurally rather than behaviorally: any principal that can create or
patch a pod can name any owner it likes. In a namespaced `Report` an operator can check a
suspicious owner against the pods in that namespace; a central collector has no such view, so
the wire schema documents these fields as unverified and a receiver must not use them as a
security boundary. Verifying the owner in-daemon is deliberately not the answer — it needs RBAC
per owner kind and still does not stop an attacker who controls a real object — the control is
cluster-level admission policy over who may set `ownerReferences`.

### Kubernetes Events

`pkg/reportevents.Recorder` is the third output path, gated by `--events-enabled` (default
`false`). It has two entry points: `FindingFlushed` is `reporter.Options.FlushSink`, called once
per deduplicated finding on every `Reporter` flush; `ConditionChanged` is the
`StatusWriter.onConditionChanged` callback described in [Status reporting](#status-reporting).
Between them they emit `PolicyViolation`/`PolicyWouldViolate` (from `Finding.Enforced`) and
`PolicyError` (from `Applied`/`TargetsValid` going `False`).

It writes `eventsv1.Event` objects directly through the typed client rather than through
`k8s.io/client-go/tools/events`' `EventRecorder`. That recorder's correlator keys its dedup cache
on `(type, action, reason, reportingController, reportingInstance, regarding, related)` and never
looks at the note, so two distinct causes sharing those fields — different targets of the same
policy and pod, or a changed failure reason under an unchanged condition type — would collapse
into one Event series with only the first message surviving. `Recorder` instead derives each
Event's name deterministically: a finding's `Fingerprint()` (computed before `Redact`, matching
the identity `Reporter` itself dedupes by), or the policy UID plus condition type for a policy
error. A `Create` that hits `AlreadyExists` means the identical cause fired before, so it patches
that object's `series` and `note` in place rather than creating a new one; a distinct cause always
gets its own object. Every note passes through `reporter.Redact`/`reporter.Sanitize` first — the
same boundary described next.

## Redaction chokepoint

Secret material must be structurally incapable of reaching a `Report`, a log line, or the wire,
not merely filtered out by policy. One chokepoint, not configurable:

**`reporter.Finding`.** `Finding` is a *closed* struct of typed scalars: no header
map, no body field, no free-form properties passthrough. An unredacted payload is not
representable at the boundary. `buildResult` emits a fixed property key set and every value
passes `reporter.Sanitize`. Pod labels — arbitrary user-controlled key/values — are deliberately
never emitted.

**`reporter.Redact`.** A `Finding` reaches a sink before anything in `pkg/reporter` has touched
it, still carrying the raw argv and paths the kernel observed: `buildResult` scrubs on the way
into a `Report`, which is no help to a sink that never builds one. `Redact` is the same
`Sanitize` applied to every string field of a `Finding`, and it is what `pkg/pushsink` and
`pkg/reportevents` call before a finding leaves the daemon as anything other than a `Report` — so
what waits in a send queue, or lands in an Event's note, is already scrubbed and bounded. It
rebuilds `PodIdentity` field by field rather than copying and patching it: a field added there and
not added to `Redact` is dropped, never forwarded unscrubbed. Pod labels are dropped for the same
reason they are never emitted into a `Report`. `pkg/reportevents.Recorder.ConditionChanged` calls
`Sanitize` directly on a condition's `Reason`/`Message`, which can carry compiler error text
quoting policy content and has no `Finding` to route through `Redact`.

The argument is structural rather than procedural: there is no option, flag, or field that
weakens the mechanism, and adding one is a reason to reject a PR
([Agents.md](../../Agents.md)). It is also tested: `reporter.TestRedactionChokepoint` fails if a
new `Finding` field or property key escapes sanitization. Adding a string field to `Finding`
therefore forces two tests wider — `TestRedactionChokepointCoversEveryFindingStringField` and
the closed property-key set in `result_test.go`. That widening is the review gate doing its
job: widen it deliberately, never loosen it. The logging rule that completes it: only
redacted accessor output may be logged — never a raw header map, body, or CEL variable value.

The chokepoint has a kernel-side counterpart in `pkg/bpf/exectrace`: a reserved ring buffer
record is recycled memory mmapped to userspace, so the program zeroes it before filling it —
an unzeroed tail is a cross-pod argv leak, not untidiness.

## Status reporting

`pkg/controller.StatusWriter` is the single writer of `RuntimePolicyStatus` and the single
implementation of `runtimeevent.PolicyStatusRecorder`. It consumes the policy event stream only;
pod-level detail belongs to the Reports and the Prometheus counters, not to the status.

Because every node runs a daemon and `RuntimePolicy` is cluster-scoped, status is **sharded**:
`status.nodes` holds one `NodePolicyStatus` per node and each daemon replaces only its own entry,
then lifts the newest `lastEvaluatedTime` across all shards to the top level. Updates flush every 30 seconds (and once on shutdown) via
`retry.RetryOnConflict` against the `status` subresource, so concurrent per-node writes converge
instead of clobbering each other.

Conditions are merged by type: `TargetsValid` comes from `egressmgr`; `EnforcementAvailable`,
`ObservationAvailable`, `ExecRulesValid` and `OpenRulesValid` come from `lsmmgr`;
`EnforcementAvailable` and `PodsMatched` are written by both, since either manager can fail to
attach or match pods for its own behaviors. `TargetsValid`, `ExecRulesValid` and `OpenRulesValid`
are answers about the spec, identical on every node, so they are merged into `status.conditions`
verbatim. Each behavior gets its own condition type because conditions are keyed by type and
last-write-wins.

`EnforcementAvailable`, `ObservationAvailable` and `PodsMatched` are answers about a node, so a
recorded condition of those types lands in this node's `status.nodes` shard as a compact signal
(`enforcementAvailable`, `observationAvailable`, `podsMatched`, plus a `message` naming what is
unavailable) instead of being written cluster-scoped. Every flush then derives the cluster-scoped
condition of each type from all the shards: availability is all-true — one node that cannot
enforce or observe leaves its workloads uncovered no matter how many others can, and the `False`
message names the failing nodes — while `PodsMatched` is any-true, since a policy's pods typically
run on a few nodes and the nodes where none are scheduled must not read as a selector matching
nothing. On a mixed cluster the top-level conditions therefore state something true of the
cluster instead of flapping to whichever node flushed last. A type no shard reports is removed
from `status.conditions` rather than left at whatever an older writer put there.

Shards themselves are pruned at flush time: each daemon watches Node existence (a name-only
metadata watch) and drops another node's entry from `status.nodes` once that node is gone, so a
deleted node's last-known signals stop feeding the aggregate. A daemon never prunes its own
shard, and never prunes before its node watch has synced. A node that still exists but no longer
runs a daemon (a taint, an unscheduled DaemonSet) keeps its shard; the watch only answers
whether the node object is there.

`Applied` is derived rather than recorded: `StatusWriter` computes it at flush time from
`spec.mode` plus the aggregated `EnforcementAvailable` / `ObservationAvailable` for that mode and
the aggregated `PodsMatched` — a mode that promises enforcement or observation does not read as
applied while any node's attachment behind it never took, or while no node has a matching pod.
The two are checked in that order, so an attachment failure (the more actionable case) is
reported ahead of, and is never masked by, a selector that also happens to match nothing at the
same time. The one direct exception to the derivation is `reportCompileFailure`, which records
`Applied=False/CompileFailed` itself for a policy the compiler rejected outright — there is no
evaluation result to derive anything from, since nothing compiled.

This is the mechanism behind
the "fail loud, not silent" rule: a network target the runtime cannot program (IPv6, a CIDR wider
than `/24`, a hostname) is reported as a typed `egressfilter.RejectedTarget`, logged at `V(0)`,
**and** surfaced as `TargetsValid=False` with the per-value reason; an open or exec path that
cannot become a `char[128]` map key does the same through `lsm.RejectedTarget`. Silently skipping
it is the forbidden failure mode.

An optional `onConditionChanged` callback, injected into `NewStatusWriter`, notifies a caller of
every condition a flush actually persists whose status, reason, or message changed from what was
there before. It fires from `flushOne`, after a successful `UpdateStatus`, comparing the object's
conditions before and after that write — not from `RecordCondition`, since `Applied` is usually
derived rather than recorded (above) and a hook on `RecordCondition` would therefore miss most of
its real transitions. Comparing persisted state also means a daemon restart, which starts this
node's in-memory condition cache empty, cannot manufacture a spurious notification: what changed
is judged against the API object, fetched fresh on every flush, not against local memory.
`pkg/reportevents` is the only current subscriber (see [Kubernetes Events](#kubernetes-events)).

## Metrics

`pkg/metrics.New(reg)` registers every collector against a caller-supplied `prometheus.Registerer`
— the daemon passes a fresh private `prometheus.Registry` rather than the global default, so
repeated wiring (and tests) cannot panic on duplicate registration. `metrics.Serve(ctx, addr, reg,
health, log)` exposes `/metrics` and `/healthz`, and returns cleanly on context cancellation.
`/healthz` fails while the runtime policy informer has not synced or the collector's dispatch loop
has not ticked recently, and is otherwise honest about having nothing else to check.

`--metrics-addr` (default `:9090`) selects the bind address; the chart passes
`--metrics-addr=:{{ .Values.daemon.metrics.port }}` and declares the matching `containerPort`.
An empty value disables the endpoint without disabling the counters.

`pkg/metrics/metrics.go` registers exactly six collectors, all under the `nirmata_runtime`
namespace: `events_ingested_total{source,kind}`, `events_dropped_total{source,reason}`,
`attribution_misses_total`, `findings_emitted_total{policy,behavior}`,
`monitor_filter_eval_errors_total{policy,expression}`, and
`report_writes_total{result}`. The `reason` values something produces are `buffer_full`
(`pkg/collector`), `unattributed` (`pkg/monitor`, `pkg/reporter`),
`unattributed_kernel_deny` (`pkg/monitor`), `ringbuf_full` / `name_unreadable` /
`undecodable` (`pkg/bpf/dnsquery`, all under `source="dnsquery"`), and `queue_full` /
`send_failed` (`pkg/pushsink`, under `source="pushsink"`).

## Helm chart / deployment shape

`charts/kyverno-runtime/` installs:

- A `DaemonSet` (`templates/daemonset.yaml`) running `kyverno-runtime daemon`, always installed,
  privileged, `hostPID: true`, no host filesystem mounts, `NODE_NAME` injected from
  `spec.nodeName`, and `--metrics-addr=:{{ .Values.daemon.metrics.port }}` (default 9090) with a
  matching `containerPort` named `metrics`. `hostPID` and `privileged` keep the pod outside the
  `baseline` Pod Security Standard, so its namespace needs
  `pod-security.kubernetes.io/enforce: privileged`.
- A shared `ClusterRole`/`ClusterRoleBinding`/`ServiceAccount`
  (`templates/clusterrole.yaml`, `templates/clusterrolebinding.yaml`, `templates/serviceaccount.yaml`)
  granting pod/policy reads, `runtimepolicies/status` `[get,update,patch]` for the status writer,
  and full CRUD on `openreports.io` `reports` for the reporter, with
  `values.daemon.rbac.extraRules` as an escape hatch for granting the daemon access to
  additional resource types referenced by the `resource` CEL library.
- The push sink's configuration, when `daemon.push.target` is set: `--push-target` plus the three
  `--push-tls-*` paths, backed by a read-only mount of `daemon.push.tls.secretName` at
  `/etc/kyverno-runtime/push-tls` holding `ca.crt`, `tls.crt` and `tls.key`. The chart refuses to
  render a target without that Secret rather than installing a daemon that exits at boot.
- `--events-enabled=true` when `daemon.events.enabled` is set, which also adds `events.k8s.io`
  `events` `[create,patch]` to the ClusterRole. The chart refuses to render
  `daemon.events.enabled: true` with `daemon.reports.enabled: false` rather than installing a
  daemon that exits at boot, the same way it refuses an incomplete push TLS configuration.
- The `RuntimePolicy` CRD (`charts/kyverno-runtime/crds/`), plus the vendored OpenReports CRDs
  (`openreports.io_*`), which `pkg/reporter` now writes to; the OpenReports API is registered into
  both the daemon's scheme and the controller-runtime client used for those writes.

## Known Gaps / Future Work

These are verified, current limitations — not planned features to build toward, which belong in a
future `PLAN.md`.

- **An exec evaluates both chains on BPF-LSM and only one on the tracepoint fallback.** LSM has a
  hook per behavior, so an exec hits `file_open` for the binary's open and `bprm_check_security`
  for the exec: both chains run. The fallback hooks one point, `security_file_open`, and picks the
  chain from the `__FMODE_EXEC` bit — either/or, so an exec never reaches the `open` chain. A path
  in `spec.open.deny` still blocks opens on both (tracepoint and LSM); only on BPF-LSM does it also 
  block executing it.
- **Monitor-mode observation has two transports, and both are lossy at their own edges.** The
  `network`/`open`/`exec` observations ride the counters the enforcing objects already keep;
  `pkg/bpf/exectrace` additionally streams per-occurrence exec events with argv, and the DNS
  question observer is a program and a ring buffer of its own
  (see [Choosing a transport](#choosing-a-transport-counter-map-or-ring-buffer)):
  - Counters are drained every 10 seconds, so those findings lag behavior by up to that interval
    and only counts survive — not per-occurrence ordering or timing.
  - The per-cgroup `open_events` inner map holds 2048 `(path, decision)` keys; a workload touching
    more than that within one interval loses the excess (read-and-reset mitigates, does not
    eliminate).
  - Network observation is destination-IPv4 only: no port, no protocol, no IPv6.
  - A DNS question is one record delivered as it happens, so ordering and per-occurrence timing do
    survive there — at the cost of a bounded buffer. It holds roughly 450 records, and a reader
    that falls behind loses questions to `ringbuf_full` rather than merging them into a count.
  - There is no TLS SNI or HTTP visibility. DNS visibility is the queried name and nothing else:
    only UDP datagrams to port 53 are read, so DNS over HTTPS, DNS over TLS and DNS over TCP/53
    produce no observation, no answer or query type is recorded, and a cached or shared answer
    means no question was asked at all. A resolution is also not a connection.
- **The kernel-side counters are always on, even for enforce-only nodes.** What used to be
  learning-mode residue is now the substrate of monitor mode: every LSM enforcer increments per-path
  counters in the `open_events` hash-of-maps on every hook invocation regardless of mode, and
  `probe.c` counts destination addresses whenever the `OBSERVE`/`LEARNING_MODE` flag bit is set.
  Userspace only enables the egress flag for pods with an observe-mode policy, but the LSM path
  counting is unconditional in the C, so an enforce-only deployment still pays for it (and the outer
  map is only populated for cgroups an observing enforcer knows about, so most lookups miss).
  Removing the cost requires a `#ifdef`-gated build or a mode flag in the C. Recompiling is not
  the obstacle: `make generate-bpf` builds every object in `hack/bpf-builder` and `make verify-bpf`
  gates drift in CI, so this is unbuilt work rather than an unavailable toolchain. The DNS
  observer shows the shape a gate should take: the program returns before
  reading anything when the skb's cgroup is absent from its `cgids` map, so an unselected pod pays
  one hash lookup per datagram and nothing else.
- **Container attribution is best-effort per runtime.** `pkg/containers.buildCandidatePaths` now
  generates candidates for `cri-containerd`/`crio`/`docker` scopes across systemd and cgroupfs
  layouts with a cgroup v1 fallback, and `ResolveCgInfos` returns partial results plus a joined
  error instead of failing or panicking on the first bad container. It is still a path-shape
  heuristic: an unrecognized layout yields no cgroup ID, no enforcement, and no observation for that
  container. The failure is now logged and requeued rather than silent, but there is no positive
  confirmation that a pod is covered.
- **Unsupported network targets are rejected, not programmed.** The egress maps are IPv4 `/32`
  hashes by construction (`u32` key, `ip->daddr` only, no L4 parsing). `egressfilter.ParseTargets`
  expands CIDRs of `/24` or narrower and rejects IPv6, wider CIDRs, and hostnames as typed
  `RejectedTarget` values that reach a `V(0)` log and a `TargetsValid=False` condition. They are no
  longer dropped silently, but they are still not enforceable. An LPM-trie/IPv6 map redesign is the
  follow-up (#41).
- **Enforcement findings are counter-grained.** The observation maps count `(target, decision)`
  pairs, so an enforce-mode deny surfaces as a finding with `enforced=true` — but only counts
  survive, not per-occurrence ordering, PIDs, or timing, and only for pods some policy has in
  observe scope (egress counting still requires the pod's `OBSERVE` flag).
- **eBPF behavior is only partly exercised in CI.** Unit tests cover the pure logic (parsing,
  matching, attribution, status sharding, reporting) and the manager bookkeeping through seam
  interfaces, and a kind-based lane covers egress enforcement and program load. LSM-behavioral
  tests need `lsm=bpf` in the kernel command line, which hosted runners do not provide, so that job
  is `workflow_dispatch`-gated. The DNS question observer sits on the same line: the verify
  lane proves the object loads and `TestDNSQueryMapsRoundTrip` proves its maps are usable through
  the calls `dnsmgr` makes, but no lane asserts end to end that a question from a real pod becomes
  a finding.
- **A `dns` value's shape is decided by the compiler, not by admission.** The CRD carries two
  `dns` rules — the behavior-kind count, and a spec-level rule refusing `mode: enforce` alongside a
  `dns` behavior — but `values` is `[]string`, so an address as a `dns` value or a misplaced
  wildcard is well-formed OpenAPI and accepted by the apiserver; the daemon refuses it at compile
  time and reports `Applied=False` with reason `CompileFailed`. There is no admission webhook to
  close that gap, so a `kubectl apply` of a malformed value succeeds and the operator has to read
  the status. Pinned by `test/chainsaw/runtimepolicy-dns`, which asserts the current split so that
  moving value validation into admission turns those steps red.

- **No promotion workflow.** There is no code path that turns observed behavior into a proposed
  `RuntimePolicy` allow/deny list. The intent is for that promotion step to become a separate,
  LLM-assisted project rather than a CLI command added to this repository.
