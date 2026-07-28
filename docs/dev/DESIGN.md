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
- [Shadow AI detection](#shadow-ai-detection)
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
- `pkg/lsmmgr.LsmManager` and `pkg/egressmgr.EgressManager`: both an `events.PodEventHandler` and
  an `events.RuntimePolicyEventHandler`; they drive the actual eBPF attachments (see
  [Enforcement](#enforcement-ebpf-lsm-hooks-and-egress-filtering)).
- `pkg/attribution.Index` is a `PodEventHandler`; `pkg/controller.StatusWriter` and
  `pkg/monitor.Monitor` are `RuntimePolicyEventHandler`s — the cgroup→pod index, the status writer,
  and the monitor-mode evaluator (see [The event plane](#the-event-plane)).
- `pkg/metrics`, `pkg/collector`, `pkg/reporter`: the Prometheus registry and `/metrics` server,
  the observation pipeline, and the OpenReports writer.

`runDaemon` is the single wiring site; the two typed handler slices are what the compiler checks:

```text
metrics registry + Serve(--metrics-addr)    -> errgroup
attribution.NewIndex(WithMetrics)
reporter.New(controller-runtime client)     -> Run in errgroup
controller.NewStatusWriter(nodeName, 30s)   -> Run in errgroup
egressmgr.NewEgressManager(log, statusWriter)
lsmmgr.NewLsmManager(log, statusWriter)
monitor.New(log, reporter, metrics)
podHandlers    = [em, lsmm, attrIdx]
policyHandlers = [em, lsmm, statusWriter, monitor]
collector: PollSource(egress-observe, 10s) + PollSource(lsm-observe, 10s)
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
| `podSelector` | `*metav1.LabelSelector` | Pods this policy applies to. |
| `evaluationInterval` | `*metav1.Duration` | If set, the policy is periodically re-evaluated (`controller.evaluateForInterval`) instead of only on create/update. |
| `variables` | `[]admissionregistrationv1.Variable` | Named CEL expressions reusable across behaviors via `variables.<name>`. |
| `behaviors` | `[]PolicyBehavior` | The allow/deny rules, one entry per behavior type. |
| `mode` | `*RuntimePolicyMode` | `monitor` or `enforce`. `enforce` programs the deny/allow maps; `monitor` attaches the same programs with empty maps and evaluates observations in userspace (see [The event plane](#the-event-plane)). Optional with no default: a policy that omits `mode` is inert — see [Known Gaps](#known-gaps--future-work). |

Each `PolicyBehavior` entry must set **exactly one** of `network`, `exec`, or `open`, enforced by
an `XValidation` rule: `(has(self.network) ? 1 : 0) + (has(self.exec) ? 1 : 0) + (has(self.open) ? 1 : 0) == 1`.
Each behavior (`Behavior` type) has an optional `allow` and/or `deny` (`BehaviorRule`), and each
rule has a literal `values []string` and/or a CEL `expression string` — the compiler unions the
two (`pkg/compiler/compiler.go: compileBehavior`, `pkg/compiler/policy.go: evalCompiledBehavior`).

Semantics (see `docs/runtimepolicy.md` for the full reference with examples):

- `network` values are IPv4 addresses (egress), `exec` values are command names/paths, `open`
  values are file paths.
- `deny.values: ["*"]` (or an expression producing `["*"]`) is a **default-deny** sentinel for that
  behavior type: that behavior becomes deny-all-except-allowed for matched pods, instead of the
  default allow-all-except-denied.
- `docs/runtimepolicy.md` specifies the multi-policy case as a **union across all `RuntimePolicy`
  objects matching a pod** — any matching policy asserting default-deny flips the behavior, and the
  effective allow (or deny) list is the union of every matching policy's entries. **That is only
  implemented for `network`.** `pkg/egressmgr` attaches one filter per pod and merges every matching
  policy's IPs into it, tracking the set of policy UIDs that assert default-deny in
  `podAttachment.defaultDeny` so the eBPF flag is cleared only once none remain. `pkg/lsmmgr` has no
  such bookkeeping: it attaches a separate LSM program per policy, so `open`/`exec` compose as an
  intersection rather than a union — see [Known Gaps](#known-gaps--future-work).
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
   `values` with the CEL expression's result, and returns an `EvaluationResult{UID, Name, Mode, IPs,
   Open, Exec, Selector}` where `IPs`/`Open`/`Exec` are each an `AllowDenyPair{Allow, Deny []string}`.

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

Both are compiled from the same source (`pkg/bpf/lsm/_cprog/lsm.bpf.c`) into two distinct BPF
objects — `lsmFileOpen` and `lsmExecCheck` — via `bpf2go` with mutually exclusive
`-DLSM_FILE_OPEN` / `-DLSM_EXEC_CHECK` build flags; the source `#error`s if neither or both are
set. The split replaced the earlier single `lsmGeneric` object that branched on a runtime
`argtypes` map entry, which the verifier rejects for `bprm_check_security` because the context
argument's type is only known at attach time (#51, `3568f42`). `LsmEnforcer` (`pkg/bpf/lsm/lsm.go`)
hides the two object types behind generic `prog`/`cgids`/`banned`/`allowed`/`defaultDeny` fields
plus an `io.Closer`, so `pkg/lsmmgr` is program-type agnostic.

Per enforcer, `createForProgType` populates the `banned`/`allowed` path maps from that behavior's
`AllowDenyPair` — **unless the mode is an observe mode, in which case both maps are left empty and
`default_deny` is never set** — sets the `default_deny` map entry if the deny list contains `"*"`, and attaches
with `link.AttachLSM` (`ebpf.AttachLSMMac`); on any failure the partially-built enforcer is closed.
Matched pods' cgroup IDs (resolved by `pkg/containers`) go into that enforcer's `cgids` map, and the
BPF program returns 0 immediately for any cgroup not in it. In the kernel the decision is a pure map
lookup: if `default_deny` is set, allow only paths present in `allowed`, otherwise deny only paths
present in `banned`; `-EPERM` otherwise.

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

Note the consequence of one program per policy: N enforce-mode policies matching a pod attach N LSM
programs to the same hook, each with its own map set. The kernel denies if any of them denies, so
`open`/`exec` rules from separate policies intersect rather than union
(see [Known Gaps](#known-gaps--future-work)).

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

## The event plane

Enforcement is a kernel-side map lookup and produces no userspace output. Monitor mode needs the
opposite: a stream of what a workload actually did, attributed to a pod, matched against policy
in userspace. That is the event plane. It is built on the counters the **existing** BPF objects
already keep — no new kernel programs, no ring buffers, no new `.o` files.

### Normalized events (`pkg/runtimeevent`)

`runtimeevent.Event` is the single currency of the plane: a `Kind`
(`net|exec|open`), a timestamp, an optional cgroup ID / PID / comm, a `Count`
(observations are deltas, not individual occurrences), two deliberately distinct deny flags —
`KernelDenied`, the kernel's actual enforcement decision, set only by the BPF poll sources from
the decision dimension of the observation maps, and `WouldDeny`, monitor mode's counterfactual,
set only by `pkg/monitor` on its per-policy copy — one non-nil facts struct
per kind, and a `PodIdentity`.

Three interfaces define the plumbing, all in `pkg/runtimeevent/iface.go`:

| Interface | Implemented by | Role |
| --- | --- | --- |
| `Source` | `collector.NewPollSource` | Produces events until its context ends. |
| `Sink` | `monitor.Monitor` | Consumes fully-annotated events; must be fast and must not panic outward. |
| `PolicyStatusRecorder` | `controller.StatusWriter` | Receives status conditions from anywhere in the plane. |

### Observation: draining the existing maps

Both managers grew a `CollectObservations(ctx) ([]runtimeevent.Event, error)` method:

- `pkg/egressmgr/observe.go` walks the pods that have at least one observe-mode policy attached
  (the `OBSERVE` flag is refcounted per pod, so a pod with an empty observe set is not counting)
  and drains that pod's `ip_events` counters via `egressfilter.ReadIPEvents`. Reads are
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

### Collector (`pkg/collector`)

`Collector` is a small fan-in/fan-out pipeline: N `Source`s → a buffered channel → an ordered
list of `Stage`s → N `Sink`s, all driven by `Run(ctx)`.

- `NewPollSource(name, interval, poll)` adapts the managers' `CollectObservations` into a
  `Source`. Poll-based collection is a deliberate consequence of decision 2 above: the existing
  programs expose counters, not a stream.
- A `Stage` (`Name() string; Process(*Event) bool`) may annotate an event and returns false to
  drop it. Stages run in insertion order; the daemon installs exactly one, `attribution.Index`.
- Drops are always counted, labeled by source and reason (`buffer_full`, `unattributed`), and
  exposed via `Dropped()` and `kyverno_runtime_events_dropped_total`. A full buffer drops the
  newest event rather than blocking a source.
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
  `kyverno_runtime_attribution_misses_total`. Dropping unattributed events is only defensible
  because the miss is counted — a silent drop would hide an attribution regression, which is
  exactly what #38 was.

Owner derivation needs no extra RBAC: it reads `pod.OwnerReferences[0]`, and when the owner is a
`ReplicaSet` whose name ends in the pod's `pod-template-hash`, reports the `Deployment` instead.

`PodIdentity.Labels` is the index's own map — replaced, never mutated — and is documented
read-only so the plane does not copy a label map per event. Sinks must not mutate it.

### Monitor (`pkg/monitor`)

`Monitor` is the `Sink` that turns observations into findings. It tracks monitor- AND
enforce-mode policies in a per-event-ready form (`trackedPolicy`: mode, compiled selector plus
`netBehavior`/`pathBehavior` matchers), replacing the whole value on every `RuntimePolicyEvent`
rather than mutating it — both so `HandleEvent` can read one outside the lock and so it is immune
to `egressmgr` mutating the `EvaluationResult` it shares (#53).

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
`kyverno_runtime_events_dropped_total{source="monitor",reason="unattributed_kernel_deny"}` and is
logged at V(2): a kernel deny must never vanish silently.

### Reporter (`pkg/reporter`)

`Reporter` buffers findings, deduplicates them by `Finding.Fingerprint()` (a SHA-256 over policy,
behavior, pod, and target), and flushes every 10 seconds into one namespaced OpenReports `Report`
per (namespace, node) named `kyverno-runtime-<nodeName>`. Merging preserves `count`,
`firstTimestamp`, and `lastTimestamp`; results are capped at 500 with a
`runtime.kyverno.io/truncated-results` annotation; a flush whose results are byte-identical to
what is already stored is skipped rather than written. `Run(ctx)` flushes once more after
cancellation, on a fresh bounded context, so the last window is not lost on shutdown. It writes
through a `sigs.k8s.io/controller-runtime/pkg/client.Client` built from the daemon's `rest.Config`
with the OpenReports types installed in the scheme.

## Redaction chokepoint

Secret material must be structurally incapable of reaching a `Report` or a log line, not merely
filtered out by policy. One chokepoint, not configurable:

**`reporter.Finding`.** `Finding` is a *closed* struct of typed scalars: no header
map, no body field, no free-form properties passthrough. An unredacted payload is not
representable at the boundary. `buildResult` emits a fixed property key set and every value
passes `sanitize`. Pod labels — arbitrary user-controlled key/values — are deliberately never
emitted.

The argument is structural rather than procedural: there is no option, flag, or field that
weakens the mechanism, and adding one is a reason to reject a PR
([Agents.md](../../Agents.md)). It is also tested: `reporter.TestRedactionChokepoint` fails if a
new `Finding` field or property key escapes sanitization. The logging rule that completes it: only
redacted accessor output may be logged — never a raw header map, body, or CEL variable value.

## Status reporting

`pkg/controller.StatusWriter` is the single writer of `RuntimePolicyStatus` and the single
implementation of `runtimeevent.PolicyStatusRecorder`. It consumes the policy event stream only;
pod-level detail belongs to the Reports and the Prometheus counters, not to the status.

Because every node runs a daemon and `RuntimePolicy` is cluster-scoped, status is **sharded**:
`status.nodes` holds one `NodePolicyStatus` per node and each daemon replaces only its own entry,
then lifts the newest `lastEvaluatedTime` across all shards to the top level. Updates flush every 30 seconds (and once on shutdown) via
`retry.RetryOnConflict` against the `status` subresource, so concurrent per-node writes converge
instead of clobbering each other.

Conditions are merged by type: `Applied` is written by the `StatusWriter` itself with the reason
naming the mode (`Enforcing`/`Monitoring`); `TargetsValid` comes from `egressmgr`
and `ObservationAvailable` from `lsmmgr`, and are merged verbatim. This is the mechanism behind
the "fail loud, not silent" rule: a network target the runtime cannot program (IPv6, a CIDR wider
than `/24`, a hostname) is reported as a typed `egressfilter.RejectedTarget`, logged at `V(0)`,
**and** surfaced as `TargetsValid=False` with the per-value reason. Silently skipping it is the
forbidden failure mode.

## Metrics

`pkg/metrics.New(reg)` registers every collector against a caller-supplied `prometheus.Registerer`
— the daemon passes a fresh private `prometheus.Registry` rather than the global default, so
repeated wiring (and tests) cannot panic on duplicate registration. `metrics.Serve(ctx, addr, reg,
log)` exposes `/metrics` and returns cleanly on context cancellation.

`--metrics-addr` (default `:9090`) selects the bind address; the chart passes
`--metrics-addr=:{{ .Values.daemon.metrics.port }}` and declares the matching `containerPort`.
An empty value disables the endpoint without disabling the counters.

Populated today, all under the `kyverno_runtime` namespace:
`events_ingested_total{source,kind}`, `events_dropped_total{source,reason}`,
`attribution_misses_total`, `findings_emitted_total{policy,behavior,severity}`, and
`report_writes_total{result}`. `policy_eval_errors_total{policy,stage}`, `ai_classified_total`, and
`inventory_syncs_total` are registered so that the code paths that will feed them add no new metrics
file, but nothing increments them yet.

## Shadow AI detection

`RuntimePolicy` also carries an `ai` behavior (`PolicyBehavior.AI *AIBehavior`,
4-way exclusive with `network`/`exec`/`open`) that classifies traffic as LLM,
MCP, or A2A instead of matching raw IPs/commands/paths, plus a `discover`
`RuntimePolicyMode` that rolls classified traffic into a cluster-scoped
`AIInventory` singleton instead of emitting per-event findings. The packages
behind this exist and are unit-tested:

- `pkg/detect/ai`: a pure classifier (`Classifier.Classify`) over a
  hot-reloadable provider catalog (`providers.go`, embedded `catalog.json`,
  18 providers), with confidence scoring (`confidence.go`) and an `ai` CEL
  library (`cellib.go`, library name `kyverno.ai`) exposing catalog lookups
  as `ai.isProvider`/`ai.provider`/`ai.isLLMPath`/`ai.isMCPMethod`/
  `ai.isA2AMethod`/`ai.isMCPServerPackage`.
- `pkg/inventory`: `Rollup` accumulates classified events per
  `(namespace, kind, name)` workload key (bounded sets, capped at 64 entries
  / 128 bytes each — model names are attacker-influenced); `Syncer` publishes
  that as this node's shard of the `AIInventory` singleton
  (`SingletonName = "cluster"`) under `RetryOnConflict`.
- `pkg/aicontrols`: `EndpointResolver` (a `collector.Stage`) sets
  `NetFacts.Governed` (`nil`/`true`/`false`) by comparing a destination
  against the configured AIControls proxy's Service + EndpointSlice
  addresses, refreshed periodically — never per-event. This is the seam with
  the AIControls product: kyverno-runtime answers "is this AI call governed
  at all", AIControls answers "what is this AI call doing" (LLM/MCP
  semantics, SSRF floor, approval flows).
- `runtimeevent.AIFacts` (`pkg/runtimeevent/ai.go`) is the classifier's
  output type, attached to an event as `Event.AI`. Every field is one of
  class/provider/model/endpointKind/JSON-RPC-method/transport/confidence/
  evidence-tokens/sanctioned — evidence tokens are names only (host, path,
  header name, port), never a header value or body content
  (`pkg/detect/ai/confidence.go: Token`), consistent with the redaction
  chokepoints described elsewhere in this document.

Full reference (worked YAML for `discover`/`monitor`/`enforce`, the
`AIInventory` CR shape, the provider catalog and how to extend it via
ConfigMap, the `event`/`ai.*` CEL surface, redaction guarantees, and
evasion/limitations) is in [`docs/shadow-ai.md`](../shadow-ai.md) — including,
prominently, the current honest gaps:

- The five BPF sources these packages are meant to consume
  (`pkg/bpf/{dnstrace,netflow,tlspeek,l7peek,exectrace}`) ship their C and their
  decoders but are **not compiled or loaded**: `bpf2go` needs `clang` and a
  generated `vmlinux.h`, neither of which is available on the build host, so each
  constructor reports `runtimeevent.ErrSourceNotWired`. Until that lands, the
  classifier only ever sees synthetic events.
- `cmd/kyverno-runtime/daemon.go` wires the observation pipeline (metrics,
  attribution, reporter, status writer, monitor, collector) but not yet the AI
  stages — classifier, endpoint resolver, detect engine and inventory syncer.
- AI `enforce` mode is not implemented. An `enforce`-mode `ai` behavior is
  intended to downgrade to `monitor` and set `AIEnforcementImplemented=False`,
  per `AIBehavior`'s doc comment, but no code path sets that condition yet.

## Helm chart / deployment shape

`charts/kyverno-runtime/` installs:

- A `DaemonSet` (`templates/daemonset.yaml`) running `kyverno-runtime daemon`, always installed,
  privileged, `hostPID: true`, with host mounts for `/`, `/run`, `/var/run`, `/sys/fs/bpf`,
  `/sys/kernel/debug`, and `/sys/kernel/tracing`, `NODE_NAME` injected from `spec.nodeName`, and
  `--metrics-addr=:{{ .Values.daemon.metrics.port }}` (default 9090) with a matching
  `containerPort` named `metrics`.
- A shared `ClusterRole`/`ClusterRoleBinding`/`ServiceAccount`
  (`templates/clusterrole.yaml`, `templates/clusterrolebinding.yaml`, `templates/serviceaccount.yaml`)
  granting pod/policy reads, `runtimepolicies/status` `[get,update,patch]` for the status writer,
  and full CRUD on `openreports.io` `reports` for the reporter, with
  `values.daemon.rbac.extraRules` as an escape hatch for granting the daemon access to
  additional resource types referenced by the `resource` CEL library.
- The `RuntimePolicy` CRD (`charts/kyverno-runtime/crds/`), plus the vendored OpenReports CRDs
  (`openreports.io_*`), which `pkg/reporter` now writes to; the OpenReports API is registered into
  both the daemon's scheme and the controller-runtime client used for those writes.

## Known Gaps / Future Work

These are verified, current limitations — not planned features to build toward, which belong in a
future `PLAN.md`.

- **An omitted `spec.mode` still leaves a policy inert.** `mode` is `+optional` with no
  `+kubebuilder:default` (`api/v1alpha1/runtimepolicy_types.go`), so it compiles to `""`, which is
  neither `enforce` nor an observe mode, and both managers return early. `monitor` now works (see
  [The event plane](#the-event-plane)), but a policy that omits the field enforces nothing and
  reports nothing. Every example in `docs/runtimepolicy.md` other than the monitor-mode one still
  omits `mode`. Untracked; a `+kubebuilder:default=enforce` or an admission-time requirement is the
  obvious fix and is a breaking change either way.
- **Monitor-mode observation is poll-based and lossy at the edges.** This is a deliberate
  consequence of shipping monitor mode on the already-compiled `.o` files rather than new kernel
  programs:
  - Counters are drained every 10 seconds, so findings lag behavior by up to that interval and
    only counts survive — not per-occurrence ordering or timing.
  - The per-cgroup `open_events` inner map holds 2048 `(path, decision)` keys; a workload touching
    more than that within one interval loses the excess (read-and-reset mitigates, does not
    eliminate).
  - Network observation is destination-IPv4 only: no port, no protocol, no IPv6.
  - No DNS, TLS SNI, or HTTP visibility exists. The `dns`/`tls`/`http` event kinds are declared
    but nothing produces them, and no new kernel programs are loaded by this code.
- **The AI stages are wired into the daemon but have nothing to classify.** `cmd/kyverno-runtime/daemon.go`
  constructs the classifier, endpoint resolver, detect engine and inventory syncer, but the only
  sources feeding the collector are the two observation-map polls. With no BPF sources wired there
  is no DNS, TLS or HTTP traffic for the classifier to see. See
  [Shadow AI detection](#shadow-ai-detection).
- **`open`/`exec` rules from separate policies intersect instead of unioning.**
  `docs/runtimepolicy.md` specifies default-deny and allow/deny lists as being unioned across all
  policies matching a pod. `pkg/egressmgr` does that for `network`, but `pkg/lsmmgr` gives each
  policy its own LSM program with its own `allowed`/`banned`/`default_deny` maps and has no
  cross-policy default-deny tracking. Since the kernel denies when any attached LSM program returns
  `-EPERM`, a policy that default-denies `open` cannot be relaxed by a second policy's `allow` list:
  paths that policy A does not allow stay blocked no matter what policy B says. Untracked — no
  issue filed yet.
- **The kernel-side counters are always on, even for enforce-only nodes.** What used to be
  learning-mode residue is now the substrate of monitor mode: both LSM variants increment per-path
  counters in the `open_events` hash-of-maps on every hook invocation regardless of mode, and
  `probe.c` counts destination addresses whenever the `OBSERVE`/`LEARNING_MODE` flag bit is set.
  Userspace only enables the egress flag for pods with an observe-mode policy, but the LSM path
  counting is unconditional in the C, so an enforce-only deployment still pays for it (and the outer
  map is only populated for cgroups an observing enforcer knows about, so most lookups miss).
  Removing the cost requires a `#ifdef`-gated build or a mode flag in the C — i.e. recompiling the
  BPF objects, which this repository cannot do on the current toolchain.
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
  is `workflow_dispatch`-gated (#60).
- **The five shadow-AI BPF sources are not compiled at all.** `pkg/bpf/{dnstrace,netflow,tlspeek,
  l7peek,exectrace}` ship reviewed C and exhaustively tested pure decoders, but `bpf2go` needs
  `clang` and a generated `vmlinux.h`, so no object exists and no verifier has ever seen them. Each
  constructor reports `runtimeevent.ErrSourceNotWired`. The decoders are tested; the kernel side is
  unproven — treat the C as a proposal until a Linux toolchain lane compiles and loads it.
<!-- The stale gap list that used to follow was removed: #38 (CRI-O/Docker attribution),
     #41 (silently dropped targets), #52, and "reporting/metrics/status are never constructed"
     were all fixed in the foundations PR. Re-verify against the code before re-adding a gap. -->
- **No promotion workflow.** There is no code path that turns observed behavior into a proposed
  `RuntimePolicy` allow/deny list. The intent is for that promotion step to become a separate,
  LLM-assisted project rather than a CLI command added to this repository.
