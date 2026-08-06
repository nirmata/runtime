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
- `pkg/dnsmgr.Manager`: the same pair of interfaces for the DNS question observer, deciding which
  pods it is attached to and gated in for (see [The event plane](#the-event-plane)). Wired only if
  `pkg/bpf/dnsquery` loads; a kernel that refuses the program leaves every other behavior working.
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
| `podSelector` | `*metav1.LabelSelector` | Pods this policy applies to. |
| `evaluationInterval` | `*metav1.Duration` | If set, the policy is periodically re-evaluated (`controller.evaluateForInterval`) instead of only on create/update. |
| `variables` | `[]admissionregistrationv1.Variable` | Named CEL expressions reusable across behaviors via `variables.<name>`. |
| `behaviors` | `[]PolicyBehavior` | The allow/deny rules, one entry per behavior type. |
| `mode` | `*RuntimePolicyMode` | `monitor` or `enforce`. `enforce` programs the deny/allow maps; `monitor` attaches the same programs with empty maps and evaluates observations in userspace (see [The event plane](#the-event-plane)). Optional with no default: a policy that omits `mode` is inert — see [Known Gaps](#known-gaps--future-work). |

Each `PolicyBehavior` entry must set **exactly one** of `network`, `exec`, `open`, or `dns`,
enforced by an `XValidation` rule:
`(has(self.network) ? 1 : 0) + (has(self.exec) ? 1 : 0) + (has(self.open) ? 1 : 0) + (has(self.dns) ? 1 : 0) == 1`.
Each behavior (`Behavior` type) has an optional `allow` and/or `deny` (`BehaviorRule`), and each
rule has a literal `values []string` and/or a CEL `expression string` — the compiler unions the
two (`pkg/compiler/compiler.go: compileBehavior`, `pkg/compiler/policy.go: evalCompiledBehavior`).

Semantics (see `docs/users/reference/runtimepolicy.md` for the full reference with examples):

- `network` values are IPv4 addresses, CIDRs, cluster Service DNS names and external domain names
  (egress), `exec` values are command names/paths, `open` values are file paths, `dns` values are
  hostnames or left-wildcards.
- `deny.values: ["*"]` (or an expression producing `["*"]`) is a **default-deny** sentinel for that
  behavior type: that behavior becomes deny-all-except-allowed for matched pods, instead of the
  default allow-all-except-denied. On a `dns` behavior it means "report every name" instead, and
  short-circuits the allow list rather than exempting it.
- A `dns` behavior is observation only, and `pkg/compiler.validateDNSBehavior` rejects it in
  `enforce` mode with a message naming `monitor` and the `network` behavior. The two grammars are
  one function apart on purpose: `ParseDNSValue` accepts a left-wildcard and `ParseNetworkValue`
  rejects one, because a `network` target has to be resolved to addresses and programmed into a
  kernel map while a `dns` value is only ever compared against an observed question name. What a
  hostname *is* comes from a single `validHostname`, so nothing else can drift between them.
  Enforcing a destination named by domain is the `network` behavior's job
  (`egressfilter.ParseTargets` → the domain maps), which is why accepting `enforce` on `dns` would
  be a second spelling of one intent with only one of them working.
- `docs/users/reference/runtimepolicy.md` specifies the multi-policy case as a **union across all `RuntimePolicy`
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
   Open, Exec, DNS, Selector}` where `IPs`/`Open`/`Exec`/`DNS` are each an
   `AllowDenyPair{Allow, Deny []string}`.

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
in userspace. That is the event plane. Most of it rides the counters the enforcement BPF objects
already keep; the DNS question observer is the one source with a program and a ring buffer of its
own.

### Choosing a transport: counter map or ring buffer

The two source shapes are not interchangeable, and the deciding question is what the observation
*is*:

- **A bounded enum rides a counter map.** An address, a resolved path, an exec filename, each
  paired with the kernel's decision: the key set is bounded by what the workload touches, the
  interesting quantity is "how many times", and a read-and-reset drain turns the map into deltas.
  Nothing is lost between polls that the counter does not record, and the kernel side costs one
  map update per event.
- **A variable-length string needs a ring buffer.** A DNS question name is the payload, not a key:
  its value is the whole observation, aggregation would destroy it, and a map keyed on it would be
  a map keyed on unbounded user data. Each occurrence is its own record, delivered as it happens,
  with `Count` fixed at 1.

The cost of the second shape is that a full buffer loses observations where a full counter map
merely stops distinguishing them, which is why the ring buffer source carries loss counters and
the poll sources do not.

### Normalized events (`pkg/runtimeevent`)

`runtimeevent.Event` is the single currency of the plane: a `Kind`
(`net|dns|exec|open`), a timestamp, an optional cgroup ID / PID / comm, a `Count`
(a poll source's observations are deltas, not individual occurrences; a `dns` record is always
one question), two deliberately distinct deny flags —
`KernelDenied`, the kernel's actual enforcement decision, set only by the BPF poll sources from
the decision dimension of the observation maps, and `WouldDeny`, monitor mode's counterfactual,
set only by `pkg/monitor` on its per-policy copy — one non-nil facts struct
per kind, and a `PodIdentity`.

Three interfaces define the plumbing, all in `pkg/runtimeevent/iface.go`:

| Interface | Implemented by | Role |
| --- | --- | --- |
| `Source` | `collector.NewPollSource`, `dnsquery.Source` | Produces events until its context ends. |
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

### The DNS question observer (`pkg/bpf/dnsquery`)

`cgroup_dnsegress` (`_cprog/query.bpf.c`) is a `cgroup_skb/egress` program that reads the QNAME
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
them across CPUs every 30 seconds and reports the delta through the `LossFunc` the daemon wires to
`EventsDropped{source="dnsquery"}`.

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
  `Source`. Poll-based collection is a deliberate consequence of decision 2 above: the enforcement
  programs expose counters, not a stream. `dnsquery.Source` implements `Source` directly, because
  its transport already is one.
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

`Monitor` is the `Sink` that turns observations into findings. It tracks monitor- AND
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
per (namespace, node) named `kyverno-runtime-<nodeName>`. Merging preserves `count`,
`firstTimestamp`, and `lastTimestamp`; results are capped at 500 with a
`runtime.nirmata.io/truncated-results` annotation; a flush whose results are byte-identical to
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
naming the mode (`Enforcing`/`Monitoring`); `TargetsValid` comes from `egressmgr`,
`ObservationAvailable`, `ExecRulesValid` and `OpenRulesValid` from `lsmmgr`, and are merged
verbatim. Each behavior gets its own condition type because conditions are keyed by type and
last-write-wins. This is the mechanism behind
the "fail loud, not silent" rule: a network target the runtime cannot program (IPv6, a CIDR wider
than `/24`, a hostname) is reported as a typed `egressfilter.RejectedTarget`, logged at `V(0)`,
**and** surfaced as `TargetsValid=False` with the per-value reason; an open or exec path that
cannot become a `char[128]` map key does the same through `lsm.RejectedTarget`. Silently skipping
it is the forbidden failure mode.

## Metrics

`pkg/metrics.New(reg)` registers every collector against a caller-supplied `prometheus.Registerer`
— the daemon passes a fresh private `prometheus.Registry` rather than the global default, so
repeated wiring (and tests) cannot panic on duplicate registration. `metrics.Serve(ctx, addr, reg,
log)` exposes `/metrics` and returns cleanly on context cancellation.

`--metrics-addr` (default `:9090`) selects the bind address; the chart passes
`--metrics-addr=:{{ .Values.daemon.metrics.port }}` and declares the matching `containerPort`.
An empty value disables the endpoint without disabling the counters.

`pkg/metrics/metrics.go` registers exactly five collectors, all under the `nirmata_runtime`
namespace: `events_ingested_total{source,kind}`, `events_dropped_total{source,reason}`,
`attribution_misses_total`, `findings_emitted_total{policy,behavior,severity}`, and
`report_writes_total{result}`. The `reason` values something produces are `buffer_full`
(`pkg/collector`), `unattributed` (`pkg/monitor`, `pkg/reporter`),
`unattributed_kernel_deny` (`pkg/monitor`), and `ringbuf_full` / `name_unreadable` /
`undecodable` (`pkg/bpf/dnsquery`, all under `source="dnsquery"`).

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
  reports nothing. Untracked; a `+kubebuilder:default=enforce` or an admission-time requirement is
  the obvious fix and is a breaking change either way.
- **Monitor-mode observation has two transports, and both are lossy at their own edges.** The
  `network`/`open`/`exec` observations ride the counters the enforcement objects already keep; the
  DNS question observer is a program and a ring buffer of its own
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
- **`open`/`exec` rules from separate policies intersect instead of unioning.**
  `docs/users/reference/runtimepolicy.md` specifies default-deny and allow/deny lists as being unioned across all
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
