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
- [Learning mode and the gRPC API](#learning-mode-and-the-grpc-api)
- [WorkloadProfile](#workloadprofile)
- [Helm chart / deployment shape](#helm-chart--deployment-shape)
- [Known Gaps / Future Work](#known-gaps--future-work)

## Overview

kyverno-runtime enforces and observes pod behavior — file opens, process execution, and network
egress — using eBPF, driven by two cluster-scoped CRDs:

- `RuntimePolicy` (`api/v1alpha1/runtimepolicy_types.go`): selects pods and declares allow/deny
  rules for `network`, `exec`, and `open` behaviors.
- `WorkloadProfile` (`api/v1alpha1/workloadprofile_types.go`): declares a bounded learning window
  (experimental — see [WorkloadProfile](#workloadprofile)).

There is no admission webhook in this project; policies are enforced entirely at runtime via
eBPF programs attached from a per-node daemon.

## Components

The binary at `cmd/kyverno-runtime/` (`root.go`) exposes two subcommands:

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
- A gRPC server (`pkg/srv/grpc.go`, `pkg/proto/learning`) exposing `Start`/`Stop`/`Read` for
  learning mode, backed by `LsmManager`/`EgressManager`.

The daemon waits for the `RuntimePolicy` informer cache to sync before starting the pod watcher,
so newly-observed pods are evaluated against the full set of currently-known policies.

### `kyverno-runtime ctrl`

Implemented in `cmd/kyverno-runtime/wpcontroller.go`. A cluster-scoped, non-DaemonSet Deployment
(`charts/kyverno-runtime/templates/ctrl-deployment.yaml`, disabled by default —
`ctrl.enabled: false` in `values.yaml`) built on `controller-runtime`. It:

- Watches `WorkloadProfile` objects (`pkg/workloadprofile.NewWorkloadProfileController`).
- Resolves daemon pod endpoints from the daemon `DaemonSet`'s `Service`/`EndpointSlice`
  (`pkg/controller.NewDsEndpointResolver`, configured via `--daemonset-svc-name`/`--daemonset-svc-ns`).
- Calls each daemon's gRPC learning API (`Start`/`Stop`) to begin/end a learning window when a
  `WorkloadProfile` is created/deleted.

`ctrl` supports leader election (`--leader-elect`, default `true` when enabled via the chart) and
exposes standard `/healthz`/`/readyz` probes and a metrics endpoint.

## RuntimePolicy: schema and semantics

`RuntimePolicySpec` (`api/v1alpha1/runtimepolicy_types.go`) has exactly these fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `podSelector` | `*metav1.LabelSelector` | Pods this policy applies to. |
| `evaluationInterval` | `*metav1.Duration` | If set, the policy is periodically re-evaluated (`controller.evaluateForInterval`) instead of only on create/update. |
| `variables` | `[]admissionregistrationv1.Variable` | Named CEL expressions reusable across behaviors via `variables.<name>`. |
| `behaviors` | `[]PolicyBehavior` | The allow/deny rules, one entry per behavior type. |

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

## Learning mode and the gRPC API

Each daemon exposes a gRPC `LearningService` (`proto/learning.proto`,
`pkg/proto/learning/learning_grpc.pb.go`), served by `pkg/srv/grpc.go`:

- `Start(uid, labels, duration)`: fans out to both `LsmManager.Start` and `EgressManager.Start`
  (`events.LearningIface`), each of which finds currently-attached pods whose labels match
  `labels` and flips a per-cgid "learning mode" flag in the relevant BPF map
  (`SetLearningModeForCgids` for open events / an analogous mechanism for egress) for `duration`,
  tracked under `uid`.
- `Stop(uid)`: cancels the learning window early.
- `Read(uid, behaviorKind)`: reads back per-pod counts from the BPF maps recorded during the
  window — `BEHAVIOR_NETWORK` from `EgressManager`, `BEHAVIOR_OPEN`/`BEHAVIOR_EXEC` both read from
  `LsmManager` (see [Known Gaps](#known-gaps--future-work)).

`pkg/srv/srv.go` additionally implements an HTTP handler (`learningModeSrv.ServeHttp`) that
fans a single request out over gRPC to every known daemon endpoint (as resolved by `ctrl`'s
`DsEndpointResolver`) and merges the per-daemon `Read` results — this is the path `ctrl` (or any
future caller) would use to collect learned behavior across the whole cluster for one workload
profile UID.

## WorkloadProfile

`WorkloadProfileSpec` (`api/v1alpha1/workloadprofile_types.go`) has two fields:
`behaviorsToLearn []string` and `duration *metav1.Duration`, with an `XValidation` rule making the
whole spec immutable (`self == oldSelf`). The CRD is cluster-scoped, has a `Ready` status field,
and a `finalizer` (`runtime.kyverno.io/finalizer`) to guarantee `Stop` is attempted on daemons
before the object is removed (`pkg/workloadprofile/workloadprofile_reconciler.go`).

**This is present as a CRD and reconciler, but is not yet functionally complete**:

- The reconciler's `handleNewWorkloadProfile` builds a gRPC `StartRequest` with
  `Labels: make(map[string]string), // todo` — an empty, unpopulated label map. Since
  `LsmManager.Start`/`EgressManager.Start` select pods via
  `labels.SelectorFromSet(matchLabels)`, an empty map is the "select everything" selector, not the
  workload the user intended to target. Pod-label targeting from `WorkloadProfile` to the daemons
  is a no-op today.
- `behaviorsToLearn` is accepted by the schema and immutability-checked, but is never read anywhere
  in `pkg/workloadprofile` or plumbed into the `StartRequest` — the daemons currently always learn
  every behavior kind they support for the (currently unfiltered) matched pods, regardless of what
  `behaviorsToLearn` says.
- `kyverno-runtime ctrl` (and therefore `WorkloadProfile` reconciliation) is disabled by default in
  the Helm chart (`ctrl.enabled: false`).

Treat `WorkloadProfile` as an experimental, in-progress mechanism: the CRD, controller wiring, and
gRPC learning-window plumbing exist and run, but do not yet scope learning to the intended pods or
behaviors. `docs/workloadprofile.md` documents this from a user-facing perspective; a separate,
concurrent change is removing `WorkloadProfile` from user-facing docs (e.g. `README.md`) for
initial OSS release scoping. That is a documentation-scoping decision for user docs — it does not
change what's true in code, which is what this file describes.

## Helm chart / deployment shape

`charts/kyverno-runtime/` installs:

- A `DaemonSet` (`templates/daemonset.yaml`) running `kyverno-runtime daemon`, always installed,
  privileged, `hostPID: true`, with host mounts for `/`, `/run`, `/var/run`, `/sys/fs/bpf`,
  `/sys/kernel/debug`, and `/sys/kernel/tracing`, and `NODE_NAME` injected from
  `spec.nodeName`.
- A `Deployment` (`templates/ctrl-deployment.yaml`) running `kyverno-runtime ctrl`, gated behind
  `.Values.ctrl.enabled` (default `false`).
- A shared `ClusterRole`/`ClusterRoleBinding`/`ServiceAccount`
  (`templates/clusterrole.yaml`, `templates/clusterrolebinding.yaml`, `templates/serviceaccount.yaml`),
  with `values.daemon.rbac.extraRules` as an escape hatch for granting the daemon access to
  additional resource types referenced by the `resource` CEL library.
- CRDs for `RuntimePolicy` and `WorkloadProfile` (`charts/kyverno-runtime/crds/`), plus the
  vendored OpenReports CRDs (`openreports.io_*`) — the OpenReports API is registered into both
  binaries' schemes (`openreportsv1alpha1.Install(scheme)`) but is not otherwise used by any code
  path described above; no component in this repo currently creates or reconciles `Report`/`ClusterReport`
  objects.

## Known Gaps / Future Work

These are verified, current limitations — not planned features to build toward, which belong in a
future `PLAN.md`:

- **`spec.mode` is wired into the CRD's print column but not into the API type.**
  `RuntimePolicyMode` (`monitor`/`enforce`) and the constants `PolicyModeMonitor`/`PolicyModeEnforce`
  are defined in `api/v1alpha1/runtimepolicy_types.go`, and `RuntimePolicy` carries a
  `+kubebuilder:printcolumn:name="Mode",JSONPath=".spec.mode"` marker (reflected in the generated
  CRD YAML, `charts/kyverno-runtime/crds/runtime.kyverno.io_runtimepolicies.yaml`). However,
  `RuntimePolicySpec` has **no `Mode` field** — only `PodSelector`, `EvaluationInterval`,
  `Variables`, and `Behaviors`. The `Mode` printer column will render empty for every policy, and
  there is no monitor-vs-enforce distinction anywhere in the evaluation or enforcement code today;
  every policy is unconditionally enforced. This is incomplete wiring left over from an earlier
  design, not a working (even partial) feature — do not build on `RuntimePolicyMode` without
  first adding the field to the spec and threading it through `pkg/compiler`, `pkg/lsmmgr`, and
  `pkg/egressmgr`.
- **`exec` behaviors compile and evaluate but are not enforced.** `PolicyBehavior.Exec` is
  compiled by `pkg/compiler` and appears in `EvaluationResult.Exec`, and the BPF LSM program
  (`pkg/bpf/lsm/_cprog/lsm.bpf.c`) supports a second attach target for this
  (`bprm_check_security`, `argTypeExecCheck` in `pkg/bpf/lsm/lsm.go`). But `pkg/lsmmgr` only ever
  instantiates an LSM enforcer for the `file_open` target (`lsm.NewForAttachTarget(&l.logger,
  "file_open")` in `pkg/lsmmgr/runtimepolicies.go`) and only ever reads/writes
  `compiledRp.Open`; `compiledRp.Exec` is never consulted by `lsmmgr` or `egressmgr`. A
  `RuntimePolicy` with only `exec` rules will compile, apply, and report success, but has no
  runtime effect. The gRPC `Read` API's `BEHAVIOR_EXEC` case also currently reads from the same
  open-events map as `BEHAVIOR_OPEN` (`pkg/srv/grpc.go`), which is consistent with there being no
  distinct exec enforcer yet.
- **`WorkloadProfile` pod-label targeting is a no-op.** See [WorkloadProfile](#workloadprofile)
  above — `workloadProfileReconciler.handleNewWorkloadProfile` sends an empty `Labels` map in the
  `StartRequest`, so learning mode currently applies to all pods a daemon has attached rather than
  the workload the profile named, and `behaviorsToLearn` is not read at all.
- **No in-repo promotion workflow.** There is currently no code path that turns learned/observed
  behavior (via the `Read` gRPC API) into a proposed `RuntimePolicy` allow/deny list. The intent is
  for that promotion step to become a separate, LLM-assisted project rather than a CLI command
  added to this repository; a full design for that is out of scope here and belongs in a future
  `PLAN.md`.
