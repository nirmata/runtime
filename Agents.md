# Instructions for coding agents

Read [CLAUDE.md](CLAUDE.md) first: it holds the conventions review keeps
catching, and every rule in it is there because a real PR broke it.

Read the [DESIGN](docs/dev/DESIGN.md) before making any significant change.

## Documentation Guidelines

### Purpose of Key Documents

**[DESIGN.md](docs/dev/DESIGN.md)** describes the *current* architecture and implementation:

- Component responsibilities and interfaces
- How policies are matched, collected, evaluated, and reported
- Design decisions and rationale
- Integration patterns and workflows
- **Keep this synchronized with the actual codebase** (what's deployed on `main`)

**[docs/runtimepolicy.md](docs/runtimepolicy.md)** is the user-facing reference: the spec, `mode`
semantics, status and conditions, Reports, metrics, and the honest limits of monitor mode. Keep the
limits section truthful — it is the part reviewers check first.

**PLAN.md** would describe *planned* work and future enhancements (development roadmap by
phase, deliverables/status/acceptance criteria, known issues and open design questions), but it
does not currently exist in this repository. If forward-looking roadmap tracking becomes
necessary, create `docs/dev/PLAN.md` following the same "current vs. planned" split described
here, and update this file to reference it again. Until then, skip any PLAN.md-specific step
below.

### When Completing a Feature

1. Ensure code changes are merged to `main` with tests passing
2. Update [DESIGN.md](docs/dev/DESIGN.md):
   - Add new sections or expand existing ones to document the feature
   - Include code examples, configuration, and operational guidance
   - Update diagrams if architecture changed
3. Verify [DEVELOPMENT.md](DEVELOPMENT.md) is current:
   - Add new build targets or workflows if needed
   - Update common development tasks section
   - Document any new operational behaviors
4. If a `docs/dev/PLAN.md` exists at the time, remove/complete the corresponding item there too.

### When Modifying Architecture

1. Update [DESIGN.md](docs/dev/DESIGN.md) first to describe the new design
2. Update this file ([Agents.md](Agents.md)) if runtime policies or development guidelines change
3. Update [DEVELOPMENT.md](DEVELOPMENT.md) for new workflows or behaviors
4. If a `docs/dev/PLAN.md` exists at the time, review it for any affected planned items

## Dev Documents

Store all developer docs in the "docs/dev" folder.

## Code generation and changes

Follow these rules when generating and updating code:

- always run "make build" and "make test" after **code** changes (skip for doc changes). Fix any reported issues.
- after any significant code change, always validate on a kind cluster before finishing (at minimum: `make kind-install` and a targeted behavioral check such as `make smoke-quickstart` when relevant).
- for runtime pipeline, collector, evaluator, or reporter changes, also run "make smoke-quickstart" before finishing.
- when creating a PR, sign commits using "git commit -s...".
- tests are table-driven, stdlib `testing` plus `github.com/google/go-cmp/cmp` for struct diffs. No
  testify. Regression tests encode the pinned invariant in their name and doc comment
  (`TestRequeueCapSurvivesPointerChange`), never an issue or PR number — see the comment rule in
  [DEVELOPMENT.md](DEVELOPMENT.md).
- inject time (`Clock func() time.Time`) and filesystem roots (`procRoot`) — never sleep in a test
  and never touch the real `/proc`. Kernel-touching code goes behind the managers' seam interfaces
  so its bookkeeping is testable off-kernel; "returns an error on darwin" is not a test.
- malformed user input must be rejected or reported, never crash: no unchecked index, no `[1]` after
  `Split`, no `panic("not implemented")` in a CEL binding or decoder. But do not add a `recover()`
  barrier around library or internal calls — a panic there is a bug and should surface. `utils.Guard`
  belongs at the fan-out boundaries only (collector stages/sinks, informer handler fan-out). See the
  panic rule in [CLAUDE.md](CLAUDE.md).
- anything a user authored that cannot be honored must reach a `V(0)` log **and** a status
  condition. "Silently skipped" is the forbidden failure mode.
- never regenerate or edit `*_bpfel.go`, `*_bpfeb.go`, or `.o` files unless you have the full BPF
  toolchain; new `_cprog/*.c` with a commented `go:generate` line is fine.

## Package map

Read this before deciding where new code goes. `docs/dev/DESIGN.md` has the full architecture; this
is the one-line-per-package index.

| Package | Role |
| --- | --- |
| `api/v1alpha1` | The `RuntimePolicy` CRD: spec, `mode`, and the node-sharded status + conditions. |
| `pkg/compiler` | Compiles a `RuntimePolicy` into CEL programs and evaluates it into an `EvaluationResult`. Policy-time, not per event. |
| `pkg/utils` | `Guard(op, fn)` — the panic barrier used at handler fan-out boundaries so one bad handler cannot take out its siblings. |
| `pkg/controller` | `RuntimePolicy` and `Pod` informers (typed queue keys, lister-fetch-at-process, deletes keyed by UID) plus `StatusWriter`. |
| `pkg/containers` | Resolves a pod's container cgroup paths/IDs across containerd/CRI-O/Docker and systemd/cgroupfs layouts. |
| `pkg/bpf/lsm`, `pkg/bpf/egressfilter` | The two eBPF programs: LSM `file_open`/`bprm_check_security` enforcers and a `cgroup_skb/egress` IPv4 filter. Both map-driven, plus per-cgroup observation counters. |
| `pkg/lsmmgr`, `pkg/egressmgr` | The managers that attach those programs per matched pod and drain their observation counters (`CollectObservations`). |
| `pkg/runtimeevent` | The normalized `Event` type, its `KernelDecision`, and the `Source`/`Sink`/`PolicyStatusRecorder` interfaces. |
| `pkg/collector` | Sources → stages → sinks pipeline, with drop accounting and source restart. |
| `pkg/attribution` | cgroup/pod-UID/PID → pod identity index. Both an `events.PodEventHandler` and a `collector.Stage`. |
| `pkg/monitor` | The sink that evaluates observations against monitor-mode policies and emits findings. |
| `pkg/reporter` | Writes findings into namespaced OpenReports `Report`s. The redaction chokepoint. |
| `pkg/metrics` | Prometheus collectors and the `/metrics` server (`--metrics-addr`). |
| `cmd/kyverno-runtime` | The `daemon` subcommand; `daemon.go` is the single wiring site. |

## Runtime event filtering policy

There is one event pipeline: `pkg/collector`, fed by poll sources over the observation counters the
two existing eBPF programs keep, annotated by `pkg/attribution`, consumed by `pkg/monitor`. There is
no `connect`/`tcpconnect` collector and no Inspektor Gadget dependency.

The filtering rules that apply to that pipeline:

- Events that cannot be attributed to a pod are dropped by the `pkg/attribution` stage, and every
  drop increments `kyverno_runtime_attribution_misses_total`. Dropping is only acceptable *because*
  it is counted: a silent drop hides an attribution regression.
- Buffer-full drops are likewise counted, labeled by source and reason. Never add a drop path
  without a counter.
- `open`/`exec` observations are kept even when metadata is sparse, so long as the pod is known.
- Egress observation is destination-IPv4 only. It does see flows a default-deny drops: the BPF
  program computes its decision, records it, and only then returns, and the decision is part of the
  observation counter key. Never move an enforcement return ahead of the counting branch.

## Redaction (non-negotiable)

`docs/dev/DESIGN.md` describes one chokepoint: the closed `reporter.Finding` struct on the way
out. It is not configurable, and that is the point.

- Never add an option, flag, values key, or field that disables, bypasses, or narrows it.
  A PR that does is to be rejected, not merged with a warning.
- Never add a free-form map to `reporter.Finding` or a new key to the fixed property set without
  routing it through `sanitize`.
- Never log a raw header map, request body, or CEL variable value. Only redacted accessor output may
  be logged. `V(0)` is operator-must-see, `V(2)` lifecycle, `V(4)` per-event trace.

## Modes

`spec.mode` is `enforce` or `monitor`. `enforce` programs the deny/allow maps; `monitor` attaches
the same programs with **empty** maps and matches in userspace over polled observations. Use
`compiler.IsObserveMode(mode)` rather than comparing strings, and never let an observe-mode policy
program a deny entry.

## Markdown generation and changes

- Fix all markdownlint issues before finishing markdown changes.
- Keep markdown tables in compact style (`| --- | --- |`) to satisfy table style linting.
- Add a language for every fenced code block (for example: `bash`, `yaml`, `text`).
- Avoid bare URLs in prose; use markdown links instead.
- Avoid duplicate headings in a single file.

## GitHub Actions Configuration

All GitHub Actions in `.github/workflows/` are pinned to specific commit hashes (not mutable tags or versions) for security and reproducibility. This prevents unexpected behavior changes if action authors update tags.

**Format:** `uses: owner/action@<commit_hash> # v<semantic_version>`

Example:

```yaml
uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
```

To update an action to a new version:

1. Find the latest commit hash for the desired version tag on the action's GitHub release page
2. Replace the old hash with the new hash in all three workflows (ci.yml, e2e.yml, release.yml)
3. Include the semantic version as a comment for clarity
4. Test workflows locally with `act` if possible before merging

## Common learnings

- Prefer `apply_patch` (or direct file edits) over shell heredocs in fish; heredoc formatting can break commands.
- For code changes validated on kind, run `make kind-install` before behavioral verification to avoid stale images.
- For runtimebehavior auto-enrollment checks, use controller-managed pods (Deployment/StatefulSet/etc.) unless bare-pod enrollment is explicitly enabled.
- Keep quickstart validation deterministic: verify expected report shape and include actionable diagnostics when results are missing.
- In Chainsaw assertions, avoid CEL features/macros that may not be supported by the embedded evaluator (for example `exists(...)`); prefer portable checks such as `contains(to_string(...), ...)` when validating list membership.
- When rerunning Chainsaw with `--skip-delete`, proactively remove stale test resources (especially Pods and RuntimePolicy objects) to avoid immutable-field patch failures and false negatives.
- If behavior assertions pass but Chainsaw cleanup hangs on namespace/resource deletion, capture the successful assertion evidence, rerun with controlled cleanup strategy, and document cleanup as an environment issue rather than a feature regression.
