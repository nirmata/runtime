# Development guide

How to build, test, and validate kyverno-runtime locally.

## Prerequisites

| Tool | Notes |
| --- | --- |
| Go | Version from `go.mod` (`go 1.26.0`). [Install Go](https://golang.org/doc/install) |
| Docker | Image builds and the BPF builder container |
| kind | Local cluster: `go install sigs.k8s.io/kind@latest` |
| kubectl | [Install kubectl](https://kubernetes.io/docs/tasks/tools/) |
| Helm 3+ | The chart in `charts/kyverno-runtime/` |
| Chainsaw | `v0.2.15` (pinned as `CHAINSAW_VERSION` in the Makefile) |
| golangci-lint | `v2.11.4` in CI |
| ko | `v0.17.1` in CI |
| Node | `npx` runs `markdownlint-cli2` |

Everything that touches the kernel — attaching programs, draining observation maps, the BPF
smoke test — needs a Linux host. The unit suites, `go build`, and the lint targets all run on
macOS; the kernel-bound tests skip themselves there.

## Build and test targets

| Target | Purpose |
| --- | --- |
| `make build` | `fmt` + `lint`, then build `./cmd/kyverno-runtime` |
| `make fmt` | `gofmt -l -w .` |
| `make lint` | `golangci-lint run ./...` |
| `make lint-docs` | `markdownlint-cli2` over every tracked markdown file |
| `make helm-verify` | `helm lint`, then template the chart with defaults and with the toggles flipped |
| `make helm` | `helm-verify`, then package the chart into `dist/` |
| `make helm-push` | `make helm`, then `helm push` the package to `CHART_REGISTRY` |
| `make test` | Alias for `test-unit` |
| `make test-unit` | `go test -race ./...` |
| `make test-chainsaw` | CRD schema and admission conformance; needs a cluster with the CRDs applied, no daemon |
| `make test-e2e` | Full Chainsaw e2e suite, minus the LSM tests |
| `make test-e2e-gate` | Install gate only: image builds, chart installs, DaemonSet Ready, policies accepted |
| `make test-e2e-egress` | Egress allow/deny enforcement behavior |
| `make test-e2e-lsm` | BPF-LSM `open`/`exec` enforcement behavior |
| `make test-bpf-smoke` | Program load and verifier acceptance; needs Linux and root |
| `make smoke-quickstart` | Alias for `test-e2e-gate` |
| `make premerge-smoke` | `build` + `kind-install` + `smoke-quickstart` |
| `make run` | `go run ./cmd/kyverno-runtime` |
| `make ko-build` | Build the image locally with ko |
| `make ko-push` | Build and push a multi-arch image |
| `make kind` | Create a kind cluster, then `kind-install` |
| `make kind-load-image` | Load the locally built image into the kind cluster |
| `make kind-install` | `ko-build` + `kind-load-image` + `kind-install-manifests` |
| `make kind-install-prebuilt` | Same, reusing an image already in local Docker |
| `make kind-install-manifests` | Apply the CRDs and `helm upgrade --install` the chart |
| `make test-e2e-install` | `kind-install` + `test-e2e` |
| `make test-e2e-install-prebuilt` | `kind-install-prebuilt` + `test-e2e` |
| `make generate-crds`, `make verify-crds` | Regenerate the CRDs from `api/v1alpha1`, or fail on drift |
| `make generate-bpf`, `make verify-bpf` | Regenerate the BPF objects from the `_cprog` sources, or fail on drift |
| `make bpf-builder-image` | Build the pinned-clang container `generate-bpf` runs in |
| `make generate-client`, `make generate-listers`, `make generate-informers` | Regenerate `pkg/client/` |

`make run` starts the root command, which prints usage. The daemon is
`kyverno-runtime daemon`, and it requires the `NODE_NAME` environment variable, so running it
outside a pod means setting that yourself.

## Local workflow

```bash
git checkout -b feature/my-change
make build      # fmt, lint, compile
make test       # unit suites with -race
```

For anything that touches the managers, the collector, the monitor, or the reporter, validate on
a cluster before finishing:

```bash
make kind             # first time: create the cluster and install
make kind-install     # subsequent iterations: rebuild, reload, upgrade
make smoke-quickstart # install gate
make test-e2e-egress  # egress enforcement behavior
```

`make kind-install` rebuilds and reloads the image every time. Running only the Chainsaw suites
validates whatever image was loaded last.

Documentation-only changes need `make lint-docs`, not `make build` or `make test`.

Commits are signed: `git commit -s`.

## Test layout

`test/chainsaw/` — CRD schema and admission conformance. It needs `charts/kyverno-runtime/crds`
applied to a cluster and nothing else: no image, no daemon, no eBPF-capable kernel. Everything
asserted there is decided by the apiserver from the generated OpenAPI schema and its CEL rules.
`runtimepolicy-valid/` holds manifests that must be accepted, `runtimepolicy-invalid/` those that
must be rejected. Config: `test/chainsaw/.chainsaw.yaml`.

`test/e2e/` — needs the chart installed on a kind cluster. Config: `test/e2e/.chainsaw.yaml`; the
cluster shape it expects is `test/e2e/kind-config.yaml`.

| Directory | What it covers | In `make test-e2e` |
| --- | --- | --- |
| `install-gate/` | Image builds, chart installs, DaemonSet Ready, policies accepted. Asserts nothing about eBPF. | yes |
| `egress-enforce/` | Default-deny with a single allow-listed pod IP: the allowed target stays reachable **and** the denied one does not. | yes |
| `dispatch-only/lsm-enforce/` | `open` and `exec` deny/allow through the BPF-LSM hooks. | no, excluded by `--exclude-test-regex '^lsm-'` |
| `bpfsmoke_test.go` | Go test that loads the BPF programs and programs their maps. Skips off-Linux and without root. | no, run it with `make test-bpf-smoke` |

File `open` and process `exec` enforcement require a kernel booted with BPF-LSM active: `bpf`
must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel boot parameter). Stock
distributions and hosted CI runners are typically not booted with it. That is why
`dispatch-only/` is excluded from `make test-e2e` and lives behind `make test-e2e-lsm`.

Network egress enforcement and observation require only a cgroup v2 host and BPF support; a
stock kind cluster on a Linux host qualifies.

Run one directory directly:

```bash
chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/egress-enforce/
```

Keep resources around to inspect a failure, then clear them before rerunning — a stale Pod or
`RuntimePolicy` causes immutable-field patch failures and false negatives:

```bash
chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/egress-enforce/ --skip-delete
kubectl -n kyverno-runtime logs -l app.kubernetes.io/name=kyverno-runtime --tail=400
kubectl get reports -A
kubectl delete runtimepolicy --all
```

## Generated artifacts

Every committed generated file must be reproducible by a pinned toolchain from committed source,
and CI checks it.

- **CRDs** (`charts/kyverno-runtime/crds/`): `make generate-crds` runs `controller-gen` at the
  version pinned in the Makefile, which stamps itself into a version annotation on every CRD — an
  unpinned run makes that annotation flap. `make verify-crds` fails on any diff.
- **BPF objects** (`pkg/bpf/*/*_bpfe*.{go,o}`): `make generate-bpf` compiles the `_cprog/*.c`
  sources inside `hack/bpf-builder`, whose pinned clang is the reproducibility contract; the
  container runs as the invoking user so nothing ends up root-owned. `make verify-bpf` fails on
  any byte difference. Never hand-edit `*_bpfel.go`, `*_bpfeb.go`, or `.o` files — add
  `_cprog/*.c` with a `go:generate` line instead.
- **Typed client** (`pkg/client/`): `make generate-client`, `make generate-listers`,
  `make generate-informers`.

## CI workflows

Three workflows in `.github/workflows/`. Each job name says whether it is an assertion (it fails
when the product misbehaves) or a gate (it fails when the build or install breaks).

### `ci.yml`

Runs on pushes to `main`, pull requests targeting `main`, and manual dispatch.

| Job | Kind | What it runs |
| --- | --- | --- |
| `Build & Unit Test` | assertion | `gofmt -l`, golangci-lint, `markdownlint-cli2`, `go build ./...`, `go vet ./...`, `make test-unit` |
| Helm and CRD drift | gate | `make helm-verify`, `make verify-crds` |
| BPF object drift | gate | `make verify-bpf` |
| CRD conformance | assertion | `make test-chainsaw` on a bare kind cluster |
| BPF verifier smoke | assertion | Kernel preconditions, then `make test-bpf-smoke` as root |
| Egress enforcement | assertion | `make kind-install`, `make test-e2e-gate`, `make test-e2e-egress` |
| LSM enforcement | assertion | `workflow_dispatch` only: `make test-bpf-smoke` and `make test-e2e-lsm` on a host booted with `lsm=...,bpf` |

`Build & Unit Test` is the required status check in the repository ruleset for `main`, matched by
job name. Renaming it leaves pull requests permanently unmergeable with no failure anywhere to
explain why; if it is renamed, the ruleset changes in the same commit.

### `release.yml`

Runs on tag pushes (`v*`):

- `lint-test` gates everything downstream: `gofmt`, `make lint`, `make lint-docs`, a build of
  `./cmd/kyverno-runtime`, and `make test`.
- `publish-candidate` pushes `ghcr.io/nirmata/kyverno-runtime:candidate-<sha>` for
  `linux/amd64,linux/arm64`.
- `release-e2e` pulls that candidate, installs it into kind with `make kind-install-prebuilt`,
  and runs `make test-e2e-gate` and `make test-e2e-egress`. BPF-LSM `open`/`exec` behavior is
  not covered, for the same reason it is not covered in `ci.yml`: hosted runners are not booted
  with `lsm=...,bpf`.
- `promote-image` retags the tested digest with the git tag using
  `docker buildx imagetools create`, so the released image is the exact artifact e2e ran
  against and the manifest list keeps both platforms. There is no `latest` tag.
- Derives the chart version from the tag (`v0.2.0` → `0.2.0`), updates
  `charts/kyverno-runtime/Chart.yaml` `version` and `appVersion`, then runs `helm lint` and
  `helm package`.
- Pushes the packaged chart to `oci://ghcr.io/nirmata/charts`, which resolves to
  `ghcr.io/nirmata/charts/kyverno-runtime` and keeps the chart package separate from the
  `ghcr.io/nirmata/kyverno-runtime` image package.

### Publishing a chart by hand

`make helm` packages into `dist/`; `make helm-push` publishes it. Both read `version` and
`appVersion` from `Chart.yaml` and accept an override, so a release can be cut without
editing the file:

```bash
helm registry login ghcr.io -u <username>
make helm-push CHART_VERSION=0.1.0 CHART_APP_VERSION=v0.1.0
```

`appVersion` is the image tag the DaemonSet pulls when `image.tag` is unset. Point it at a
tag that exists in `ghcr.io/nirmata/kyverno-runtime`, or the chart installs and every daemon
pod then fails `ImagePullBackOff`.

A chart pushed from a private repository is a private GHCR package: `helm install` returns
401 or 404 for anyone who has not run `helm registry login`. Make the package public in its
GHCR settings to publish it, or document the login step for consumers.

Override `CHART_REGISTRY` to publish somewhere else, which is also how to rehearse the push
against a local registry:

```bash
docker run -d -p 5000:5000 registry:2
make helm-push CHART_REGISTRY=oci://localhost:5000/nirmata/charts
```

### `ghcr-candidate-cleanup.yml`

Prunes the `candidate-<sha>` tags `release.yml` produces. Weekly schedule and manual
dispatch: deletes older `candidate-*` container versions from GHCR,
keeping a configurable number of the newest, with a `dry_run` mode for preview.

All actions are pinned to commit hashes with the semantic version as a trailing comment. To
update one, replace the hash in every workflow that uses it and keep the comment in sync.

## Project structure

```text
kyverno-runtime/
├── cmd/kyverno-runtime/     # main, root command, and the daemon subcommand
├── api/v1alpha1/            # the RuntimePolicy CRD types
├── pkg/                     # see the package map in Agents.md
├── charts/kyverno-runtime/  # Helm chart: DaemonSet, RBAC, and crds/
├── hack/bpf-builder/        # pinned-clang container used by generate-bpf
├── test/chainsaw/           # CRD schema and admission conformance
├── test/e2e/                # cluster e2e suites plus the BPF smoke test
├── examples/                # runnable scenario manifests, validated in CI
├── docs/users/              # user documentation
├── docs/dev/                # this guide and DESIGN.md
└── Makefile
```

The one-line-per-package index is the package map in [Agents.md](../../Agents.md); read it before
deciding where new code goes. [DESIGN.md](DESIGN.md) has the architecture behind it.

## Code conventions

### Naming

- Files and packages use `snake_case`.
- Exported types and functions use `PascalCase`.
- Interface names end with `-er` (`Source`, `Sink`, `Compiler`).

### Testing

- Unit tests live in the same package as the code, `*_test.go`.
- Tests are table-driven, stdlib `testing` plus `github.com/google/go-cmp/cmp` for struct diffs.
  No testify.
- Inject time (`Clock func() time.Time`) and filesystem roots (`procRoot`). Never sleep in a test
  and never touch the real `/proc`. Kernel-touching code goes behind the managers' seam
  interfaces so its bookkeeping is testable off-kernel.
- Cluster-level tests are Chainsaw suites under `test/`.

### Error handling

- Wrap errors: `fmt.Errorf("context: %w", err)`.
- Anything a user authored that cannot be honored must reach a `V(0)` log **and** a status
  condition. "Silently skipped" is the forbidden failure mode.
- Do not add a `recover()` barrier around library or internal calls — a panic there is a bug and
  should surface. `utils.Guard` belongs at fan-out boundaries only.

### Documentation

- The default is no comment. Write one where a competent reader of the code would
  still get it wrong — a non-blocking handoff, a padding-free BPF map key, a
  parameter that takes a raw value and escapes it internally.
- Never narrate history: no "no longer", "used to", "previously", no changelog
  prose, no GitHub issue or PR numbers. Git blame and the tracker hold that.
- No package doc comments. No error-handling narration. No ALL-CAPS
  MUST/NEVER/ALWAYS. A comment must carry more than the signature below it, and a
  comment block longer than the body it explains is a smell.
- When a test pins a regression, encode the *invariant* in the test name and doc
  comment, not the ticket number — the invariant outlives the tracker.
- Full rules and the review history behind them: [CLAUDE.md](../../CLAUDE.md).
- Architecture context: [DESIGN.md](DESIGN.md).

### Markdown

- `make lint-docs` must pass. Keep tables compact (`| --- | --- |`), give every fenced block a
  language, use markdown links rather than bare URLs, and avoid duplicate headings in a file.
- Every fenced `yaml` block declaring `apiVersion: runtime.nirmata.io/v1alpha1` is validated, so
  an inline snippet has to be a complete manifest with `spec.mode` set.

## Troubleshooting builds and tests

**golangci-lint failures.**

```bash
golangci-lint run ./... --fix
```

**Image build fails, or the build picks up a stale layer.**

```bash
docker system prune -a
make ko-build
```

**e2e tests fail with `ImagePullBackOff`.** The image was not loaded into the kind cluster:

```bash
make kind-load-image
kubectl -n kyverno-runtime rollout restart daemonset/kyverno-runtime-kyverno-runtime
```

**Tests time out.** Raise the timeout in the relevant `.chainsaw.yaml`, or check the daemon is
healthy:

```bash
kubectl -n kyverno-runtime logs -f -l app.kubernetes.io/name=kyverno-runtime
```

**A Chainsaw assertion misbehaves.** The embedded evaluator does not support every CEL
feature — `exists(...)` in particular. Prefer portable checks such as
`contains(to_string(...), ...)` for list membership.

**Cleanup hangs on namespace or resource deletion after the assertions passed.** Capture the
assertion evidence, rerun with a controlled cleanup strategy, and treat it as an environment
issue rather than a product regression.

## Getting help

- [DESIGN.md](DESIGN.md) for architectural context.
- [Agents.md](../../Agents.md) for the package map and task workflow.
- [GitHub Issues](https://github.com/nirmata/kyverno-runtime/issues).
