# Contributing to Nirmata Runtime

Thanks for considering a contribution. This covers how to get a change built,
tested, and merged. For what makes a good change — naming, comments, panic
handling, redaction, the rest of the judgment calls review keeps catching —
read [CLAUDE.md](CLAUDE.md) and [Agents.md](Agents.md) first. Those apply the
same way whether the change comes from a person or an agent.

## Before you start

- Bugs and feature requests go to [GitHub
  issues](../../issues).
- Security vulnerabilities do not go to the issue tracker. Follow
  [SECURITY.md](SECURITY.md) instead.
- For anything larger than a small fix, open an issue or a draft PR first —
  it's cheaper to redirect a design before code exists than after.

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by` line, certifying you wrote it or
otherwise have the right to submit it under the project's license (the
[Developer Certificate of Origin](https://developercertificate.org/)):

```bash
git commit -s -m "fix: your change"
```

This adds `Signed-off-by: Your Name <you@example.com>` using your git
`user.name`/`user.email`. If you forgot on a commit that's not yet pushed:

```bash
git commit --amend -s
```

For a range of commits already on your branch:

```bash
git rebase --signoff main
```

There is currently no automated DCO check in CI — a PR missing sign-off will
be caught in review rather than by a bot. (Maintainers: adding a DCO check to
CI is tracked as a gap; it should exist before this policy can be enforced
consistently.)

## Setting up your environment

What you can run locally depends on your host, not on which package you're
touching:

| Environment | Unit tests | `make build`/`lint` | Egress e2e (`test-e2e-egress`, `-protocol`) | BPF-LSM e2e (`test-e2e-lsm`, full `test-e2e`) | Regenerating BPF objects |
| --- | --- | --- | --- | --- | --- |
| macOS + Docker Desktop | yes | yes | yes (Docker Desktop's LinuxKit VM boots with BPF-LSM active) | yes | yes, via the containerized builder |
| Linux, `bpf` *not* in `/sys/kernel/security/lsm` | yes | yes | yes (cgroup v2 + BPF is enough) | no — fails loudly rather than skipping | yes, via the containerized builder |
| Linux, `bpf` in `/sys/kernel/security/lsm` | yes | yes | yes | yes | yes, via the containerized builder |

Kernel-touching Go tests (`test-bpf-verify`, `test-bpf-smoke`) skip themselves
on anything but Linux with root, so they won't fail your build on macOS —
they just won't run. Regenerating BPF objects (`make generate-bpf`) needs
only Docker: the pinned clang toolchain lives in the container in
[`hack/bpf-builder/`](hack/bpf-builder/), not on your host, so it produces
identical bytes on macOS and Linux alike.

Tools, versions, and the full prerequisite list are in
[docs/dev/DEVELOPMENT.md](docs/dev/DEVELOPMENT.md).

## Building and testing

```bash
git checkout -b your-branch
make build      # fmt, lint, compile
make test       # go test -race ./...
```

For anything touching the managers, the collector, the monitor, or the
reporter, validate on a cluster before opening the PR:

```bash
make kind             # first time: create the cluster and install
make kind-install     # subsequent iterations: rebuild, reload, upgrade
make smoke-quickstart # install gate
make test-e2e-egress  # egress enforcement behavior
make test-e2e-protocol
```

On a host with BPF-LSM active (Docker Desktop, or a Linux box booted with
`lsm=...,bpf`):

```bash
make test-e2e-lsm     # open/exec enforcement, or:
make test-e2e         # the full Chainsaw suite, LSM included
```

Documentation-only changes need `make lint-docs`, not `make build` or `make
test`. The full target list, what each one needs from the kernel, and the
test layout under `test/chainsaw/` and `test/e2e/` are in
[docs/dev/DEVELOPMENT.md](docs/dev/DEVELOPMENT.md#build-and-test-targets).

## The LSM e2e lane has no PR signal

`open`/`exec` enforcement through BPF-LSM (`test-e2e-lsm` in CI, the
`lsm-behavior` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml))
is `workflow_dispatch`-only, pointed at a self-hosted runner booted with
`lsm=...,bpf`. GitHub-hosted runners cannot satisfy it — `ubuntu-latest`
reports `lockdown,capability,landlock,yama,apparmor,ima,evm` with no `bpf` —
so **no CI job on your pull request exercises the LSM hooks.** The narrower
`test-e2e-gate`, `test-e2e-egress`, and `test-e2e-protocol` lanes run on every
PR instead.

If your change touches `pkg/bpf/lsm`, `pkg/lsmmgr`, or the `open`/`exec`
behaviors, run `make test-e2e-lsm` (or the full `make test-e2e`) yourself
before opening the PR — on Docker Desktop's LinuxKit VM, or on a Linux VM you
boot with a `bpf`-inclusive `lsm=` kernel parameter — and say in the PR
description that you did. A maintainer can also dispatch the `lsm-behavior`
job by hand against a qualifying runner.

## Regenerating committed artifacts

Two kinds of generated file are committed and checked for drift in CI:

- **CRDs** (`charts/kyverno-runtime/crds/`), from `api/v1alpha1` via
  `make generate-crds`. `make verify-crds` fails on any diff — run it after
  changing a type in `api/v1alpha1`.
- **BPF objects** (`pkg/bpf/*/*_bpfe*.{go,o}`), from `pkg/bpf/*/_cprog/*.c`
  via `make generate-bpf`, which runs the pinned-clang container in
  [`hack/bpf-builder/`](hack/bpf-builder/). `make verify-bpf` fails on any
  byte difference. Never hand-edit `*_bpfel.go`, `*_bpfeb.go`, or `.o` files;
  add or change a `_cprog/*.c` source and regenerate instead.

Both checks run in CI (`Helm and CRD drift`, `BPF object drift` in
[`ci.yml`](.github/workflows/ci.yml)) and will fail your PR if the committed
output doesn't match what the pinned toolchain produces. Run the matching
`generate-*` target and commit the result rather than editing the generated
file directly.

A new BPF program also needs an entry in the verifier table in
`test/e2e/bpfverify_test.go` — see
[docs/dev/DEVELOPMENT.md](docs/dev/DEVELOPMENT.md#generated-artifacts) for
what that entry needs.

## Code conventions

Naming, comments, error handling, panics, redaction, and the rest of the
judgment calls that matter more than any checklist here are in
[CLAUDE.md](CLAUDE.md) and [Agents.md](Agents.md). Read them before writing
code, not after review flags something they already cover.

Markdown changes must pass `make lint-docs`: compact tables (`| --- | --- |`),
a language on every fenced code block, no bare URLs, no duplicate headings in
one file.

## Opening a pull request

- Keep the PR self-contained: no comment or identifier referencing an issue
  number or an unmerged companion PR. Put that context in the commit message
  instead.
- Sign every commit (`git commit -s`).
- Describe what you validated: which `make test-e2e-*` targets you ran, and
  on what kind of host (macOS/Docker Desktop, Linux with or without
  BPF-LSM).
- Update `docs/dev/DESIGN.md` if you changed the architecture, and the
  relevant `docs/users/` reference if you changed user-visible behavior —
  see the documentation guidelines in [Agents.md](Agents.md).

A maintainer will review for correctness, test coverage, and the conventions
above. Expect follow-up questions on anything that reads as a workaround
rather than a fix — this codebase would rather you ask than guess.
