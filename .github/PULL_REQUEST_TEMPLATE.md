# Pull request

## What this changes and why

<!-- The behavior before and after, and the reason for the change. Not a
     restatement of the diff. -->

## How it was validated

- [ ] `make build` and `make test` pass
- [ ] For a change to the managers, collector, evaluator, or reporter: validated on
      a kind cluster (`make kind-install`, plus a targeted check such as
      `make smoke-quickstart`, `make test-e2e-egress`, or `make test-e2e-protocol`)
- [ ] For a change touching `pkg/bpf/lsm`, `pkg/lsmmgr`, or `open`/`exec` behavior:
      ran `make test-e2e-lsm` (or `make test-e2e`) on a host with BPF-LSM active
      (Docker Desktop or a `lsm=...,bpf` Linux VM) — CI cannot exercise this, see
      [CONTRIBUTING.md](../CONTRIBUTING.md#the-lsm-e2e-lane-has-no-pr-signal)
- [ ] `make lint-docs` passes, for any markdown change

## Generated artifacts

- [ ] `make verify-crds` passes, or this PR does not touch `api/v1alpha1`
- [ ] `make verify-bpf` passes, or this PR does not touch `pkg/bpf/*/_cprog`
- [ ] A new BPF program has an entry in `test/e2e/bpfverify_test.go`, or this PR
      does not add one

## Documentation

- [ ] `docs/dev/DESIGN.md` updated, or this PR does not change the architecture
- [ ] The relevant `docs/users/` page updated, or this PR does not change
      user-visible behavior

## Commits

- [ ] Every commit is signed off (`git commit -s`), per [CONTRIBUTING.md](../CONTRIBUTING.md#sign-your-commits-dco)
