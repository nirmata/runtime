# Instructions for coding agents

Read the [DESIGN](docs/dev/DESIGN.md) and [PLAN](./docs/dev/PLAN.md) before making any significant change.

## Documentation Guidelines

### Purpose of Key Documents

**[DESIGN.md](docs/dev/DESIGN.md)** describes the *current* architecture and implementation:

- Component responsibilities and interfaces
- How policies are matched, collected, evaluated, and reported
- Design decisions and rationale
- Integration patterns and workflows
- **Keep this synchronized with the actual codebase** (what's deployed on `main`)

**[PLAN.md](docs/dev/PLAN.md)** describes *planned* work and future enhancements:

- Development roadmap organized by phase
- Deliverables, status, and acceptance criteria for each phase
- Known issues and design open questions
- **Remove completed items** from PLAN.md and move their documentation to DESIGN.md

### When Completing a Feature

1. Ensure code changes are merged to `main` with tests passing
2. Update [PLAN.md](docs/dev/PLAN.md):
   - Change status to **COMPLETED** ✅ for the phase/item
   - Or remove the item if entire phase is done
3. Update [DESIGN.md](docs/dev/DESIGN.md):
   - Add new sections or expand existing ones to document the feature
   - Include code examples, configuration, and operational guidance
   - Update diagrams if architecture changed
4. Verify [DEVELOPMENT.md](DEVELOPMENT.md) is current:
   - Add new build targets or workflows if needed
   - Update common development tasks section
   - Document any new operational behaviors

### When Modifying Architecture

1. Update [DESIGN.md](docs/dev/DESIGN.md) first to describe the new design
2. Update this file ([Agents.md](Agents.md)) if runtime policies or development guidelines change
3. Update [DEVELOPMENT.md](DEVELOPMENT.md) for new workflows or behaviors
4. Review [PLAN.md](docs/dev/PLAN.md) for any affected planned items

## Dev Documents

Store all developer docs in the "docs/dev" folder.

## Code generation and changes

Follow these rules when generating and updating code:

- always run "make build" and "make test" after **code** changes (skip for doc changes). Fix any reported issues.
- after any significant code change, always validate on a kind cluster before finishing (at minimum: `make kind-install` and a targeted behavioral check such as `make smoke-quickstart` when relevant).
- for runtime pipeline, collector, evaluator, or reporter changes, also run "make smoke-quickstart" before finishing.
- when creating a PR, sign commits using "git commit -s...".

## Runtime event filtering policy

- connect/tcpconnect events without k8s namespace+pod metadata must be treated as node/system noise and filtered out of pod-specific reporting.
- open/exec events may be retained even when metadata is sparse to preserve valid workload detections.

Keep this behavior aligned with docs/dev/DESIGN.md when making datasource or
collection-path changes.

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
