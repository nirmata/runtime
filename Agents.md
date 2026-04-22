# Instructions for coding agents

Read the [DESIGN](docs/dev/DESIGN.md) and [PLAN](./docs/dev/PLAN.md) before making any significant change.

## Dev Documents

Store all developer docs in the "docs/dev" folder.

## Code generation and changes

Follow these rules when generating and updating code:

- always run "make build" and "make test" after code changes. Fix any reeported issues.
- for runtime pipeline, collector, evaluator, or reporter changes, also run
	"make smoke-quickstart" before finishing.
- when creating a PR, sign commits using "git commit -s...".

## Runtime event filtering policy

- connect/tcpconnect events without k8s namespace+pod metadata must be treated
	as node/system noise and filtered out of pod-specific reporting.
- open/exec events may be retained even when metadata is sparse to preserve
	valid workload detections.

Keep this behavior aligned with docs/dev/DESIGN.md when making datasource or
collection-path changes.

## Markdown generation and changes

- Fix all markdownlint issues
