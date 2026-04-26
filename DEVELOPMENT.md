# Kyverno Runtime Development Guide

This guide provides everything you need to build, test, and contribute to kyverno-runtime.

## Prerequisites

- **Go 1.21+** - [Install Go](https://golang.org/doc/install)
- **Docker** - For building container images
- **kind** - Kubernetes in Docker for local testing (`go install sigs.k8s.io/kind@latest`)
- **kubectl** - Kubernetes CLI (`go install k8s.io/client-go/tools/clientcmd@latest`)
- **Chainsaw** - E2E test framework (`go install github.com/kyverno/chainsaw@latest`)
- **golangci-lint** - Linter (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`)
- **ko** - Container image builder (`go install github.com/google/ko@latest`)
- **Helm 3+** - Package manager for Kubernetes

## Quick Start

### 1. Clone and Set Up

```bash
git clone https://github.com/nirmata/kyverno-runtime.git
cd kyverno-runtime
go mod download
```

### 2. Build Locally

```bash
make build          # Format + lint + build Go binary
make ko-build       # Build container image locally (requires Docker)
```

### 3. Test

```bash
make test           # Unit tests only
make test-e2e       # Full E2E test suite (requires kind cluster)
```

### 4. Deploy to Local kind Cluster

```bash
make kind               # Create a new kind cluster
make kind-install       # Build, load image, and deploy to existing cluster
make smoke-quickstart   # Run smoke validation tests
```

## Build Targets

| Target | Purpose |
| --- | --- |
| `make build` | Format code, run linter, build binary |
| `make fmt` | Format Go code with gofmt |
| `make lint` | Run golangci-lint on all code |
| `make lint-docs` | Check markdown files with markdownlint |
| `make run` | Run binary locally (requires Inspektor Gadget) |
| `make ko-build` | Build container image with ko (local Docker) |
| `make ko-push` | Build and push multi-arch image to registry |
| `make kind` | Create a new kind cluster and install kyverno-runtime |
| `make kind-install` | Build and install kyverno-runtime to existing cluster |
| `make test` | Run unit tests |
| `make test-e2e` | Run all E2E Chainsaw tests |
| `make test-e2e-quickstart` | Run quickstart E2E tests only |
| `make smoke-quickstart` | Run smoke validation (equivalent to test-e2e-quickstart) |
| `make premerge-smoke` | Full pre-merge validation (build + install + smoke test) |
| `make test-e2e-install` | Full CI pipeline (kind-install + test-e2e) |

## Development Workflow

### Making Code Changes

1. **Create a feature branch:**

   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make your changes** in `pkg/` and/or `cmd/` directories.

3. **Validate locally:**

   ```bash
   make build        # Verify compilation and linting
   make test         # Run unit tests
   ```

4. **Test on a kind cluster:**

   ```bash
   make kind-install       # Deploy to cluster
   make smoke-quickstart   # Run quick validation
   ```

5. **For pipeline/collector/evaluator/reporter changes**, also run:

   ```bash
   make test-e2e     # Full E2E suite
   ```

6. **Sign and commit:**

   ```bash
   git commit -s -m "Description of changes"
   ```

7. **Push and create a pull request:**

   ```bash
   git push origin feature/my-feature
   ```

### Making Documentation Changes

1. Update markdown files in `docs/` or root directory.
2. Run linter:

   ```bash
   make lint-docs
   ```

3. Fix any reported issues (table formatting, bare URLs, code block languages).
4. Commit and push.

**Note:** Doc changes do not require `make build` or `make test`.

## Testing Guide

### Unit Tests

Run all unit tests:

```bash
make test
```

Run specific test file:

```bash
go test ./pkg/policy -v
```

Run specific test:

```bash
go test ./pkg/policy -run TestEvaluateRuntimePolicy -v
```

### E2E Tests

E2E tests use [Chainsaw](https://kyverno.github.io/chainsaw/) YAML framework.

**Prerequisites:**

- kind cluster with kyverno-runtime installed
- Required CRDs (RuntimePolicy, RuntimeBehavior, Report)

**Run all E2E tests:**

```bash
make test-e2e
```

**Run specific test directory:**

```bash
chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/quickstart/
```

**Test scenarios available:**

- `test/e2e/quickstart/` - README flow and sample policies
- `test/e2e/trace-open/` - File open event detection
- `test/e2e/trace-exec/` - Exec event detection
- `test/e2e/multiple-policies/` - Multiple policies on single pod
- `test/e2e/runtimebehavior-samples/` - RuntimeBehavior baseline detection
- `test/e2e/runtimebehavior-auto-enrollment/` - Auto-enrollment workflows
- `test/e2e/runtimepolicy-cluster-scope/` - Cluster-scoped policies

**Debugging failed tests:**

```bash
# Keep test resources for inspection
chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/quickstart/ --skip-delete

# Check controller logs
kubectl -n kyverno-runtime logs -f -l app.kubernetes.io/name=kyverno-runtime

# Inspect reports
kubectl get reports -A
kubectl get reports -n <namespace> -o yaml
```

## GitHub Actions Workflows

The repository uses four workflows under `.github/workflows/`.

### CI (`ci.yml`)

- Triggers on pushes to `main` and pull requests targeting `main`
- Runs formatting checks (`gofmt -l .`)
- Runs Go lint (`golangci-lint`) and markdown lint (`markdownlint-cli2`)
- Builds the controller binary and runs unit tests (`go test ./...`)

### E2E (`e2e.yml`)

- Triggers on manual runs (`workflow_dispatch`) with input `suite=quickstart|full`
- Creates a kind cluster and installs required tooling (`kubectl`, `helm`, `ko`, `chainsaw`)
- Runs:
  - `make kind-install smoke-quickstart` for manual `quickstart`
   - `make test-e2e-install` for manual `full`
- On failures, dumps pods/reports/controller logs for easier debugging

### Release (`release.yml`)

- Triggers on tag pushes (`v*`)
- Builds and pushes a temporary candidate image tag to `ghcr.io/nirmata/kyverno-runtime`
- Runs release E2E against that candidate image
- Promotes the candidate image to release tag and `latest` only after E2E passes
- Publishes Helm chart by deriving chart version from tag (for example, `v0.2.0` -> `0.2.0`)
- Updates `charts/kyverno-runtime/Chart.yaml` `version` and `appVersion` from tag
- Runs `helm lint` and `helm package` for chart validation and packaging
- Pushes the packaged chart to OCI registry: `oci://ghcr.io/nirmata/kyverno-runtime`
- Runs `helm/chart-releaser-action` to publish release artifacts and update chart index

### GHCR Candidate Cleanup (`ghcr-candidate-cleanup.yml`)

- Triggers on weekly schedule and manual dispatch
- Deletes older `candidate-*` container versions from GHCR
- Keeps a configurable number of newest candidate versions
- Supports `dry_run` mode for safe preview before deletion

**One-time setup note:** If you want classic Helm repository index publishing via GitHub Pages, ensure `gh-pages` is configured in repository Settings -> Pages.

## Project Structure

```text
kyverno-runtime/
├── cmd/kyverno-runtime/        # Main binary entry point
├── pkg/
│   ├── controller/             # Pod reconciliation logic
│   ├── datasource/             # Inspektor Gadget integration
│   ├── pipeline/               # Event processing pipeline
│   │   ├── matcher.go          # Policy matching
│   │   ├── collector.go        # Event collection
│   │   ├── evaluator.go        # Policy evaluation (CEL)
│   │   └── reporter.go         # Report generation
│   ├── policy/                 # Policy evaluation engines
│   │   ├── evaluator.go        # RuntimePolicy evaluator
│   │   └── anomaly_detector.go # RuntimeBehavior anomaly detection
│   └── runtimeevents/          # Event type definitions
├── api/v1alpha1/               # CRD type definitions
├── config/                     # K8s manifests (RBAC, deployment)
├── charts/                     # Helm chart
├── docs/
│   ├── dev/                    # Developer documentation
│   │   ├── DESIGN.md           # Architecture and design decisions
│   │   └── PLAN.md             # Development plan
│   └── users/                  # User documentation
├── test/e2e/                   # Chainsaw E2E tests
├── samples/                    # User-facing policy examples
└── Makefile                    # Build and test orchestration
```

## Key Modules

### Controller (`pkg/controller/`)

- Watches Pod resources
- Reconciles pods through the runtime policy pipeline
- Manages DaemonSet deployment

### Pipeline (`pkg/pipeline/`)

**Four modular components process each pod:**

1. **Matcher** - Determines which policies apply to a pod
2. **Collector** - Gathers runtime events using Inspektor Gadget
3. **Evaluator** - Evaluates CEL expressions in policy conditions
4. **Reporter** - Creates/updates Report resources with findings

### Policy (`pkg/policy/`)

- **RuntimePolicy evaluator** - Signature-based detection (CEL expressions)
- **RuntimeBehavior evaluator** - Anomaly detection from baselines

### Datasource (`pkg/datasource/`)

- Inspektor Gadget integration
- Event collection with configurable timeout/window
- Metadata filtering for noise reduction

## Code Conventions

### Naming

- Files and packages use `snake_case`
- Exported types/functions use `PascalCase`
- Interface names end with `-er` (e.g., `Matcher`, `Collector`)

### Testing

- Unit tests in same package as code: `*_test.go`
- Integration tests in `test/e2e/` using Chainsaw
- Mock implementations for interfaces: `mock_*.go`

### Error Handling

- Use wrapped errors: `fmt.Errorf("context: %w", err)`
- Log errors with context before returning
- Don't swallow non-recoverable errors

### Documentation

- Exported functions/types have comments describing purpose
- Complex logic includes comments explaining why, not just what
- See [DESIGN.md](docs/dev/DESIGN.md) for architecture details

## Important Behaviors

### Runtime Event Filtering

The controller applies semantic filtering to avoid noise while preserving valid detections:

| Event Type | Missing k8s Metadata | Behavior |
| --- | --- | --- |
| `connect`, `tcpconnect` | namespace/pod metadata | **Filtered out** (node/system noise) |
| `open`, `exec` | sparse metadata | **Retained** (valid workload events) |

This filtering is configured in the datasource and should be maintained during collection-path changes.

### Default Deployment Configuration

- **Leader election:** Enabled by default
- **Active instance:** Single controller instance reconciles cluster
- **Event collection:** From the node running the active controller
- **Pod filtering:** No per-node filtering (cluster-wide reconciliation)

## Common Development Tasks

### Add a New Policy Check

1. Add validation rule to `RuntimePolicy` spec
2. Implement CEL expression matching in evaluator
3. Add E2E test case in `test/e2e/`
4. Update sample policy in `samples/`

### Modify Event Collection

1. Update datasource event types in `pkg/datasource/event_types.go`
2. Update Inspektor Gadget invocation in `pkg/datasource/inspektor_gadget_source.go`
3. Run `make smoke-quickstart` to validate
4. Update [DESIGN.md](docs/dev/DESIGN.md) if filtering semantics change

### Add a New CRD

1. Define types in `api/v1alpha1/`
2. Generate manifests: `make generate-manifests`
3. Add reconciliation logic to controller
4. Create E2E test for new functionality
5. Document changes in [DESIGN.md](docs/dev/DESIGN.md)

### Create an E2E Test

1. Create directory under `test/e2e/` (for example, `test/e2e/my-scenario/`)
2. Add `chainsaw-test.yaml` with test steps
3. Add `README.md` describing the test
4. Reference sample YAML files from `samples/` where possible
5. Run `chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/my-scenario/`

## Pre-Merge Checklist

Before submitting a pull request:

- [ ] Code compiles: `make build`
- [ ] Unit tests pass: `make test`
- [ ] Linting passes: `make lint`
- [ ] Markdown passes: `make lint-docs` (doc changes)
- [ ] Commits are signed: `git commit -s`
- [ ] For code changes: tested on kind cluster (`make kind-install` + `make smoke-quickstart`)
- [ ] For pipeline/collector/evaluator/reporter changes: full `make test-e2e` passes
- [ ] PR description references related issues
- [ ] [DESIGN.md](docs/dev/DESIGN.md) updated if architecture changed

## Troubleshooting

### Build Issues

**golangci-lint failures:**

```bash
# Fix with auto-formatter
golangci-lint run ./... --fix
# Or run individual checks
golangci-lint run ./... --disable-all -E vet
```

**Docker/image build fails:**

```bash
# Rebuild without cache
docker system prune -a
make ko-build
```

### Test Issues

**E2E tests fail with "image pull backoff":**

```bash
# Image wasn't loaded into kind cluster
make kind-load-image
kubectl -n kyverno-runtime rollout restart daemonset/kyverno-runtime-kyverno-runtime
```

**Tests timeout:**

```bash
# Increase Chainsaw timeout in test/e2e/.chainsaw.yaml
# or check if controller is healthy
kubectl -n kyverno-runtime logs -f -l app.kubernetes.io/name=kyverno-runtime
```

**Stale test resources:**

```bash
# Delete namespaces to clean up
kubectl delete ns e2e-quickstart e2e-multi-policy
# Or delete specific resources
kubectl delete runtimepolicy --all
kubectl delete runtimebehavior --all
```

## Design and Planning Documents

### Purpose and Maintenance

This project maintains clear separation between **current implementation** and **planned work**:

- **[DESIGN.md](docs/dev/DESIGN.md)** - Describes the *current* architecture and implementation
  - Updated when the architecture changes or when completing major features from PLAN.md
  - Should accurately reflect the deployed system (what you see in `main` branch)
  - Includes design decisions, component responsibilities, and integration patterns
  - Add new sections here to document completed features from PLAN.md

- **[PLAN.md](docs/dev/PLAN.md)** - Roadmap for *future* work and enhancements
  - Describes planned features, phases, and requirements
  - Tracks implementation status for each phase (PROPOSED, IN PROGRESS, COMPLETED, etc.)
  - Remove completed items and move their documentation to DESIGN.md
  - Keep only truly planned or in-progress items

### Guidelines for Contributing

**When implementing a feature from PLAN.md:**

1. Make your code changes and get them merged to `main`
2. Update [PLAN.md](docs/dev/PLAN.md): Change status to **COMPLETED** ✅ or move to a completed section
3. Update [DESIGN.md](docs/dev/DESIGN.md): Add or expand sections documenting the new feature
4. Update this file ([DEVELOPMENT.md](DEVELOPMENT.md)): Add any new build targets, workflows, or gotchas
5. Update [README.md](../../README.md): Update examples or next-steps if user-facing

**When modifying the architecture:**

1. Update [DESIGN.md](docs/dev/DESIGN.md) first (before code changes when possible)
2. Update [Agents.md](../../Agents.md) if the change affects coding guidelines or runtime behavior
3. Update diagrams and examples to reflect the new design
4. Add a note in [PLAN.md](docs/dev/PLAN.md) if this affects planned items

**When writing significant documentation changes:**

1. Run `make lint-docs` to check markdown style (no extra work needed — it's automated in CI)
2. Keep tables compact: `| --- | --- |` for linting compliance
3. Add language to all fenced code blocks (e.g., `bash`, `yaml`, `go`)
4. Use markdown links instead of bare URLs
5. Check for duplicate headings in the file

### Before Making Significant Changes

Read these documents in this order:

1. [DESIGN.md](docs/dev/DESIGN.md) - Understand the current architecture
2. [PLAN.md](docs/dev/PLAN.md) - See what's planned or in-flight
3. [Agents.md](../../Agents.md) - Review development guidelines and runtime policies

## Getting Help

- Check existing issues: [GitHub Issues](https://github.com/nirmata/kyverno-runtime/issues)
- Review [DESIGN.md](docs/dev/DESIGN.md) for architectural context
- Look at existing tests and samples for patterns
- Check [test/e2e/README.md](test/e2e/README.md) for scenario descriptions

## Performance Considerations

- **Event collection timeout:** Default 5s (configurable)
- **Reconciliation window:** Depends on pod churn and policy complexity
- **Report deduplication:** Fingerprint-based (prevents duplicate findings)
- **Max report results:** Default 1000 per policy per pod

Adjust these via controller environment variables or Helm values.

## Security Notes

- **RBAC:** See [config/rbac/](config/rbac/) for required permissions
- **Webhook:** Not required (detection only, no blocking at this layer)
- **Event collection:** Runs on node-local Inspektor Gadget (no external calls)
- **Reports:** Written to pod namespace (respects namespace isolation)

## License

Kyverno Runtime is released under the Apache 2.0 License. When contributing, your changes must be compatible with this license.
