# Quickstart E2E Tests

This directory contains two complementary Chainsaw E2E tests for validating quickstart scenarios:

## 1. README Quickstart Flow (`quickstart-trace-open`)

Validates the documented quickstart path from the README:

- Creates a namespace with `runtime-monitor=enabled` label
- Applies a simple inline RuntimePolicy for file open events
- Creates a pod that reads `/etc/hosts` repeatedly
- Verifies PolicyReport is generated with findings

This test is minimal and focused on demonstrating the core detection flow.

## 2. Sample Policies Verification (`quickstart-samples-verification`)

Validates that the documented sample policies work correctly together:

- Applies `runtimepolicy-file-open-detection.yaml` and `runtimepolicy-network-egress-check.yaml`
- Creates a pod that triggers both file open and network events
- Verifies PolicyReports are generated for both policy types

This test demonstrates the full production workflow with real sample configurations.

## Running the tests

```bash
make test-e2e  # Runs all E2E tests including both quickstart tests
# or
chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/quickstart/
```
