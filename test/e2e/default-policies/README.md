# Default RuntimePolicy Library E2E Tests

This directory contains end-to-end tests for the default RuntimePolicy library.

## Test Structure

### Installation Verification (`default-policies-installation`)

Verifies that all 7 default policies are installed in the cluster when `defaultPolicies.enabled=true`.

**Assertions:**

- `detect-credential-access` policy exists
- `detect-shell-execution` policy exists
- `detect-sensitive-file-access` policy exists
- `detect-public-network-egress` policy exists
- `detect-process-discovery` policy exists
- `detect-security-tool-disruption` policy exists
- `detect-suspicious-dns` policy exists

### Credential Access Detection Test (`credential-access-detection`)

Tests detection of credential file access attempts.

**Test workload:**

```bash
sh -c "cat /etc/passwd && cat /etc/shadow 2>/dev/null; sleep 1"
```

**Expected result:**

- PolicyReport is generated
- At least one finding for credential access
- Severity: CRITICAL or HIGH

**Evidence:**

- File paths: `/etc/passwd`, `/etc/shadow`
- Event type: `open`

---

### Shell Execution Detection Test (`shell-execution-detection`)

Tests detection of shell spawning.

**Test workload:**

```bash
/bin/sh -c "echo 'shell execution test' && sleep 1"
```

**Expected result:**

- PolicyReport is generated
- At least one finding for shell execution
- Severity: HIGH

**Evidence:**

- Process name: `/bin/sh`
- Event type: `exec`

---

### Sensitive File Access Detection Test (`sensitive-file-access-detection`)

Tests detection of access to system configuration files.

**Test workload:**

```bash
sh -c "cat /etc/hosts >/dev/null && cat /etc/hostname >/dev/null; sleep 1"
```

**Expected result:**

- PolicyReport is generated
- At least one finding for sensitive file access
- Severity: MEDIUM

**Evidence:**

- File paths: `/etc/hosts`, `/etc/hostname`
- Event type: `open`

---

### Process Discovery Detection Test (`process-discovery-detection`)

Tests detection of process enumeration via `/proc` filesystem.

**Test workload:**

```bash
sh -c "cat /proc/1/status >/dev/null 2>&1 || echo 'proc access attempted'; sleep 1"
```

**Expected result:**

- PolicyReport may be generated (depends on eBPF permissions)
- If present, findings indicate process discovery
- Severity: LOW

**Evidence:**

- File path: `/proc/*/status`
- Event type: `open`

---

### Security Tool Disruption Detection Test (`security-tool-disruption-detection`)

Tests detection of security tool execution.

**Test workload:**

```bash
sh -c "which iptables >/dev/null 2>&1 || echo 'iptables not found'; sleep 1"
```

**Expected result:**

- PolicyReport may be generated (depends on tool availability)
- If present, findings indicate security tool access
- Severity: HIGH

**Evidence:**

- Process names: `iptables`, `ufw`, `auditctl`, and similar tools
- Event type: `exec`

---

## Running the Tests

### Run all default policy tests

```bash
chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/default-policies/
```

### Run a specific test

```bash
chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/default-policies/ -l credential-access-detection
```

### Use make target

```bash
make test-e2e-install
```

---

## Test Prerequisites

1. **Cluster with kyverno-runtime installed**

   ```bash
   make kind-install
   ```

2. **Default policies enabled in Helm values**

   ```bash
   helm upgrade --install kyverno-runtime ./charts/kyverno-runtime \
     --set defaultPolicies.enabled=true
   ```

3. **Chainsaw test runner installed**

   ```bash
   go install github.com/kyverno/chainsaw@latest
   ```

---

## Troubleshooting

### PolicyReport not generated

- Check kyverno-runtime pod status: `kubectl get pods -n kyverno-runtime`
- Verify signature engine config: `kubectl get cm -n kyverno-runtime kyverno-runtime-config`
- Check controller logs: `kubectl logs -n kyverno-runtime -l app.kubernetes.io/name=kyverno-runtime`

### Tests timing out

- Increase timeout values in the test spec
- Check cluster readiness: `kubectl get nodes`
- Verify Inspektor Gadget is working: `kubectl logs -n kyverno-runtime --tail=50`

### Missing runtime findings

- Ensure pods have sufficient privileges for eBPF tracing
- Check supported event types (`exec`, `open`, `tcpconnect`, `dns`)
- Verify signature engine rules are enabled in config

---

## Expected Test Results Summary

| Test | Policy | Event Type | Severity | Pass Criteria |
| --- | --- | --- | --- | --- |
| Installation | All 7 policies | N/A | N/A | All policies exist |
| Credential Access | detect-credential-access | open | CRITICAL | >=1 finding |
| Shell Execution | detect-shell-execution | exec | HIGH | >=1 finding |
| Sensitive Files | detect-sensitive-file-access | open | MEDIUM | >=1 finding |
| Process Discovery | detect-process-discovery | open | LOW | Report exists |
| Security Tools | detect-security-tool-disruption | exec | HIGH | Report exists |
| Suspicious DNS | detect-suspicious-dns | dns | WARNING | Report may exist |

---

## Integration with CI/CD

The default policies E2E tests are run as part of the standard suite:

```bash
make test-e2e-install
```

Tests use Chainsaw framework configuration in `test/e2e/.chainsaw.yaml` with:

- 30s apply timeout
- 120s assertion timeout
- 90s cleanup timeout

---

## Future Enhancements

- [ ] Add public network egress test with actual network connection
- [ ] Add suspicious DNS test with actual DNS resolution
- [ ] Add correlation tests for multi-policy scenarios
- [ ] Add performance and scale tests for large workloads
- [ ] Add failure recovery tests
