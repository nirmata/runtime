# Detect reads of MCP configuration files

## What this shows

An MCP configuration file lists the servers a tool will connect to and, often, the
credentials it will connect with. A process in a workload reading one is worth knowing
about, and detecting it needs nothing new: the `open` behavior in `mode: monitor` already
reports every file open a policy names.

No DNS is involved, and no new field is involved. The whole detection is a `deny` list of
absolute paths on the behavior that has existed since the first release, run in the mode
that reports instead of blocking.

Each value is a whole path or a directory. There is no `~` expansion and no wildcard for the
home directory or the file name, and a directory rule such as `/root/.cursor/*` would report
every file below it, not just the MCP config. So every (home directory, config file) pair is
its own literal entry. That enumeration is the whole cost of the approach, and it is visible
in `policy.yaml` rather than hidden behind a pattern that would silently match less than it
looks like it matches.

Some paths have no literal to list — a project-scoped `.mcp.json` sits wherever the repository
was checked out. Those are reached the other way round, with a broad `deny` and a
`monitorFilter` that decides which findings are worth reporting: see
[Paths that cannot be enumerated](#paths-that-cannot-be-enumerated).

## Requires

File `open` observation needs BTF at
`/sys/kernel/btf/vmlinux`, plus either BPF-LSM active (`bpf` in `/sys/kernel/security/lsm`) or, for the `fmod_ret` fallback, kernel 5.7 or later with the
BPF JIT on x86-64 or arm64. Docker Desktop's LinuxKit VM has BPF-LSM active, so a kind
cluster on macOS runs this example. See [platform support](../../../docs/users/platforms.md).

```bash
kubectl debug node/<node> -it --image=busybox:1.36 -- sh -c 'cat /host/sys/kernel/security/lsm; uname -rm'
```

`bpf` in the first line means the LSM hooks; otherwise the second line must show kernel 5.7
or later on `x86_64` or `aarch64`.

Read it from the node, not from the agent pod: that image is distroless and has neither a
shell nor `cat`.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: monitor`, so nothing is ever blocked.

## Run it

1. Start the client. It writes an MCP config and an unrelated dotfile, both under `/root`:

   ```bash
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/mcp-client
   ```

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol detect-mcp-config-access
   ```

   `Applied=True` with reason `Monitoring`.

3. Read both files:

   ```bash
   kubectl exec mcp-client -- cat /root/.cursor/mcp.json; echo "exit=$?"
   kubectl exec mcp-client -- cat /root/.gitconfig; echo "exit=$?"
   ```

## Verify

Both directions matter. A check that only asserts the MCP config was reported would also
pass against a policy that reports every open.

Observation is poll-based for `open`: counters are drained every `--observe-interval` (10s
by default) and findings are flushed every 10s, so allow up to about 20 seconds.

- `exit=0` on both. Monitor mode never blocks; the reads succeeded.
- One result names the MCP config, and none names `/root/.gitconfig`:

  ```bash
  kubectl get report kyverno-runtime-mcp-client -o yaml
  ```

  ```yaml
  - source: kyverno-runtime
    policy: detect-mcp-config-access
    rule: open
    category: Runtime Security
    result: fail
    scored: true
    description: 'monitor mode: open of /root/.cursor/mcp.json would have been denied by policy detect-mcp-config-access'
    subjects:
    - apiVersion: v1
      kind: Pod
      name: mcp-client
      namespace: default
    properties:
      behavior: open
      comm: cat
      container: client
      count: "1"
      enforced: "false"
      node: kind-worker
      serviceAccount: default
  ```

  `enforced: "false"` is what makes this a counterfactual: an enforcing form of the same
  policy would have returned `-EPERM` to that `cat`, and this one did not.

## Paths that cannot be enumerated

`policy.yaml` names every path it reports, which works exactly as far as the paths are
predictable. Two MCP targets are not:

- a project-scoped `.mcp.json`, whose absolute path depends on where the repository was
  checked out;
- the OAuth refresh-token cache under `~/.mcp-auth/`, whose filenames are hashes.

For those, invert the policy: deny everything, and narrow the *findings* with a
[monitorFilter](../../../docs/users/reference/runtimepolicy.md#filtering-monitor-findings) — a CEL
predicate evaluated against each observation, which does have prefix, suffix, substring, and
regex matching. The alternatives here are a disjunction, so they belong in one expression:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: report-mcp-config-or-credential-read
spec:
  mode: monitor
  podSelector:
    matchLabels:
      app: mcp-client
  behaviors:
  - open:
      deny:
        values: ["*"]
  monitorFilter:
    expressions:
    - name: mcp-config-or-credential-read
      expression: >-
        has(event.open) && (
          event.open.path.contains("/.mcp-auth/") ||
          event.open.path.endsWith("/.mcp.json") ||
          [
            "/mcp.json", "/mcp_config.json",
            "/claude_desktop_config.json", "/.claude.json",
          ].exists(f, event.open.path.endsWith(f))
        )
```

Two things this does not change. The filter narrows findings, not observation: the kernel still
records every path the pod opens, and the per-cgroup map is under the same pressure a bare
`deny: ["*"]` would put it under. And it is monitor-only — an `enforce` policy carrying a
`monitorFilter` is refused at admission, because an enforce finding is the record that
something was actually blocked and is never suppressed.

## Turning it into enforcement

The same `policy.yaml` with `mode: enforce` blocks the reads instead of reporting them, in
the kernel's file-open hook, for every process in the pod including a `kubectl exec` shell.
Switching modes rebuilds the attachment, so an observing program never inherits deny
entries. Run the reads again after switching and the `cat` fails with
`Permission denied`.

## Clean up

```bash
kubectl delete rpol detect-mcp-config-access
kubectl delete -f client.yaml
```
