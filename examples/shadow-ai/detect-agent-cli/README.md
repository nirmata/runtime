# Detect agent CLIs and self-hosted inference servers

## What this shows

Two kinds of AI workload start as an `execve` and never announce themselves any other way.

A **coding agent CLI** — `claude`, `codex`, `gemini`, `aider`, `goose` — reached for inside a
build pod or a debug container is a new path from that pod to a model provider, to the
filesystem, and to whatever tools the agent decides to run. Nothing in the image contract said
it would be there.

A **self-hosted inference server** — `ollama serve`, `vllm`, `sglang`, `llama.cpp` — is the
truer shadow AI, because nobody registered it anywhere. It has no provider hostname to
resolve and no vendor endpoint to block. It serves on a port inside the cluster, and this
runtime has no port dimension in any policy value, so the launch is the signal.

The binary is not the signal in either case. `npx -y @anthropic-ai/claude-code` execs node,
`uvx aider-chat` execs a Python launcher, and `python -m vllm.entrypoints.openai.api_server`
execs python. Matching the binary catches every use of node. Matching the name it was invoked
under, or the package a launcher was asked to fetch, catches the agent.

So `policy.yaml` observes exec broadly and narrows the *findings* with a
[monitorFilter](../../../docs/users/reference/runtimepolicy.md#filtering-monitor-findings).

The first expression is a guard. `event.exec` exists only on an exec observation, so without
`has(event.exec)` the second expression would be evaluated against this pod's file and
network observations too. Expressions are ANDed and short-circuit on the first false, which
is what makes the guard work.

The `vllm.` and `sglang.` prefixes cover the `python -m <module>` form, where the whole
dotted module path is one argument.

## Requires

Process `exec` observation requires a kernel booted with BPF-LSM active: `bpf` must appear in
`/sys/kernel/security/lsm` (set with the `lsm=` kernel boot parameter). Stock distributions
and hosted CI runners are typically not booted with it; Docker Desktop's LinuxKit VM is, so a
kind cluster on macOS runs this example.

```bash
kubectl debug node/<node> -it --image=busybox:1.36 -- cat /host/sys/kernel/security/lsm
```

Read it from the node, not from the daemon pod: that image is distroless and has neither a
shell nor `cat`.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md). The
policy runs in `mode: monitor`, so nothing is ever blocked.

## Run it

1. Start the workload. It writes launcher stubs and then idles:

   ```bash
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/ai-workload
   ```

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol detect-agent-cli
   ```

   `Applied=True` with reason `Monitoring`.

3. Launch one agent CLI, one inference server, and one ordinary tool:

   ```bash
   kubectl exec ai-workload -- npx -y @anthropic-ai/claude-code &
   kubectl exec ai-workload -- ollama serve &
   kubectl exec ai-workload -- python3 -m vllm.entrypoints.openai.api_server &
   kubectl exec ai-workload -- npx -y prettier --write .
   ```

## Verify

Both directions matter. A check that only asserts the agents were reported would also pass
against a policy that reports every exec — which is exactly what this policy would do without
its filter.

Exec observations arrive on a ring buffer as they happen, but findings are flushed every 10
seconds, so allow about that long.

```bash
kubectl get report kyverno-runtime-ai-workload -o yaml
```

- Three results, each naming what was launched in its `argv` property:

  ```yaml
  - source: kyverno-runtime
    policy: detect-agent-cli
    rule: exec
    result: fail
    description: 'monitor mode: exec of /usr/local/bin/npx would have been denied by policy detect-agent-cli'
    properties:
      behavior: exec
      target: /usr/local/bin/npx
      argv: npx -y @anthropic-ai/claude-code
      comm: npx
      enforced: "false"
  ```

- **No result for `prettier`**, and none for the shell, `chmod`, or anything else the pod ran.
  That absence is the filter working.

Two details worth knowing when reading the report. `target` distinguishes one finding from
another, so two different launchers produce two results rather than merging into one. And each
exec is observed twice, once on the ring buffer with argv and once through the counters
without it; the counter copy has an empty `argv`, so `argv.exists(...)` is false and the
filter drops it. You see one result per launch, not two.

## What this does not cover

- **An argument past the eighth.** The kernel record is `char argv[8][128]`, so a launcher
  whose package name sits after eight earlier arguments is not matched, and an argument longer
  than 127 bytes is truncated. Put the recognizable token early, or fall back to the
  allow-list form below.
- **A renamed or wrapped binary.** This is a denylist of names, and copying `ollama` to
  `/tmp/helper` defeats it while the `execve` is still observed.
- **A model reached from library code.** An agent embedded in an application process never
  execs anything; [detect-ai-sdks](../detect-ai-sdks/) covers that case from the file side.

## Tightening it

When a workload's legitimate binaries are known, an allow list blocks the whole class rather
than enumerating it:

```yaml
spec:
  mode: enforce
  behaviors:
  - exec:
      deny:
        values:
        - "*"
      allow:
        values:
        - "/bin/sh"
```

That is enforcement, so it carries no `monitorFilter` — an `enforce` policy is refused with
one, because an enforce finding records that the kernel actually blocked something and is
never suppressed. See [restrict-exec-allowlist](../../files-and-processes/restrict-exec-allowlist/) for the
allow-list form on its own.

## Clean up

```bash
kubectl delete rpol detect-agent-cli
kubectl delete -f client.yaml
```
