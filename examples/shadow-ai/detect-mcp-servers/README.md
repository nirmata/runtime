# Detect stdio MCP servers a workload launches

## What this shows

An MCP server using the stdio transport is a child process. Its client writes JSON-RPC to
that process's stdin and reads the replies from stdout, so nothing crosses a socket and
nothing appears in DNS, in a proxy log, or in a firewall. A workload can pick up a new tool,
and with it a new path to the filesystem or to a remote API, without producing a single
packet that says so.

What it does produce is an `execve`. This example reports every stdio MCP server a workload
launches, identified by the package it was asked to run.

The binary is not the signal. `npx -y @modelcontextprotocol/server-filesystem /data` execs
node; `uvx mcp-server-git` execs a Python launcher; `docker run mcp/sqlite` execs docker.
Matching the binary catches every use of node, and matching the package catches the MCP
server. So `policy.yaml` observes exec broadly and narrows the *findings* with a
[monitorFilter](../../../docs/users/reference/runtimepolicy.md#filtering-monitor-findings).

The first expression is a guard. `event.exec` exists only on an exec observation, so
without `has(event.exec)` the second expression would be evaluated against this pod's file
and network observations too. Expressions are ANDed and short-circuit on the first false,
which is what makes the guard work.

The `!a.startsWith("-")` clause in the suffix rule is not decoration: a flag is never a
package, and without it `--no-mcp` would match the `-mcp` suffix.

## Requires

Process `exec` observation requires a kernel booted with BPF-LSM active: `bpf` must appear
in `/sys/kernel/security/lsm` (set with the `lsm=` kernel boot parameter). Stock
distributions and hosted CI runners are typically not booted with it; Docker Desktop's
LinuxKit VM is, so a kind cluster on macOS runs this example.

```bash
kubectl debug node/<node> -it --image=busybox:1.36 -- cat /host/sys/kernel/security/lsm
```

Read it from the node, not from the daemon pod: that image is distroless and has neither a
shell nor `cat`.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: monitor`, so nothing is ever blocked.

## Run it

1. Start the workload. It writes two launcher stubs and then idles:

   ```bash
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/mcp-agent
   ```

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol detect-mcp-servers
   ```

   `Applied=True` with reason `Monitoring`.

3. Launch one MCP server and one ordinary tool:

   ```bash
   kubectl exec mcp-agent -- npx -y @modelcontextprotocol/server-filesystem /data &
   kubectl exec mcp-agent -- uvx mcp-server-git --repository /src &
   kubectl exec mcp-agent -- npx -y prettier --write .
   ```

## Verify

Both directions matter. A check that only asserts the MCP servers were reported would also
pass against a policy that reports every exec — which is exactly what this policy would do
without its filter.

Exec observations arrive on a ring buffer as they happen, but findings are flushed every 10
seconds, so allow about that long.

```bash
NODE=$(kubectl get pod mcp-agent -o jsonpath='{.spec.nodeName}')
kubectl get report "kyverno-runtime-${NODE}" -o yaml
```

- Two results, one per MCP server, each naming the package in its `argv` property:

  ```yaml
  - source: kyverno-runtime
    policy: detect-mcp-servers
    rule: exec
    result: fail
    description: 'monitor mode: exec of /usr/local/bin/npx would have been denied by policy detect-mcp-servers'
    properties:
      behavior: exec
      target: /usr/local/bin/npx
      argv: npx -y @modelcontextprotocol/server-filesystem /data
      comm: npx
      enforced: "false"
  ```

- **No result for `prettier`**, and none for the shell, `chmod`, or anything else the pod
  ran. That absence is the filter working.

Two details worth knowing when reading the report. `target` distinguishes one finding from
another — two different launchers produce two results rather than merging into one. And each
exec is observed twice, once on the ring buffer with argv and once through the counters
without it; the counter copy has an empty `argv`, so `argv.exists(...)` is false and the
filter drops it. You see one result per server, not two.

## The other transport

A remote MCP server is reached over HTTPS, so it produces a DNS question and no `execve` at
all. `remote-policy.yaml` covers that half, filtering the pod's questions down to the `mcp.`
hostname shape that hosted providers overwhelmingly use:

```bash
kubectl apply -f remote-policy.yaml
kubectl exec mcp-agent -- nslookup mcp.notion.com
kubectl exec mcp-agent -- nslookup example.com
```

The first is reported with `rule: dns`, the second is not. It needs only cgroup v2, not
BPF-LSM — DNS questions are read from a `cgroup_skb` program rather than from an LSM hook.

A `dns` behavior only ever reports, whatever `mode` says, and a policy pairing one with
`mode: enforce` is refused when it compiles. Blocking a remote endpoint is a `network`
behavior, shown in
[trusted-and-untrusted-agents](../trusted-and-untrusted-agents/).

## Tightening it

The filter is a denylist of package shapes, and a denylist is only as good as its list.
Renaming a server binary or wrapping it in a shell script defeats it, while the `execve`
itself is still observed. When a workload's legitimate binaries are known, an allow list
blocks the whole class rather than enumerating it:

```yaml
spec:
  mode: enforce
  behaviors:
  - exec:
      deny:
        values: ["*"]
      allow:
        values:
        - /usr/local/bin/python3
        - /app/agent
```

That is enforcement, so it carries no `monitorFilter` — an `enforce` policy is refused with
one, because an enforce finding records that the kernel actually blocked something and is
never suppressed. See
[restrict-exec-allowlist](../../files-and-processes/restrict-exec-allowlist/) for the allow-list form on its own.

## Clean up

```bash
kubectl delete rpol detect-mcp-servers detect-remote-mcp-endpoints --ignore-not-found
kubectl delete -f client.yaml
```
