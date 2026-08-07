# Detecting shadow MCP

An MCP server a workload picked up on its own — not in the image contract, not reviewed, not
inventoried — is a new path from that workload to a filesystem, a database, or a remote API.
OWASP tracks the class as MCP09:2025, Shadow MCP Servers.

This guide covers what a `RuntimePolicy` can see of MCP, and what it cannot. For the fields
themselves see the [RuntimePolicy reference](reference/runtimepolicy.md); for the expression
environment see the [CEL reference](reference/cel.md).

## Why the runtime sees what the network does not

MCP has two transports and they need entirely different signals.

A **remote** server is reached over HTTPS. The connection is visible — a DNS question, a
destination, a TLS handshake — but the request itself is ciphertext, so nothing here reads a
JSON-RPC method or an `Mcp-Session-Id` header. That is a proxy's job.

A **stdio** server is a child process. Its client writes JSON-RPC to that process's stdin and
reads stdout, so **no socket is opened at all**. A firewall, a CASB, and a service mesh see
nothing, because there is nothing to see. What exists is an `execve` and, usually, a
configuration file read.

That is the split worth keeping in mind: the runtime is where stdio MCP is visible, and it is
the only place it is visible.

## What you can see

| Question | Answer |
| --- | --- |
| Which MCP servers did this workload launch? | Yes — `exec` observation carries argv |
| Did it read an MCP config or credential file? | Yes — `open` observation carries the resolved path |
| Which remote MCP endpoints did it resolve? | Yes — `dns` observation carries the question name |
| Can I stop it reaching an unapproved endpoint? | Yes — `network`, by domain name or address |
| Can I stop it launching an MCP server? | Yes, by allow-listing the binaries it may exec |
| Which tools did it call, with which arguments? | **No** — that is inside TLS |
| Is this pod *serving* MCP to others? | **No** — every hook here is egress or exec |
| Did someone `kubectl port-forward` to an MCP Service? | **No** — that path is the API server |

The last two are worth stating plainly: this is an egress and execution observer. A pod
listening on a port, and a port-forward reaching it, are outside what it watches. Admission
control and RBAC on `pods/portforward` cover those.

## Find the MCP servers a workload launches

The binary is not the signal. `npx -y @modelcontextprotocol/server-filesystem /data` execs
node, `uvx mcp-server-git` execs a Python launcher, and `docker run mcp/sqlite` execs docker.
Matching the binary catches every use of node; matching the package catches the MCP server.

So observe exec broadly, and narrow the findings:

```yaml
apiVersion: runtime.nirmata.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: detect-mcp-servers
spec:
  mode: monitor
  podSelector:
    matchLabels:
      nirmata.io/workload-class: ai-agent
  behaviors:
  - exec:
      deny:
        values: ["*"]
  monitorFilter:
    expressions:
    - name: exec-events-only
      expression: 'has(event.exec)'
    - name: mcp-server-package
      expression: >-
        event.exec.argv.exists(a, a.startsWith("@modelcontextprotocol/")) ||
        event.exec.argv.exists(a, a.startsWith("mcp-server-")) ||
        event.exec.argv.exists(a, a.startsWith("mcp_server")) ||
        event.exec.argv.exists(a, a.startsWith("mcp/")) ||
        event.exec.argv.exists(a, a in ["mcp-remote", "supergateway", "mcpo"]) ||
        event.exec.argv.exists(a, !a.startsWith("-") && a.endsWith("-mcp"))
```

The `exec` behavior is what turns argv streaming on for the pod; the filter is what keeps the
report readable. `has(event.exec)` is a guard — expressions are ANDed and short-circuit, so it
stops the second expression being evaluated against this pod's file and network observations.

Runnable: [detect-mcp-servers](../../examples/detect-mcp-servers/).

## Find MCP configuration and credential reads

An MCP configuration file lists the servers a client will connect to and, in each entry's
environment block, often the token it will connect with. Reading one is worth knowing about.

When the paths are predictable, name them:

```yaml
  behaviors:
  - open:
      deny:
        values:
        - /root/.claude.json
        - /root/.cursor/mcp.json
        - /root/.vscode/mcp.json
        - /root/.codeium/windsurf/mcp_config.json
        - /root/.config/Claude/claude_desktop_config.json
```

Two targets are not predictable, and neither can be written as a value:

- a project-scoped `.mcp.json`, whose absolute path depends on where the repository was
  checked out;
- the OAuth **refresh**-token cache under `~/.mcp-auth/`, whose filenames are hashes.

For those, observe broadly and filter:

```yaml
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

One limit no better expression fixes: some clients keep their server list inside a general
`settings.json`, which a path predicate cannot tell from any other editor setting.

Runnable: [detect-mcp-config-access](../../examples/detect-mcp-config-access/).

## Find the remote endpoints it resolves

A `dns` behavior reports the names a workload asks for. Its `allow` list is a declared
expectation — a name matching none of the entries is reported on its own — which is the right
shape for "this agent may reach these providers, tell me about anything else":

```yaml
spec:
  mode: monitor
  behaviors:
  - dns:
      allow:
        values:
        - mcp.notion.com
        - api.githubcopilot.com
        - kube-dns.kube-system.svc.cluster.local
```

Hosted MCP providers overwhelmingly use an `mcp.` hostname, so a filter generalizes better
than a list that has to be maintained:

```yaml
  behaviors:
  - dns:
      deny:
        values: ["*"]
  monitorFilter:
    expressions:
    - name: mcp-endpoint-resolved
      expression: >-
        has(event.dns) && (
          event.dns.qname.startsWith("mcp.") ||
          event.dns.qname.contains(".mcp.")
        )
```

A `dns` behavior only ever reports. To block a destination, name it in a `network` behavior.

Runnable: [report-unexpected-dns](../../examples/report-unexpected-dns/).

## Compel MCP traffic through a gateway

The strongest control available is not a denylist of endpoints, which goes stale the week it
is written. It is default-deny to an approved gateway, with `protocol` closing the gap so the
only way out is TLS to that gateway:

```yaml
spec:
  mode: enforce
  behaviors:
  - network:
      allow:
        values:
        - mcp-gateway.platform.svc.cluster.local
        - kube-dns.kube-system.svc.cluster.local
      deny:
        values: ["*"]
  - protocol:
      allow:
        values: ["tls", "dns"]
      deny:
        values: ["*"]
```

This does not detect MCP. It makes MCP traffic go somewhere that can inspect it — which is the
one thing a TLS-terminating proxy cannot arrange for itself.

Both behaviors carry the `"*"` sentinel, so a connection must satisfy both: the right
destination over the wrong protocol is denied, and so is TLS to anywhere else. A `network`
policy interns at most 256 domain names per pod, another reason to allow a short list rather
than deny a long one.

Runnable: [trusted-and-untrusted-agents](../../examples/trusted-and-untrusted-agents/).

## Block ad-hoc MCP servers

Matching package names is a denylist, and a denylist is only as good as its list: renaming a
server binary or wrapping it in a shell script defeats it. When a workload's legitimate
binaries are known, allow-list them instead. The `execve` is observed either way, so anything
outside the list is blocked whatever it was renamed to:

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

A declared agent image has a small, knowable exec set. Anything reaching for `npx` at runtime
was not in that contract.

Runnable: [restrict-exec-allowlist](../../examples/restrict-exec-allowlist/).

## Keeping the lists current

The set of MCP packages and hosted endpoints changes faster than a release. Rather than
editing policies, drive a list from a ConfigMap or an HTTP feed with
[`resource.get` or `http.get`](reference/cel.md), and set `spec.evaluationInterval` so it is
re-read:

```yaml
spec:
  mode: monitor
  evaluationInterval: 30m
  behaviors:
  - dns:
      deny:
        expression: >-
          json.unmarshal(http.get("http://mcp-intel.platform.svc.cluster.local/endpoints").body).map(x, string(x))
```

Those libraries are available to a behavior's `expression`, which is evaluated on that
interval. They are deliberately **not** available inside a `monitorFilter`, which runs once
per observation.

Runnable: [blocklist-from-http](../../examples/blocklist-from-http/),
[blocklist-from-configmap](../../examples/blocklist-from-configmap/).

## Limits worth knowing before you rely on this

- **A filter narrows findings, not observation.** The kernel still records every path the pod
  opens, and the per-pod map is under the same pressure a bare `deny: ["*"]` would put it
  under. On a busy workload, observations can be lost — see
  [the limits of monitor mode](reference/runtimepolicy.md).
- **A filter is monitor-only.** An `enforce` policy carrying one is refused at admission: an
  enforce finding records that the kernel actually blocked something, and is never suppressed.
- **DNS visibility is the question, not the answer.** Only cleartext UDP port 53 is read, so
  DNS-over-HTTPS and DNS-over-TLS produce nothing, and a cached answer means no question was
  asked at all. A resolution is also not a connection.
- **A destination named by domain is enforced from the pod's own DNS answers.** A workload
  that connects to a literal address it never resolved is matched by address only.
- **Nothing here reads inside TLS.** Tool names, arguments, and JSON-RPC methods require a
  proxy that terminates the connection.
