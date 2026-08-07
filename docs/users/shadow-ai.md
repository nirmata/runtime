# Detecting shadow AI

An AI capability a workload picked up on its own — a model provider it was never approved to
call, an SDK nobody reviewed, an agent CLI reached for inside a build pod, an MCP server not
in the image contract — is a new path from that workload to a filesystem, a database, or a
remote API. OWASP tracks one member of the class as MCP09:2025, Shadow MCP Servers; the rest
of it has the same shape.

This guide covers what a `RuntimePolicy` can see of AI activity, and what it cannot. For the
fields themselves see the [RuntimePolicy reference](reference/runtimepolicy.md); for the
expression environment see the [CEL reference](reference/cel.md).

## Why the runtime sees what the network does not

Three signal families carry AI activity, and only one of them is on the network.

A **name** is the cheapest and the most durable. Before a workload reaches a hosted provider
it resolves `api.anthropic.com`, `generativelanguage.googleapis.com`, or an `mcp.` hostname,
and the question crosses the wire in cleartext. A workload can drop a recognizable
`User-Agent` far more easily than it can avoid a name resolution.

A **file** is visible whether or not any traffic follows. An SDK load under
`site-packages/openai/`, a `.gguf` read out of a model cache, an OAuth token read from
`~/.claude/.credentials.json`: each is an `open`, each is attributable to a pod, and none of
them depend on the destination being reachable, resolvable, or unencrypted.

A **process** is the only signal for the two cases that produce no network traffic that says
anything. A stdio MCP server is a child process whose client writes JSON-RPC to its stdin, so
no socket is opened at all — a firewall, a CASB, and a service mesh see nothing, because
there is nothing to see. A self-hosted inference server is the mirror image: it serves a port
inside the cluster and never resolves a vendor hostname.

What none of the three gives you is the content. A remote MCP server and a model API are both
reached over HTTPS: the connection is visible — a DNS question, a destination, a TLS
handshake — but the request itself is ciphertext, so nothing here reads a JSON-RPC method, a
model name, a prompt, or an `Mcp-Session-Id` header. That is a proxy's job.

## What you can see

| Question | Answer |
| --- | --- |
| Which model providers did this workload resolve? | Yes — `dns` observation carries the question name |
| Can I stop it reaching an unapproved provider? | Yes — `network`, by domain name or address |
| Which AI SDKs are installed and being loaded? | Yes — `open` observation carries the resolved path |
| Did it read model weights, a model cache, or an agent credential? | Yes — same `open` observation |
| Which agent CLI or inference server did it launch? | Yes — `exec` observation carries argv |
| Which MCP servers did it launch? | Yes — same `exec` observation |
| Did it read an MCP config or credential file? | Yes — `open` observation carries the resolved path |
| Which remote MCP endpoints did it resolve? | Yes — `dns` observation carries the question name |
| Which model was called, with which prompt or tool arguments? | **No** — that is inside TLS |
| Is it talking to a local model on port 11434? | **Only by destination.** No policy value has a port dimension |
| Which A2A peer, and which skill did it invoke? | **No** — over HTTPS that is indistinguishable from any other HTTPS |
| Is this pod *serving* a model, an MCP server, or an agent card? | **No** — every hook here is egress or exec |
| Did someone `kubectl port-forward` to it? | **No** — that path is the API server |

The last three are worth stating plainly: this is an egress and execution observer. A pod
listening on a port, and a port-forward reaching it, are outside what it watches. Admission
control and RBAC on `pods/portforward` cover those.

## LLM provider endpoints a workload resolves

A `dns` behavior reports the names a workload asks for. Naming the providers in `deny` keeps
the report to AI traffic rather than every name the workload resolves:

```yaml
  behaviors:
  - dns:
      deny:
        values:
        # A wildcard covers subdomains and not the apex, so a provider whose
        # apex serves the API is listed twice.
        - "*.openai.com"
        - "*.anthropic.com"
        - "*.openai.azure.com"
        - "*.googleapis.com"
        - "*.mistral.ai"
        - "*.cohere.ai"
        - "*.x.ai"
        - "*.deepseek.com"
        - "*.groq.com"
        - "*.perplexity.ai"
        - "*.together.ai"
        - "*.replicate.com"
        - "*.huggingface.co"
        - openai.com
        - anthropic.com
        # Bedrock puts the region in the middle of the name, and a wildcard is
        # only the leftmost label, so each region is its own value. Adding a
        # region the workload uses is what extends this.
        - bedrock-runtime.us-east-1.amazonaws.com
        - bedrock-runtime.us-west-2.amazonaws.com
        - bedrock-runtime.eu-central-1.amazonaws.com
```

How a provider can be written at all is decided by the wildcard being the leftmost label and
nothing else. Bedrock's region sits in the middle of the name, so each region is its own
value. Vertex puts its region in a *prefix* of one label —
`us-central1-aiplatform.googleapis.com` — so the only expressible form is `*.googleapis.com`,
which also reports `storage.googleapis.com` and the rest of Google's APIs. Both are the
honest reading: a value that matched neither would look correct and report nothing.

The inverse shape suits a workload whose traffic is already understood. A `dns.allow` list is
a declared expectation — a name matching none of the entries is reported on its own — which
is the right form for "this agent may reach these providers, tell me about anything else":

```yaml
  behaviors:
  - dns:
      allow:
        values:
        - api.openai.com
        - api.anthropic.com
        - "*.openai.azure.com"
```

A `dns` behavior only ever reports. To block a destination, name it in a `network` behavior.

Runnable: [trusted-and-untrusted-agents](../../examples/shadow-ai/trusted-and-untrusted-agents/),
[report-unexpected-dns](../../examples/shadow-ai/report-unexpected-dns/).

## SDKs, model weights, and caches on disk

This is the one AI signal that does not depend on the network. It survives a hardcoded
address, a tunnel, and an endpoint that is never reachable at all — a DNS question says a name
was looked up, while an `open` under `site-packages/anthropic/` says the SDK is being loaded
in this pod, now, by a process you can attribute.

None of these paths can be written as an `open` value. An SDK directory's absolute path
depends on the interpreter version and the virtualenv, a model file has no fixed name, and a
credential file sits under whichever home directory the container runs as. So observe broadly
and filter:

```yaml
  behaviors:
  - open:
      deny:
        values: ["*"]
  monitorFilter:
    expressions:
    - name: open-events-only
      expression: 'has(event.open)'
    - name: ai-sdk-model-or-credential
      expression: >-
        [
          "/site-packages/anthropic/", "/site-packages/openai/",
          "/site-packages/google/genai/", "/site-packages/mistralai/",
          "/site-packages/cohere/", "/site-packages/litellm/",
          "/site-packages/langchain/", "/site-packages/llama_index/",
          "/site-packages/transformers/", "/site-packages/vllm/",
          "/node_modules/@anthropic-ai/sdk/", "/node_modules/openai/",
          "/node_modules/@google/genai/", "/node_modules/@langchain/",
          "/.cache/huggingface/", "/.ollama/models/", "/.cache/lm-studio/",
        ].exists(d, event.open.path.contains(d)) ||
        [".safetensors", ".gguf", ".onnx", ".ckpt"].exists(x,
          event.open.path.endsWith(x)) ||
        [
          "/.claude/.credentials.json", "/.codex/auth.json",
          "/.gemini/oauth_creds.json", "/.continue/config.json",
          "/.aider.conf.yml",
          "/.config/gcloud/application_default_credentials.json",
        ].exists(f, event.open.path.endsWith(f))
```

Directory entries carry both slashes so that a `contains` match is a path component rather
than a substring: without the trailing slash, `anthropic` also matches `anthropic-notes.txt`.

An installed SDK is evidence of intent, not of traffic. Read it alongside the names the
workload actually resolved.

Runnable: [detect-ai-sdks](../../examples/shadow-ai/detect-ai-sdks/).

## Agent CLIs and launchers

A coding agent CLI reached for inside a build pod, and a self-hosted inference server started
inside the cluster, both begin as an `execve` and announce themselves no other way. The
inference server is the truer shadow AI, because nobody registered it anywhere: it has no
vendor hostname to resolve and no provider endpoint to block, so the launch is the signal.

The binary is not that signal. `npx -y @anthropic-ai/claude-code` execs node, `uvx aider-chat`
execs a Python launcher, and `python -m vllm.entrypoints.openai.api_server` execs python.
Matching the binary catches every use of node; matching the name it was invoked under, or the
package a launcher was asked to fetch, catches the agent.

```yaml
  behaviors:
  - exec:
      deny:
        values: ["*"]
  monitorFilter:
    expressions:
    - name: exec-events-only
      expression: 'has(event.exec)'
    - name: agent-cli-or-inference-server
      expression: >-
        event.exec.argv.exists(a, a in [
          "claude", "codex", "gemini", "aider", "goose", "opencode", "crush",
          "cursor-agent", "ollama", "litellm", "text-generation-launcher",
        ]) ||
        event.exec.argv.exists(a,
          a.startsWith("@anthropic-ai/") ||
          a.startsWith("@openai/") ||
          a.startsWith("@google/gemini-cli")) ||
        event.exec.argv.exists(a,
          a == "vllm" ||
          a.startsWith("vllm.") ||
          a.startsWith("sglang.") ||
          a.startsWith("llama_cpp."))
```

The `exec` behavior is what turns argv streaming on for the pod; the filter is what keeps the
report readable. `has(event.exec)` is a guard — expressions are ANDed and short-circuit, so it
stops the second expression being evaluated against this pod's file and network observations.

Runnable: [detect-agent-cli](../../examples/shadow-ai/detect-agent-cli/).

## MCP servers a workload launches

MCP has two transports and they need entirely different signals. A remote server is reached
over HTTPS and is a name problem, covered above. A stdio server is a child process, and is the
case nothing else in the stack can see.

The same argv reasoning applies, with a different vocabulary:
`npx -y @modelcontextprotocol/server-filesystem /data` execs node, `uvx mcp-server-git` execs a
Python launcher, and `docker run mcp/sqlite` execs docker.

```yaml
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

The `!a.startsWith("-")` clause in the suffix rule is not decoration: a flag is never a
package, and without it `--no-mcp` would match the `-mcp` suffix.

For the remote half, hosted MCP providers overwhelmingly use an `mcp.` hostname, so a filter
generalizes better than a list that has to be maintained:

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

Runnable: [detect-mcp-servers](../../examples/shadow-ai/detect-mcp-servers/),
[report-unexpected-dns](../../examples/shadow-ai/report-unexpected-dns/).

## MCP configuration and credentials

An MCP configuration file lists the servers a client will connect to and, in each entry's
environment block, often the token it will connect with. Reading one is worth knowing about.

When the paths are predictable, name them:

```yaml
  behaviors:
  - open:
      deny:
        values:
        # One absolute path per (home directory, config file) pair: the kernel
        # maps are keyed on the resolved path string, so there is no glob form.
        - /root/.cursor/mcp.json
        - /root/.codeium/windsurf/mcp_config.json
        - /root/.config/Claude/claude_desktop_config.json
        - /home/node/.cursor/mcp.json
        - /home/node/.codeium/windsurf/mcp_config.json
        - /home/node/.config/Claude/claude_desktop_config.json
        - /etc/mcp/config.json
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

Runnable: [detect-mcp-config-access](../../examples/shadow-ai/detect-mcp-config-access/).

## Agent-to-agent traffic

Agent-to-agent protocols are the weakest case here, and the honest summary is that you cannot
detect the protocol — you can only constrain the peers.

An A2A call is JSON-RPC over HTTPS. The agent card at `/.well-known/agent-card.json`, the
skill being invoked, and the task lifecycle are all inside TLS, and nothing in this runtime
reads a URL path, an HTTP header, or a body. Protocol classification stops at the ALPN string
from the TLS ClientHello, which is `h2` for a great deal of ordinary traffic and identifies
nothing on its own. There is no SNI: the ClientHello parser reads the ALPN extension and skips
the server-name one, so a name comes from the DNS question or not at all.

What is left is real but coarse. An external peer is resolved before it is reached, so it
appears as a `dns` question and can be denied by a `network` behavior. An in-cluster peer is
usually a Service, which a `network` behavior names directly and enforces from Service and
EndpointSlice informers rather than from DNS:

```yaml
spec:
  mode: enforce
  podSelector:
    matchLabels:
      nirmata.io/agent: trusted
  behaviors:
  - network:
      allow:
        values:
        - kubernetes.default.svc.cluster.local
        - kube-dns.kube-system.svc.cluster.local
      deny:
        values:
        - "*"
  - protocol:
      allow:
        values:
        - "tls"
        - "dns"
      deny:
        values:
        - "*"
```

That is an approved-peer boundary, not A2A detection. It answers "which agents can this agent
reach", which is the question worth enforcing anyway; "what did they say to each other" needs
a proxy that terminates the connection. The reverse direction — this pod *serving* an agent
card to others — is outside what any hook here watches.

Runnable: [trusted-and-untrusted-agents](../../examples/shadow-ai/trusted-and-untrusted-agents/),
[egress-to-cluster-service](../../examples/egress/egress-to-cluster-service/).

## Compel AI traffic through a gateway

The strongest control available is not a denylist of providers, which goes stale the week it
is written. It is default-deny to an approved gateway, with `protocol` closing the gap so the
only way out is TLS to that gateway — the policy above, with the gateway in place of the API
server.

This does not detect anything. It makes AI traffic go somewhere that can inspect it, which is
the one thing a TLS-terminating proxy cannot arrange for itself.

Both behaviors carry the `"*"` sentinel, so a connection must satisfy both: the right
destination over the wrong protocol is denied, and so is TLS to anywhere else. A `network`
policy interns at most 256 domain names per pod, another reason to allow a short list rather
than deny a long one.

When a workload's legitimate binaries are known, the same reasoning applies to execution. A
package-name filter is a denylist, and renaming a binary or wrapping it in a shell script
defeats it; an allow list blocks the whole class instead:

```yaml
  variables:
  - name: readOnlyTools
    expression: "['/bin/cat', '/bin/ls']"
  behaviors:
  - exec:
      deny:
        values:
        - "*"
      allow:
        values:
        - "/bin/sh"
        expression: "variables.readOnlyTools"
```

A declared agent image has a small, knowable exec set. Anything reaching for `npx` at runtime
was not in that contract.

Runnable: [restrict-exec-allowlist](../../examples/files-and-processes/restrict-exec-allowlist/),
[default-deny-egress](../../examples/egress/default-deny-egress/).

## Keeping the lists current

Model providers, MCP packages, and agent CLIs all change faster than a release. Rather than
editing policies, drive a list from a ConfigMap or an HTTP feed with
[`resource.get` or `http.get`](reference/cel.md), and set `spec.evaluationInterval` so it is
re-read:

```yaml
spec:
  mode: enforce
  evaluationInterval: 30s
  podSelector:
    matchLabels:
      app: http-client
  behaviors:
  - network:
      deny:
        expression: http.get("http://ip-server.default.svc.cluster.local:8080").body.map(x, string(x))
```

Any behavior's list can be built this way, `dns` included. Those libraries are available to a
behavior's `expression`, which is evaluated on that interval. They are deliberately **not**
available inside a `monitorFilter`, which runs once per observation — so the *names* a policy
watches for can come from a feed, while the shape of an argv or path predicate cannot.

Runnable: [blocklist-from-http](../../examples/dynamic-lists/blocklist-from-http/),
[blocklist-from-configmap](../../examples/dynamic-lists/blocklist-from-configmap/).

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
- **No policy value has a port.** A local model on `11434` and a vLLM server on `8000` are
  reachable as destinations, never as ports, so a cleartext in-cluster inference endpoint is
  constrained by address or Service name or not at all.
- **Observations are truncated by the kernel record.** An `open` path is keyed at 128 bytes,
  so a deeply nested virtualenv can be cut before the component a filter looks for; argv is
  eight arguments of 127 bytes, so a package name past the eighth argument is not matched.
- **Nothing here reads inside TLS.** Model names, prompts, tool arguments, JSON-RPC methods,
  and HTTP paths all require a proxy that terminates the connection.
