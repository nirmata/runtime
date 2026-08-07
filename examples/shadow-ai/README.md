# Shadow AI

An AI capability a workload picked up on its own — a model provider it was never approved to
call, an SDK nobody reviewed, an agent CLI reached for inside a build pod, an MCP server not
in the image contract — is a new path from that workload to a filesystem, a database, or a
remote API.

Three signal families carry it, and the examples here are grouped by which one they use:

- **A name.** A hosted provider is resolved before it is reached, and the question crosses
  the wire in cleartext.
- **A file.** An SDK load, a model file, a credential read — visible whether or not any
  traffic follows.
- **A process.** A stdio MCP server and a self-hosted inference server produce no network
  traffic that says anything, and both begin as an `execve`.

[Detecting shadow AI](../../docs/users/shadow-ai.md) walks through all of them together and
is the place that says what each signal can and cannot establish. Read it before relying on
any of these.

| Directory | Signal | Scenario | Mode | Requires |
| --- | --- | --- | --- | --- |
| [report-unexpected-dns](report-unexpected-dns/) | name | Report the DNS names a workload resolves that it was not expected to, and discover the names it resolves at all | monitor | cgroup v2 |
| [trusted-and-untrusted-agents](trusted-and-untrusted-agents/) | name | Give a declared agent a hard TLS-to-one-Service boundary, and report which LLM providers an undeclared one resolves | enforce and monitor | cgroup v2 |
| [detect-ai-sdks](detect-ai-sdks/) | file | Report the AI SDKs, model files, model caches, and agent credentials a workload reads | monitor | BPF-LSM |
| [detect-agent-cli](detect-agent-cli/) | process | Report the coding-agent CLIs and self-hosted inference servers a workload launches | monitor | BPF-LSM |
| [detect-mcp-servers](detect-mcp-servers/) | process, name | Report every stdio MCP server a workload launches, and the remote MCP endpoints it resolves | monitor | BPF-LSM for the stdio half; cgroup v2 for the remote half |
| [detect-mcp-config-access](detect-mcp-config-access/) | file | Detect a process reading an MCP configuration file, credentials included | monitor | BPF-LSM |

Every one of these is a detection, not a boundary. Nothing here reads inside TLS, so model
names, prompts, tool arguments, and JSON-RPC methods are all out of reach, and no policy
value has a port — a local model on `11434` is constrained by address or Service name or not
at all. The control that does bound the problem is default-deny egress to an approved
gateway, shown in [trusted-and-untrusted-agents](trusted-and-untrusted-agents/) and
[egress/default-deny-egress](../egress/default-deny-egress/).
