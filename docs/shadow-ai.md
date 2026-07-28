# Shadow AI detection

kyverno-runtime can classify network, HTTP, and process activity as AI traffic
(LLM inference, MCP, A2A) and either report on it (`monitor` mode) or roll it
up into a cluster inventory (`discover` mode), using the same `RuntimePolicy`
CRD and eBPF collection pipeline used for `network`/`exec`/`open`.

## Status: read this before deploying

This feature is **not yet a working detector on a real cluster.** One gap is the
reason, and it is not a detail:

1. **The five eBPF data sources are not wired up.** `pkg/bpf/dnstrace`,
   `pkg/bpf/netflow`, `pkg/bpf/tlspeek`, `pkg/bpf/l7peek` and
   `pkg/bpf/exectrace` each ship their C program and a fully unit-tested
   decoder, but every `NewSource` returns `runtimeevent.ErrSourceNotWired`:
   `bpf2go` needs `clang` and a generated `vmlinux.h`, which the build host did
   not have, so no compiled object exists to load. The C has **never been
   compiled or passed through the verifier**. Consequently **nothing that ships
   today observes DNS queries, TLS ClientHellos, HTTP requests or `execve` calls
   on a live node** — the AI stages only ever see the map-poll observations
   inherited from monitor mode. Tracked in
   [#63](https://github.com/nirmata/kyverno-runtime/issues/63).

2. **AI `enforce` mode is not implemented.** A policy that sets `mode: enforce`
   on an `ai` behavior is downgraded to `monitor` and the engine records
   `AIEnforcementImplemented=False` on the policy, so the object itself says so.
   Compelled routing — forcing AI egress through a governed proxy — is
   [#64](https://github.com/nirmata/kyverno-runtime/issues/64), and it is in turn
   blocked on IPv6/CIDR egress maps
   ([#65](https://github.com/nirmata/kyverno-runtime/issues/65)).

3. **AIControls audit reconciliation is absent.** The `governed` bit works, but
   comparing the proxy's audit log against observed flows — the `M > N`
   calculation that quantifies bypass — is
   [#66](https://github.com/nirmata/kyverno-runtime/issues/66).

What *is* wired and tested: the classifier and its provider catalog, the `ai`
behavior and `discover` mode, the event-time CEL surface (`event` variable and
`ai.*` library, compiled from a real `RuntimePolicy`), the detect engine, the
`AIInventory` rollup and its per-node shard writer, the `governed` bit, and the
redaction guarantees. `cmd/kyverno-runtime/daemon.go` constructs all of it. The
end-to-end pipeline is exercised by `test/samples/shadow-ai`, which drives real
code over fixture events — see that directory's README for exactly what the
sample does and does not prove.

The honest summary: **every layer above the kernel works and is tested; the
kernel layer that would feed it real traffic does not exist yet.**

## The `ai` behavior

`spec.behaviors[]` entries are 4-way exclusive: exactly one of `network`,
`exec`, `open`, or `ai` per entry
(`api/v1alpha1/runtimepolicy_types.go: PolicyBehavior`, enforced by an
`XValidation` rule). `AIBehavior` looks like this:

```yaml
ai:
  classes: [llm, mcp, a2a]      # optional; empty means all three
  allow:
    values: ["provider:anthropic", "provider:openai"]
  deny:
    values: ["*"]                # default-deny sentinel, same as other behaviors
  match: "event.ai.provider == 'anthropic' && event.ai.confidence >= 80"
  minConfidence: 70               # 0-100; findings below this confidence are dropped
  severity: high                  # info|low|medium|high|critical
```

- `classes`: restricts which of `llm`, `mcp`, `a2a` this rule considers.
- `allow`/`deny`: destination identities — hostname globs, IPv4/CIDR literals,
  `provider:<name>` tokens resolved from the provider catalog, or
  `mcp-server:<package>` for stdio MCP servers. `values` and `expression` union,
  same as `network`/`exec`/`open`.
- `match`: a CEL predicate over the per-event `event` variable (see
  [The `event` CEL variable](#the-event-cel-variable-and-ai-library) — not yet
  compilable, see [Status](#status-read-this-before-deploying)).
- `minConfidence`: gates findings by the classifier's 0-100 confidence score.
- `severity`: attached to the emitted `reporter.Finding`.

### `discover` mode

`spec.mode: discover` observes AI traffic and writes it into the cluster-wide
`AIInventory` singleton — it emits **no per-event findings and no Reports**.
On a large cluster, one Report per classified event would be tens of
thousands of objects; the inventory is the only visible output of discovery
(`pkg/inventory` package doc).

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: discover-ai-traffic
spec:
  mode: discover
  podSelector: {}          # every pod on the node
  behaviors:
  - ai:
      classes: [llm, mcp, a2a]
```

```bash
kubectl apply -f discover-ai-traffic.yaml
kubectl get aiinventory cluster -o yaml
```

### `monitor` mode: flagging unsanctioned LLM providers

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: unsanctioned-llm-providers
spec:
  mode: monitor
  podSelector:
    matchLabels:
      app: agent-runner
  behaviors:
  - ai:
      classes: [llm]
      deny:
        values: ["*"]
      allow:
        values: ["provider:anthropic", "provider:azure-openai"]
      minConfidence: 60
      severity: high
```

Any LLM call classified with confidence >= 60 to a provider other than
Anthropic or Azure OpenAI produces a `reporter.Finding` with
`Behavior: "ai"`, `Result: "fail"`, and `Severity: "high"` — visible via
`kubectl get reports` (OpenReports) — but nothing is blocked.

### `enforce` mode: MCP allowlist (downgraded to monitor)

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: mcp-allowlist
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: agent-runner
  behaviors:
  - ai:
      classes: [mcp]
      deny:
        values: ["*"]
      allow:
        values: ["mcp-server:@modelcontextprotocol/server-filesystem"]
```

Because AI enforcement is not implemented, this policy behaves exactly like
the `monitor` example above: it reports every non-allowlisted MCP server as a
finding, and sets `status.conditions[type=AIEnforcementImplemented]` to
`False` so this is discoverable from `kubectl describe runtimepolicy
mcp-allowlist` without reading source code.

### Discovering A2A agents

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: discover-a2a-agents
spec:
  mode: discover
  podSelector: {}
  behaviors:
  - ai:
      classes: [a2a]
```

### Degraded / metadata-only observation

Not every signal is available for every event. A `tlspeek`-sourced event (once
wired) carries SNI but no destination IP; a `dnstrace`-sourced event carries
only the queried hostname. A `match` expression should not assume every
`event.ai` field is populated:

```yaml
ai:
  match: >
    has(event.ai.provider) && event.ai.provider != "" &&
    (!has(event.net) || event.ai.confidence >= 70)
  minConfidence: 40
```

Low-confidence, single-signal observations (e.g. a bare DNS question for
`api.openai.com` with no corroborating SNI or HTTP path) are exactly what
`minConfidence` exists to filter out.

## The AIInventory CR

`AIInventory` (`api/v1alpha1/aiinventory_types.go`) is a cluster-scoped
singleton named `cluster` (shortName `aiinv`). Any node's daemon creates it on
demand; every daemon in the DaemonSet writes only its own shard.

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: AIInventory
metadata:
  name: cluster
status:
  summary:
    workloads: 3
    providers: "anthropic,ollama,openai"
  nodes:
  - nodeName: node-a
    updatedAt: "2026-07-27T12:00:00Z"
    droppedEvents: 0
    workloads:
    - namespace: default
      kind: Deployment
      name: agent-runner
      classes: ["llm", "mcp"]
      providers: ["anthropic", "openai"]
      endpointKinds: ["messages", "chat.completions"]
      models: ["claude-opus-4", "gpt-4o"]
      transports: ["https"]
      eventCount: 412
      ungovernedCount: 12
      firstSeen: "2026-07-27T09:00:00Z"
      lastSeen: "2026-07-27T11:58:00Z"
```

Field notes (`pkg/inventory/rollup.go`):

- One entry per `(namespace, kind, name)` workload key, where `kind`/`name`
  is the pod's owner (Deployment, StatefulSet, ...) or `Pod` for a bare pod.
- `classes`, `providers`, `endpointKinds`, `models`, `transports` are
  deduplicated sets, capped at 64 distinct entries and 128 bytes per entry —
  `models` in particular is attacker-influenced (derived from request bodies),
  so both caps exist to stop a workload from growing the singleton without
  bound.
- `droppedEvents` surfaces the collector's ring-buffer drop count for that
  node. **A workload with zero events and a node with `droppedEvents > 0` is
  not evidence of "no AI traffic" — it may be evidence of an overwhelmed
  collector.** This field exists specifically so silence is never misread as
  safety (see [Evasion and limitations](#evasion-and-limitations)).
- `ungovernedCount` counts events whose destination did not go through the
  configured AIControls proxy (`Governed == false`); see
  [The governed bit](#the-governed-bit-and-the-aicontrols-division-of-labour).
- The rollup is per-node and per-daemon-process; the singleton is reconciled
  with `client-go/util/retry.RetryOnConflict` so concurrent daemons updating
  different shards of the same object don't clobber each other.

## The `event` CEL variable and `ai` library

> This section describes the design contract for `AIBehavior.match`. As noted
> in [Status](#status-read-this-before-deploying), `pkg/compiler` does not yet
> wire an `event` variable or the `ai` library into the CEL environment used
> to compile a `RuntimePolicy` — verify against `pkg/compiler/env.go` before
> depending on this in a real policy.

`event` is intended to expose the classified `runtimeevent.Event` to a
`match` expression. The AI-relevant subset (`pkg/runtimeevent/ai.go:
AIFacts`) is:

| Field | Type | Description |
| --- | --- | --- |
| `event.ai.class` | string | `llm`, `mcp`, or `a2a`. |
| `event.ai.provider` | string | Catalog provider name (`anthropic`, `openai`, ...), `self-hosted` for an unrecognized OpenAI-compatible endpoint, or `""` when unknown. |
| `event.ai.model` | string | Requested model name; only populated when a plaintext body preview was observed. |
| `event.ai.endpointKind` | string | API shape, e.g. `messages`, `chat.completions`, `generateContent`, `mcp.streamable-http`, `mcp.stdio`, `a2a.agent-card`, `a2a.jsonrpc`. |
| `event.ai.jsonrpcMethod` | string | Sniffed JSON-RPC method name, when present. |
| `event.ai.transport` | string | `https`, `http`, `stdio`, or `sse`; empty when the observation carries no transport information (e.g. a bare DNS question). |
| `event.ai.confidence` | int | 0-100; see [Confidence scoring](#confidence-scoring). |
| `event.ai.evidence` | list(string) | Signal tokens, e.g. `sni:api.openai.com`, `header:anthropic-version`, `port:11434`. Names only — never header values or body content. |
| `event.ai.sanctioned` | bool | Whether the matched provider is marked sanctioned in the catalog. |
| `event.net.governed` | bool (optional/tri-state) | See [The governed bit](#the-governed-bit-and-the-aicontrols-division-of-labour). |

The `ai` CEL library (`pkg/detect/ai/cellib.go`, library name `kyverno.ai`)
exposes pure, allocation-free catalog lookups so a policy author never has to
inline provider hostname regexes:

| Function | Signature | Behavior |
| --- | --- | --- |
| `ai.isProvider` | `(host, provider string) -> bool` | Whether `host` belongs to the named catalog provider. |
| `ai.provider` | `(host string) -> string` | Resolves `host` to its catalog provider name, `""` when unknown. |
| `ai.isLLMPath` | `(path string) -> bool` | Whether `path` matches a known inference endpoint shape (from `llmEndpoints` in the catalog). |
| `ai.isMCPMethod` | `(method string) -> bool` | Whether `method` sits in the MCP JSON-RPC namespace (`tools/`, `resources/`, `prompts/`, ...). |
| `ai.isA2AMethod` | `(method string) -> bool` | Whether `method` sits in the A2A JSON-RPC namespace (`message/`, `tasks/`, ...). |
| `ai.isMCPServerPackage` | `(arg string) -> bool` | Whether `arg` names a stdio MCP server package (by prefix/suffix/substring match against the catalog's `mcp` package rules). |

None of these functions panic on a non-string argument; they return a CEL
error value instead. A `nil` catalog falls back to the embedded default
rather than turning every lookup into `false`.

## The provider catalog

`pkg/detect/ai/catalog.json`, embedded into the binary via `//go:embed` and
loaded by `DefaultCatalog()`. Eighteen providers ship today:

| Provider | Self-hosted | Notes |
| --- | --- | --- |
| `anthropic` | no | `/v1/messages`, `/v1/complete`; `anthropic-version`/`anthropic-beta` headers |
| `openai` | no | `openai-organization`/`openai-project`/`openai-beta` headers |
| `azure-openai` | no | `/openai/deployments/*`, `/openai/responses` |
| `google` | no | Gemini + Vertex AI; `x-goog-api-key` header |
| `bedrock` | no | AWS Bedrock; `x-amzn-bedrock-*` headers |
| `mistral` | no | |
| `cohere` | no | |
| `openrouter` | no | |
| `groq` | no | |
| `fireworks` | no | |
| `together` | no | |
| `xai` | no | |
| `deepseek` | no | |
| `perplexity` | no | |
| `huggingface` | no | |
| `ollama` | yes | port `11434`, `/api/generate`, `/api/chat` |
| `vllm` | yes | port `8000` |
| `lmstudio` | yes | port `1234` |

The catalog also carries an `llmEndpoints` glob table (path -> endpoint kind,
e.g. `/v1/chat/completions` -> `chat.completions`), `mcp` recognition rules
(JSON-RPC method prefixes, stdio launcher binaries, package name
prefixes/suffixes, client config file/directory names), and `a2a` recognition
rules (well-known agent-card path, JSON-RPC method prefixes).

### Extending the catalog via ConfigMap

`LoadCatalog([]byte) (*Catalog, error)` (`pkg/detect/ai/providers.go`) parses
a catalog in the same JSON shape as `catalog.json` and rejects it outright
(no partial application) if any provider is missing a name or hostname list,
if two providers share a name, or if the parsed catalog has zero providers.
`Classifier.SetCatalog` swaps the classifier's catalog atomically — a `nil`
catalog is ignored so a bad ConfigMap can never blind the classifier, and an
in-flight classification always sees either the old or the new catalog, never
a partially-updated one. To add an internal self-hosted provider (an internal
model-serving deployment, for example), publish a ConfigMap holding an
extended `catalog.json` and point the daemon at it; the daemon watches the
ConfigMap and calls `SetCatalog` on change.

### Confidence scoring

`pkg/detect/ai/confidence.go` assigns each signal a fixed score, then
`Combine()` folds every independent signal that fired into one 0-100
confidence: the strongest signal's score, plus 20 for every additional
independent signal, capped at 99 (the classifier never claims certainty — it
observes traffic shape, not intent).

| Signal | Score | Signal | Score |
| --- | --- | --- | --- |
| DNS question for a provider hostname | 70 | JSON-RPC method in a protocol namespace | 90 |
| TLS SNI for a provider | 70 | MCP-Session-Id / MCP-Protocol-Version header | 95 |
| HTTP Host header for a provider | 70 | MCP streamable-HTTP shape (POST + SSE Accept + JSON Content-Type) | 80 |
| HTTP path matching a known inference endpoint | 90 | Conventional MCP path (`/mcp`, `/sse`, `/messages`) | 40 |
| Provider-distinctive header name | 95 | Open of an MCP client config file | 60 |
| Inference request body shape (`model` + `messages`) | 95 | A2A well-known agent-card request | 95 |
| Conventional self-hosted port alone (e.g. 11434) | 40 | Exec of a stdio MCP server package | 95 |

Two 70-point metadata signals for the same provider (DNS + SNI, say) combine
to 90, matching the documented example in the design doc: neither alone
claims certainty, but corroboration does.

## The governed bit and the AIControls division of labour

`event.net.governed` (`runtimeevent.NetFacts.Governed *bool`) is a tri-state
bit: `nil` means unknown, `true`/`false` means the destination was resolved
against (or found outside) the configured AIControls proxy's Service +
EndpointSlice addresses. It is set by `pkg/aicontrols.EndpointResolver`, a
`collector.Stage` (`pkg/aicontrols/stage.go`), and only becomes non-nil once
the resolver is both `Enabled()` (an AIControls namespace/service is
configured) and `Ready()` (it has successfully populated its address set at
least once). **The resolver never contacts AIControls on the per-event path**
— `Process` is a pure map lookup against addresses cached from a periodic
`Run(ctx)` refresh loop (`pkg/aicontrols/resolver.go`).

This bit is the seam between the two systems, and it exists because the two
projects answer different questions:

- **kyverno-runtime answers "is this AI call subject to governance at all?"**
  — proxy-bypass detection (a workload calling `api.openai.com` directly
  instead of through the governed egress path), stdio MCP visibility (which
  AIControls, an HTTP-plane product, cannot see), passthrough-hole detection,
  compelled-routing state, and coverage attestation ("every node's daemon is
  running and its classifier is current").
- **AIControls answers "what is this AI call doing?"** — LLM request/response
  semantics, MCP tool-call semantics, full L7 HTTP inspection, the SSRF floor,
  and human-in-the-loop approval flows.

kyverno-runtime never re-implements AIControls' L7 semantics, and AIControls
is never queried per-event from the kernel-adjacent hot path — the join
between the two is the governed bit plus workload identity (namespace/pod),
computed independently by each system and correlated by whoever consumes
both (a dashboard, an alerting rule), not by a live call between them.

`AIWorkloadInventory.ungovernedCount` is the discover-mode expression of this
bit: a workload with a non-zero `ungovernedCount` made AI calls that bypassed
the governed path, which is exactly the "shadow AI" case this feature exists
to surface — even when AIControls itself never saw the call.

## Redaction guarantees

Nothing that reaches a `Report` or the `AIInventory` can contain a header
value, request/response body content, or credential material. This is
enforced at three points, not by convention:

1. **`AIFacts.Evidence` tokens are constructed only through
   `pkg/detect/ai/confidence.go: Token(prefix, value)`**, which strips every
   byte outside printable, non-space ASCII and bounds the result to 128
   bytes. Callers pass header *names*, hostnames, paths, ports, and validated
   protocol method names — never a header value, never body text. A token
   naming a header looks like `header:anthropic-version`, never
   `header:sk-ant-...`.
2. **`runtimeevent.NewHTTPFacts` is the only constructor for HTTP event
   facts**; its fields are unexported, and secret-shaped headers are redacted
   at construction time, before the event reaches any sink (classifier,
   monitor, inventory). The intermediate header map used while parsing a
   captured request is function-local and is never itself returned or logged.
3. **`reporter.Finding` is a closed struct** (`pkg/reporter/finding.go`) —
   there is no free-form property map a producer could accidentally stuff a
   raw value into. Its `AI *AISummary` field carries only the same evidence
   tokens described above, plus `sanitizeEvidence` as defense-in-depth
   scrubbing of credential-shaped substrings before a `Finding` is written
   into a Report.

No component in this pipeline logs a raw header map, a request/response body,
or a CEL variable's raw value; see `Agents.md`'s logging conventions.

## Evasion and limitations

Detection here is signal-based traffic classification, not policy
enforcement of AI semantics, and (once the BPF sources are wired) it inherits
real limits from where in the stack it observes:

- **Encrypted DNS (DoH/DoT)** bypasses `dnstrace` entirely — a workload using
  a DNS-over-HTTPS resolver produces no plaintext DNS query for the
  classifier to see.
- **Encrypted ClientHello (ECH)** removes the SNI `tlspeek` reads, so a
  provider using ECH is invisible to the SNI signal (though DNS or HTTP-host
  signals may still corroborate it).
- **Connecting to an IP literal** (no DNS, no SNI hostname) defeats both the
  DNS and SNI signals; only an HTTP Host header, path, or body shape can
  still classify it.
- **A self-hosted OpenAI-compatible server behind a private CA on port 443**
  is effectively undetectable: no recognizable hostname, no recognizable
  port convention, and TLS termination happens before any plaintext HTTP
  signal is observable.
- **Non-cooperating workloads** (statically-linked Go binaries, custom HTTP
  clients with no distinguishing headers) may produce no signal beyond DNS/SNI
  — which, per the confidence table, caps out around 70-90, not the higher
  scores plaintext-HTTP signals reach.
- **Proxy chaining** misattributes traffic to whichever pod terminates the
  connection kyverno-runtime observes — a workload routing through an
  in-cluster forward proxy pod shows up as that proxy pod's traffic, not the
  originating workload's.
- **Non-HTTP transports** (raw gRPC, WebSocket framing without the initial
  HTTP upgrade being observed) are outside `l7peek`'s parser.
- **stdio MCP evasion**: a renamed MCP server binary or an unrecognized
  package name defeats the `argv`/package-name signal, though the underlying
  `exec` is still observed by `exectrace` (once wired) — it just isn't
  *classified* as MCP.
- **cgroup attribution gaps**: on CRI-O or Docker nodes, or cgroup v1 nodes,
  container attribution may resolve no cgroup ID at all (a pre-existing
  limitation shared with `network`/`exec`/`open` — see `docs/dev/DESIGN.md`
  [Known Gaps](dev/DESIGN.md#known-gaps--future-work)), which silently drops
  AI classification for that node's traffic along with everything else.
- **Ring-buffer drops must never read as silence.** A saturated BPF ring
  buffer drops events before they reach userspace; the `AIInventory`'s
  per-node `droppedEvents` field exists specifically so an operator sees "0
  workloads, 40000 dropped events" rather than "0 workloads" — see
  [The AIInventory CR](#the-aiinventory-cr).
- **IPv4-only, 1024-entry-cap enforcement** in the existing egress path
  applies identically to any future AI-aware enforcement built on the same
  primitives.

None of these are bugs to fix in isolation — they are the reason this feature
is explicitly scoped as *detection/inventory*, not a claim of complete
coverage, and why the [division of labour](#the-governed-bit-and-the-aicontrols-division-of-labour)
with AIControls exists: AIControls' proxy-plane visibility covers several of
the gaps above (encrypted transport, IP literals, body content) that a
kernel-adjacent observer structurally cannot.
