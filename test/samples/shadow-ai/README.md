# Shadow AI detection — full sample

A self-contained sample that drives the **entire userspace shadow-AI pipeline**
over fixture events, with golden-file assertions. It is both the worked example
for the feature and the regression test for it.

Run it:

```sh
go test ./test/samples/shadow-ai/            # assert against the goldens
go test ./test/samples/shadow-ai/ -update    # regenerate the goldens, then READ THE DIFF
```

## What this actually runs

```text
fixtures/events.json  ->  collector.LoadEvents
                      ->  attribution.Index      cgroup id -> pod identity
                      ->  governed bit           from fixtures/aicontrols.json
                      ->  ai.Classifier          sets event.ai (class/provider/confidence/evidence)
                      ->  detect.Engine          policies from policies/*.yaml
                      ->  reporter.Finding  +  inventory.Rollup
```

Every box above is the real production code. The five `policies/*.yaml` are
compiled by the real `pkg/compiler`, including the event-time CEL `match`
predicates, so a policy that would be rejected in a cluster fails this test.

## What is substituted, and why

| Substituted | Real thing | Why |
| --- | --- | --- |
| `fixtures/events.json` via `collector.SyntheticSource` | BPF ring buffers from `pkg/bpf/{dnstrace,netflow,tlspeek,l7peek,exectrace}` | Those objects cannot be built on a host without `clang` and a generated `vmlinux.h`, so their `NewSource` reports `ErrSourceNotWired`. The **decoders** that would turn kernel bytes into these events are unit-tested in their own packages against byte fixtures. |
| `fixtures/aicontrols.json` proxy address set | `aicontrols.EndpointResolver` watching a Service + EndpointSlices | Keeps the golden test deterministic and free of a fake API server. The resolver's own tests cover the lookup, the refresh loop, and the enabled/disabled semantics. |
| A synthesized `metadata.uid` per policy | the API server's UID | Manifests on disk have no UID, and every consumer keys policies by it. |

## What does NOT run here

- **No kernel, no eBPF.** Nothing in this directory loads a program, attaches to
  a cgroup, or reads a map. The five new BPF programs have never been compiled or
  passed through the verifier on any machine that produced this branch.
- **No enforcement.** `policies/03-mcp-allowlist.yaml` says `mode: enforce`, and
  the engine deliberately downgrades it to monitor and records
  `AIEnforcementImplemented=False`. Blocking AI traffic (the proposal's
  compelled-routing phase) does not exist yet. A finding from that policy means
  "this would have been reported", not "this was blocked".
- **No cluster.** `kubectl`/chainsaw admission conformance for these policies is
  a separate CI lane; this test never contacts an API server.

## The redaction assertion

`fixtures/events.json` deliberately carries three canaries:

| Canary | Where |
| --- | --- |
| `Bearer sk-canary-XYZ` | an `Authorization` header |
| `canary-KEY-123` | an `X-Api-Key` header |
| `CANARY-PROMPT` | an LLM request body |

The test asserts that **none of them appear** in any finding, in the inventory,
or in any golden file — and then asserts, as a positive control, that they *are*
present in `events.json`. Without that control a passing scan would prove
nothing. Secret header values are already `REDACTED` by the time an event exists,
because `runtimeevent.NewHTTPFacts` is the only constructor and `UnmarshalJSON`
routes through it: even a hand-written fixture cannot smuggle a live credential
into the pipeline.

If a regeneration ever writes a canary into `expected/`, that is a **redaction
regression**, not golden drift. Do not update the golden.

## Files

| Path | What it is |
| --- | --- |
| `policies/01-ai-discovery.yaml` | `mode: discover`, all classes, all pods — inventory only |
| `policies/02-unsanctioned-llm.yaml` | approved-provider allowlist + `match` predicate + `minConfidence` |
| `policies/03-mcp-allowlist.yaml` | default-deny MCP with a stdio server allowlist (`mode: enforce`, downgraded) |
| `policies/04-a2a-discovery.yaml` | agent-card discovery leaving the cluster |
| `policies/05-degraded-metadata.yaml` | the metadata-only degraded case, so fidelity is expressible |
| `fixtures/pods.json` | 6 pods: labeled agent, unlabeled worker, Deployment-owned gateway, bare pod, MCP client, A2A broker |
| `fixtures/events.json` | hosted DNS/SNI, governed vs ungoverned flows, self-hosted Ollama/vLLM body shapes, MCP streamable-HTTP, MCP stdio argv, MCP config open, A2A well-known + JSON-RPC, non-AI controls, redaction canaries |
| `fixtures/aicontrols.json` | the proxy address set used for the governed bit |
| `expected/classifications.golden.json` | what the classifier decided per event |
| `expected/findings.golden.json` | findings, with volatile timestamps dropped |
| `expected/inventory.golden.json` | the per-workload discover-mode rollup |

The goldens are the specification of this feature's behavior. When a diff appears,
decide whether the new behavior is correct before accepting it.
