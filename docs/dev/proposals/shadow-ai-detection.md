# Proposal: Shadow AI Detection

| | |
| --- | --- |
| **Status** | Draft — for discussion, not accepted |
| **Scope** | Detecting LLM, MCP, and A2A traffic originating from a workload or pod |
| **Baseline** | Verified against `4a8bcb1`, assuming #32 (WorkloadProfile removal) lands |

## Purpose

"Shadow AI" here means unsanctioned or simply unknown AI usage by workloads in the cluster. This
document does two things: it records what the runtime can actually observe today, and it proposes
how to get from there to detecting three classes of traffic — LLM provider APIs, Model Context
Protocol, and Agent2Agent.

Part 1 is descriptive and overlaps [DESIGN.md](../DESIGN.md); it is included because the design
constraints it identifies are what dictate the proposal, and several of them are load-bearing.
Part 2 is the proposal proper.

The short version: three things this needs do not exist yet — a kernel-to-userspace **event
plane**, an **event-time CEL evaluator**, and a **finding sink**. None of them are AI-specific, all
three are prerequisites for #17 and #29 as well, and the recommendation is to build them as generic
layers with an AI classifier on top rather than as an "AI feature."

## Related issues

Bugs and gaps this proposal depends on or is blocked by, filed separately:

| Issue | Relevance |
| --- | --- |
| #17, #29 | Event delivery and reporting — the same pipeline this needs |
| #36, #37 | Panics in cgroup attribution; Phase 0 has to fix these to attribute events at all |
| #38 | Attribution only works on containerd/systemd nodes — caps coverage of everything below |
| #40 | `resource.toGVR()` panics from a policy; argues for a panic barrier before adding CEL surface |
| #41 | Egress targets are IPv4-only, which limits what hostname-based AI policy can enforce |
| #42 | `mode: monitor` is a no-op — §2.7 proposes making it real |
| #44 | Policy status is never written |
| #15 | No tests; §2.3 argues the classifier should be pure and table-tested |

## PHASE 1 — What the code actually does today

> This section describes `4a8bcb1` as it stands, **including** the WorkloadProfile / learning-mode /
> `ctrl` subsystem that #32 removes. It is left in because the constraints it documents (map-polling
> instead of event streaming, no reverse cgroup index, IPv4-only egress) are exactly what the
> proposal has to work around, and because the reasons that subsystem failed inform §2.7. Where a
> component is going away, the proposal below says so and does not build on it.

### 1.1 Repo layout / build

- Module `github.com/nirmata/kyverno-runtime`, `go 1.26.0` (`go.mod:1-3`).
- Key deps: `github.com/cilium/ebpf v0.21.0`, `github.com/google/cel-go v0.28.0`, `github.com/kyverno/sdk` (CEL libs), `github.com/openreports/reports-api v0.2.1`, `grpc`, `controller-runtime v0.24.1`, `k8s.io/apiserver` (for `k8s.io/apiserver/pkg/cel/library` + `lazy`). Tool directive: `github.com/cilium/ebpf/cmd/bpf2go` (`go.mod:35`).
- **No** inspektor-gadget, **no** containerd, **no** prometheus client in use — those were dropped in the `f806f25` "alpha release" rewrite. `github.com/prometheus/client_golang` is present only transitively.
- Two commands, one binary (`cmd/kyverno-runtime/root.go`):
  - `daemon` (`cmd/kyverno-runtime/daemon.go:37-165`) — per-node DaemonSet, privileged, `hostPID: true`, hostPath mounts of `/`, `/run`, `/sys/fs/bpf`, `/sys/kernel/debug`, `/sys/kernel/tracing` (`charts/kyverno-runtime/templates/daemonset.yaml:25-60`).
  - `ctrl` (`cmd/kyverno-runtime/wpcontroller.go:22-95`) — cluster-scoped WorkloadProfile controller, **disabled by default** (`charts/kyverno-runtime/values.yaml`, `ctrl.enabled: false`).
- eBPF C sources live in `pkg/bpf/*/_cprog/`, compiled via `//go:generate go tool bpf2go` and the resulting `*_bpfel.o` / `*_bpfeb.o` are **committed to the repo**. Note `pkg/bpf/lsm/_cprog/lsm.bpf.c:3` includes `include/vmlinux.h` which is *not* in the tree — so regenerating BPF objects requires generating vmlinux.h locally; the checked-in `.o` files are what actually ship.
- `pkg/bpf/traceopen/traceopen.go` is a **one-line empty package stub** (package declaration only) — dead placeholder.

### 1.2 API types (`api/v1alpha1/`)

`RuntimePolicy` (cluster-scoped, `rpol`, `api/v1alpha1/runtimepolicy_types.go:96-112`):

- `spec.podSelector` (`*metav1.LabelSelector`, :15)
- `spec.evaluationInterval` (:19)
- `spec.variables` (`[]admissionregistrationv1.Variable`, :23)
- `spec.behaviors []PolicyBehavior` (:27) — each item is **exactly one** of `network` | `exec` | `open`, enforced by a CRD-level XValidation (`:55`)
- `spec.mode *RuntimePolicyMode` — the commit `4a8bcb1` field; enum `monitor|enforce` (`:34-41`)
- `Behavior` = `{allow?: BehaviorRule, deny?: BehaviorRule}`; `BehaviorRule` = `{values []string, expression string}` (`:44-79`)
- `status`: `observedPods`, `violatingPods`, `lastEvaluatedTime` (`:82-94`) — **all three are declared but never written by any code**. Nothing in the repo updates RuntimePolicy status.
- DeepCopy is implemented via JSON round-trip (`:140-143`), not generated deepcopy.

`WorkloadProfile` (cluster-scoped, `wp`, `api/v1alpha1/workloadprofile_types.go:29-35`): `spec.behaviorsToLearn []string`, `spec.duration`, spec immutable via XValidation (`:9`); `status.ready` (never written). `behaviorsToLearn` is **not plumbed anywhere** — the reconciler sends `Labels: make(map[string]string) // todo` (`pkg/workloadprofile/workloadprofile_reconciler.go:169`), so learning is unscoped and `behaviorsToLearn` is ignored.

#### What `.mode` actually does (important for the shadow-AI design)

`mode` is compiled into `CompiledRuntimePolicy.mode` (`pkg/compiler/compiler.go:109-112`) → `EvaluationResult.Mode` (`pkg/compiler/policy.go:23,89`). Both managers then **early-return** if it isn't `enforce`:

- `pkg/egressmgr/runtimepolicies.go:16-18` (`rpCreated`), `:37-40` (`rpUpdated` treats non-enforce as delete)
- `pkg/lsmmgr/runtimepolicies.go:15-17`, `:74-78`

So **`mode: monitor` is a literal no-op today** — there is no monitor path, because there is no event/finding pipeline to emit to. This is the single biggest gap for the shadow-AI feature and also the biggest opportunity (see §2.7).

### 1.3 Enforcement/observation data path — it is eBPF, in a privileged DaemonSet. No sidecar, no webhook, no mesh

Two independent enforcement engines, both keyed on cgroup:

**(a) Egress IP filter** — `cgroup_skb/egress` program, `pkg/bpf/egressfilter/_cprog/probe.c:21-68`, attached per container cgroup path via `link.AttachCgroup(... AttachCGroupInetEgress ...)` (`pkg/bpf/egressfilter/egressfilter.go:150-160`).
What it sees: it casts `skb->data` to a hand-rolled `struct iphdr` (`probe.c:8-19`) and reads **`ip->daddr` only**. Maps (`_cprog/maps.h`): `banned_ips`, `allowed_ips` (hash u32→u8, 1024 entries), `flags` (bit 1 `DEFAULT_DENY`, bit 2 `LEARNING_MODE`), `ip_events` (hash u32→u32 counters for learning).
Consequences: **IPv4 only**, `To4()`-only normalization (`egressfilter.go:162-170` silently drops IPv6/CIDR/hostnames), **no L4 header parsing at all** (no dst port), no protocol check, no DNS, no TLS, no SNI, no HTTP. A separate `EgressFilter` instance (separate map set) is created **per pod** (`pkg/egressmgr/pods.go:18`), so the 1024-entry cap is per pod.

**(b) LSM enforcer** — `SEC("lsm/generic_handler")` (`pkg/bpf/lsm/_cprog/lsm.bpf.c:99-129`), one program instance per `RuntimePolicy`, `AttachTo` retargeted at load time to either `file_open` or `bprm_check_security` (`pkg/bpf/lsm/lsm.go:34-58`), dispatched by an `argtypes` map value.

- `handle_open` (`lsm.bpf.c:18-56`): `bpf_d_path()` on `file->f_path`, exact-match lookup in a 128-byte-key hash (`banned`/`allowed`), returns `-EPERM`.
- `handle_exec` (`lsm.bpf.c:58-97`): `BPF_CORE_READ(bprm, filename)` — **the binary path only, no argv**. Exact string match, 128-byte key.
- Scoping is `bpf_get_current_cgroup_id()` against a `cgids` map (`lsm.bpf.c:102-114`).
- **`bprm_check_security` is never actually instantiated**: `lsmmgr.rpCreated` hardcodes `lsm.NewForAttachTarget(&l.logger, "file_open")` and only looks at `compiledRp.Open` (`pkg/lsmmgr/runtimepolicies.go:19-24`). `EvaluationResult.Exec` is compiled and evaluated but **never consumed by any manager**. So `spec.behaviors[].exec` is dead end-to-end today, even though the BPF side supports it.

**Attribution** (`pkg/containers/containers.go`): `ResolveCgInfos(pod)` walks `pod.Status.ContainerStatuses`, strips the `<runtime>://` prefix, and `stat()`s candidate cgroupv2 paths (`:89-119`) to get `{ID: stat.Ino, Path: string}`. Only `cri-containerd-<id>.scope` shapes are built — **CRI-O / Docker shim naming is not handled** (`:104-115`), and cgroup v1 layout is a TODO (`:92`). Identity known per pod is `pod.UID` + `pod.Labels` (stored in `podAttachment.labels` / `podRepresentation.labels`); namespace/name/owner are *not* retained in the managers.

**Wiring**: `podWatcher` (`pkg/controller/podwatcher.go:53-117`) uses a field-selector-scoped informer `spec.nodeName=$NODE_NAME,status.phase=Running`; `RuntimePolicyMgr` (`pkg/controller/runtimepolicy_informer.go`) watches RuntimePolicies, compiles + evaluates, and fans out to `[]events.EventIface` (`pkg/events/iface.go:22-25`) — currently exactly `[em, lsmm]` (`cmd/kyverno-runtime/daemon.go:82-85`). `EventIface` has only two methods: `PodEvent` and `RuntimePolicyEvent`. **There is no "runtime event ingress" interface at all** — nothing flows kernel→userspace except polled learning counters.

### 1.4 CEL layer

- `pkg/compiler/env.go:13-40` `newBaseEnv()`: cel-go `ext.Bindings/Encoders/Lists/Math/Protos/Sets/Strings`, plus k8s `library.CIDR/Format/IP/Lists/Regex/URLs/Quantity/SemverLib`.
- `pkg/compiler/env.go:42-53` `newEnv()` — the commit `75afe1e` addition: `http.Lib(http.Context{...http.NewHTTP()}, http.Latest())`, `resource.Lib(resource.Context{newResourceProvider(client)}, "", resource.Latest())`, `json.Lib(&json.JsonImpl{}, json.Latest())` from `github.com/kyverno/sdk/extensions/cel/libs/...`.
- Exposed to authors: `http.get(url[,headers])`, `http.post(...)`, `http.client(...)`; `resource.get(apiVersion, resource, ns, name)`, `resource.list(...)`, `resource.post(...)`; `json.unmarshal/marshal`. Backing impl for `resource` is `pkg/compiler/resourceprovider.go` (note `ToGVR` **panics** — `:56-59`).
- `variables` is the **only** custom variable in the env (`pkg/compiler/compiler.go:52`, `pkg/compiler/variables.go:11`), a lazily-evaluated struct built via `lazy.NewMapValue` (`pkg/compiler/policy.go:39-55`).
- **Critical shape constraint**: every behavior `expression` must statically type as `list(string)` (`pkg/compiler/compiler.go:143,161`), and evaluation happens *policy-time, not event-time* — `Evaluate(ctx)` produces a static `AllowDenyPair` of strings that gets stuffed into BPF maps. There is **no per-event CEL evaluation anywhere**. `evaluationInterval` re-runs the whole expression on a ticker (`pkg/controller/runtimepolicy_informer.go:309-343`). This is the structural fact that dictates the shadow-AI design: matching an HTTP request against a predicate cannot be done with today's compiler shape.
- No `pod`/`event`/`request` CEL variable exists. Comments acknowledge this: "*if there was an object variable, this function would need to be pod aware*" (`runtimepolicy_informer.go:308`).

### 1.5 Existing network awareness — precisely

| Capability | Status |
| --- | --- |
| Destination IPv4 address (egress) | **Yes** — `probe.c:34`, allow/deny + learning counters |
| Destination port / L4 | **No** — L4 header never parsed |
| IPv6 | **No** — `To4()` drops it (`egressfilter.go:164`) |
| CIDR / hostname targets | **No** — parse fails, entry silently skipped |
| DNS (query names, responses) | **No** — nothing anywhere |
| TCP connect events (`connect`/`tcpconnect`) | **No** — removed with inspektor-gadget; only `Agents.md:61` still references it |
| TLS SNI / ALPN / JA3 | **No** |
| HTTP request line / headers / body | **No** |
| Egress "learning" | **Yes but IP-only** — `ip_events` map → `EgressFilter.ReadLearned()` → `egressmgr.Read()` → gRPC `ReadResponse.network map<uint32,uint32>` (`proto/learning.proto:43`) — raw little-endian u32 IPs, not even stringified |
| Kubernetes service/endpoint → IP resolution | **No** (the `EndpointSlice` informer in `pkg/controller/endpointslice_informer.go` is only used to find *daemon pod IPs* for gRPC fan-out) |

So: today there is **zero** protocol-layer network visibility. Everything for shadow AI beyond "this pod talked to 160.79.104.10" is net-new.

### 1.6 Findings / violations / events emission

There is effectively **none**:

- No OpenReports writer. `openreportsv1alpha1.Install(scheme)` is called in both commands (`daemon.go:65`, `wpcontroller.go:59`) and the chart ships `openreports.io_reports.yaml` / `clusterreports.yaml` CRDs, but **no Go code creates, reads, or updates a `Report`**. `grep -rn "openreports" pkg/` → nothing.
- No metrics registration (only controller-runtime's default `/metrics` on the `ctrl` deployment, `wpcontroller.go:65`).
- No Kubernetes Events, no status writes, no webhooks/sinks.
- The only observable output is (a) `logger.V(2)` lines, (b) `-EPERM`/packet-drop side effects, (c) the learning-mode read path: HTTP `learningModeSrv.ServeHttp` (`pkg/srv/srv.go:36-93`) fanning out gRPC `Read` to daemons (`pkg/srv/grpc.go:51-78`), merging counter maps. That HTTP handler isn't even wired to a listener in `daemon.go`.
- The whole prior reporter/metrics design (fingerprint dedup, truncation, `kyverno_runtime_reporter_*` counters) existed pre-`f806f25` and was **deleted**; it survives only in git history (`git show f806f25^:docs/dev/DESIGN.md`).

### 1.7 Docs / roadmap in-repo

- `README.md`, `docs/runtimepolicy.md` (391 lines, spec + CEL library examples), `docs/workloadprofile.md` (marked experimental).
- `Agents.md:3` points at `docs/dev/DESIGN.md` and `docs/dev/PLAN.md` — **both deleted in `f806f25`**. `Agents.md:59-66` still encodes filtering rules for `connect`/`tcpconnect` events that no longer exist. Those docs are stale and should be rewritten as part of this work.
- The deleted `PLAN.md` is still the best statement of intent and explicitly lists **`dns` (trace_dns) = Planned** and **`http` (trace_http) = Future** — i.e. shadow-AI detection is directionally on the old roadmap, and DNS was already the intended next signal.

---

## PHASE 2 — Shadow-AI detection: implementation plan

### 2.0 Design premise

Three things must be built that don't exist: **(1) an event plane** (kernel→userspace streaming, currently absent — everything is map-polling), **(2) an event-time CEL evaluator** (currently CEL only produces static string lists at policy time), **(3) a finding sink** (currently absent). Shadow-AI detection is the forcing function for all three, and they are reusable well beyond it. I recommend building them as first-class, generic layers rather than as an "AI feature," with an AI-specific *classifier* on top.

### 2.1 Detection signals per class, ranked fidelity vs. cost

#### Class 1 — LLM API traffic

| Tier | Signal | Fidelity | Cost | Survives TLS |
| --- | --- | --- | --- | --- |
| A | DNS query name (`api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `*-aiplatform.googleapis.com`, `bedrock-runtime.*.amazonaws.com`, `*.openai.azure.com`, `api.mistral.ai`, `api.cohere.com`, `openrouter.ai`) | High for hosted providers; zero for self-hosted-by-IP | Very low (one uprobe-free tracepoint/socket filter on 53) | **Yes** |
| A | TLS ClientHello SNI | High; authoritative for the actual connection (DNS can be cached/shared) | Low (parse first TX segment on 443) | **Yes** |
| B | dst IP → provider prefix / ASN (Cloudflare, Azure, GCP, AWS) | Medium; provider CDNs are shared, high FP rate alone | Very low (already have dst IP) | **Yes** |
| B | dst port + ALPN (`h2`) + JA3/JA4 hash | Low alone; useful as SDK fingerprint corroboration | Low | **Yes** |
| C | HTTP request line + `Host` + path (`POST /v1/messages`, `/v1/chat/completions`, `/v1/complete`, `/v1beta/models/*:generateContent`, `/model/*/invoke`, `/api/generate`, `/api/chat`) | **Very high** — path shape alone identifies the API family | Needs plaintext | No |
| C | Headers: `anthropic-version`, `x-api-key`, `api-key` (Azure), `OpenAI-Organization`, `Authorization: Bearer sk-…`, `User-Agent: Anthropic/Python …`, `openai-python/…`, `AWS4-HMAC-SHA256 … bedrock` | **Very high** + tells you *which SDK* | Needs plaintext | No |
| C | Body shape: `{"model": …, "messages":[…], "max_tokens":…, "stream":true}` | Highest — catches self-hosted OpenAI-compatible (vLLM/Ollama/LM Studio) with no recognizable hostname | Needs plaintext, parsing cost | No |
| D | Process/library fingerprint: `openat` of `…/site-packages/anthropic/…`, `…/openai/…`, `…/langchain*/…`, `node_modules/@anthropic-ai/sdk`, `…/ollama`; `readlink /proc/pid/maps` for `libssl` version | Medium-high as *inventory* signal, not per-connection | Low — **`file_open` LSM hook already exists** | **Yes (not network at all)** |
| D | Plaintext HTTP on non-443 (Ollama `:11434`, vLLM `:8000`) | High and **free** — self-hosted endpoints are overwhelmingly plaintext in-cluster | Low | N/A |

**Key insight**: the *hosted* providers are cheaply covered by DNS+SNI. The *self-hosted / OpenAI-compatible* case — arguably the truest "shadow AI" — is mostly **plaintext on a non-standard port**, which needs no TLS interception. So an 80/20 exists: DNS+SNI+plaintext-HTTP-on-any-port covers a large majority without touching TLS.

#### Class 2 — MCP traffic

Two transports, two entirely different signal classes:

**2a. Remote (streamable HTTP / SSE)** — needs plaintext for anything definitive:

- `Accept: text/event-stream` **combined with** `Content-Type: application/json` on a `POST` — strong MCP-streamable-HTTP signature.
- Headers `MCP-Session-Id`, `MCP-Protocol-Version` — essentially conclusive.
- JSON-RPC body: `{"jsonrpc":"2.0","method":"initialize"|"tools/list"|"tools/call"|"resources/read"|"prompts/get"|"notifications/initialized"}` — `method` prefix `tools/`, `resources/`, `prompts/`, `sampling/`, `roots/` is conclusive.
- Path conventions `/mcp`, `/sse`, `/messages` — weak alone.
- Metadata-only fallback: long-lived TCP connection with server→client-dominated small-packet bursts and `h2`/`h1` on a non-provider host = "suspected streaming RPC", low fidelity.

**2b. Local stdio** — **process signal, no network at all**. Highest-value/lowest-cost item in the whole plan because it needs an exec hook, and the LSM exec hook is already written and unused:

- `execve` of `npx`/`npm exec` with an arg matching `@modelcontextprotocol/server-*`, `mcp-server-*`, `*-mcp`
- `uvx <pkg>` / `uv run`, `pipx run`, `python -m mcp*`, `node …/dist/index.js` under an `@modelcontextprotocol` path
- `docker run … mcp/…`
- **Requires argv**, which the current BPF exec handler does not read (`lsm.bpf.c:62` reads only `bprm->filename`). Reading argv from `bprm` in an LSM hook means walking `bprm->mm->arg_start..arg_end` — doable but fiddly; alternative is a `sched_process_exec` tracepoint (observe-only) which gives argv far more cheaply. **Recommend: tracepoint for observation, LSM for blocking, and only add argv to LSM when blocking-by-argv is actually required.**
- Corroborating: parent process is an agent runtime; child holds pipe fds (stdio) not sockets; `open` of `~/.config/…/mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json` — configuration discovery, catchable with the **existing `file_open` hook today**.

#### Class 3 — A2A traffic

- `GET /.well-known/agent.json` or `/.well-known/agent-card.json` — **conclusive** and cheap to match on the request line. Also `/.well-known/agent-card` variants; treat the whole `/.well-known/agent*` prefix as a match.
- JSON-RPC `method` in `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`, `tasks/pushNotificationConfig/*`, `agent/getAuthenticatedExtendedCard` — conclusive.
- Response body containing an agent card (`{"protocolVersion":…,"skills":[…],"capabilities":{…}}`) — requires response-side plaintext.
- Metadata-only: none usable. A2A over HTTPS to an arbitrary host is indistinguishable from any other HTTPS. **A2A is plaintext-or-nothing.**

### 2.2 The TLS problem

**Survives encryption:** DNS query names; TLS ClientHello **SNI** (plaintext in the handshake, absent ECH); **ALPN** (plaintext in ClientHello, absent ECH); dst IP/port; JA3/JA4 client fingerprint; packet size/timing/direction (weakly indicative of streaming); certificate SAN in the ServerHello (TLS 1.2 only — encrypted in 1.3).

**Requires plaintext:** HTTP method/path, all headers (`anthropic-version`, `MCP-Session-Id`, `MCP-Protocol-Version`, `Accept: text/event-stream`, `Authorization` scheme, `User-Agent`), JSON-RPC method names, request/response body shape, `model` field, token counts.

Options:

**(A) eBPF uprobes on TLS library write/read.** Attach uretprobe/uprobe to `SSL_write`/`SSL_read` (OpenSSL/BoringSSL), `gnutls_record_send/recv`, `NSS PR_Write`. Grab the buffer + length, stream via ring buffer.

- Pros: no traffic redirect, no cert handling, no MITM, works for Python/Node/Java/Ruby (all use OpenSSL or a shared lib), gives request *and* response, plus PID→cgroup attribution for free.
- Cons: needs per-container binary discovery (the lib lives in the container's mount ns — resolvable via `/proc/<pid>/root/...`, which the daemon already can reach given `hostPID` + hostPath `/`), symbol offsets vary by build, statically-linked/musl/distroless images break it, attach must happen on container start and re-attach on exec, and OpenSSL 3.x + `SSL_write_ex` variants multiply targets.
- **Go is the hard case**: Go's `crypto/tls` is pure Go and statically linked; there is no `SSL_write` symbol. You must uprobe Go symbols directly — `crypto/tls.(*Conn).Write` / `.Read` (or better `(*Conn).writeRecordLocked`) — resolved per-binary from the ELF symbol table (`.gopclntab`/`.symtab`), which requires: (i) reading the binary out of `/proc/<pid>/root/<exe>`, (ii) handling stripped binaries (`-ldflags="-s -w"` removes `.symtab` but **`.gopclntab` survives** — that's the reliable path, same trick eBPF-based tools use), (iii) **Go register ABI (go1.17+) puts args in registers, not stack**, so arg extraction is arch+ABI+Go-version dependent, and (iv) return-value probes on Go are hazardous because goroutine stack growth invalidates classic uretprobes — you must probe the return *address sites* instead. This is real, well-trodden, and expensive engineering. **For Go workloads, budget several weeks and expect version-fragility.**

**(B) Sidecar / service mesh TLS termination.** Route egress through an Envoy/Istio egress gateway with `ORIGINATE`/`TLS origination`, so the app speaks plaintext to the sidecar.

- Pros: full L7 fidelity including bodies, mature, no kernel work, works for Go/static/anything.
- Cons: requires a mesh or injection (this project is deliberately agentless-in-the-pod today — the daemon is a DaemonSet), only covers meshed namespaces, changes the trust model, adds latency and a large operational surface, and is trivially bypassed by any pod not in the mesh. **Fundamentally at odds with this codebase's architecture.** Reject as primary; support as an *optional* enrichment source.

**(C) Explicit forward proxy with CONNECT.** Set `HTTPS_PROXY` (or transparently redirect 443 to a node-local proxy) and either (c1) read `CONNECT host:443` — metadata only, equivalent to SNI, or (c2) MITM with a trusted CA injected into every pod's trust store.

- Pros: (c1) is trivial and gives you the hostname with zero kernel work; (c2) gives full plaintext including Go.
- Cons: (c1) adds nothing over SNI; (c2) needs CA distribution into every container, breaks pinned clients and mTLS, is a high-value MITM target holding every workload's API keys in plaintext, and is bypassed by ignoring `HTTPS_PROXY`. **Reject (c2)** for a security-posture product; a MITM proxy that decrypts every LLM prompt in the cluster is a worse liability than the shadow AI it detects.

**(D) Accept metadata-only.** DNS + SNI + IP + port + ALPN + JA3 only.

- Covers: all hosted LLM providers (high confidence), plaintext self-hosted (fully, since plaintext needs no interception), remote MCP/A2A to *known* hostnames (host-level only, cannot distinguish MCP from ordinary API traffic to the same host).
- Misses: MCP/A2A discrimination on arbitrary HTTPS hosts, model names, token volumes, prompt content.

#### Recommendation

**Tiered, in this order:**

1. **Ship (D) first** — DNS + SNI + connect-with-port + plaintext HTTP parsing. This is one collector, no uprobes, no per-binary symbol work, no MITM, and it already delivers: full hosted-provider LLM inventory, full self-hosted/Ollama/vLLM detection (plaintext), plaintext MCP/A2A detection, and the `.well-known/agent.json` signal for in-cluster A2A. Plus the **stdio-MCP exec signal**, which is orthogonal and cheap.
2. **Then (A), OpenSSL/BoringSSL uprobes only**, opt-in per namespace/workload via policy. This covers Python and Node — which is where essentially all LLM/MCP/A2A client code lives today. Deliberately defer Go.
3. **Then (A) for Go**, via `.gopclntab` symbol resolution, opt-in, clearly labelled experimental, with a documented fallback to metadata-only.
4. **Never (c2)**. Offer (B) only as an optional external enrichment input (e.g. accept L7 records from an Envoy access-log tap) for users who already run a mesh.

Rationale: fidelity per engineering-week is dramatically higher for tier 1, and tier 1 is a hard prerequisite for the pipeline that tiers 2–3 feed anyway. Also, encryption-surviving signals are the *evasion-resistant* ones — an attacker can avoid a recognizable User-Agent far more easily than they can avoid a DNS lookup or an SNI.

### 2.3 Where the code changes go

#### Net-new packages

```text
pkg/bpf/netflow/            NET-NEW  cgroup_skb/egress + sock_ops or kprobe/tcp_connect;
  _cprog/netflow.bpf.c               emits {cgid, saddr, daddr, dport, proto} to a BPF_MAP_TYPE_RINGBUF
  netflow.go                         Go side: bpf2go binding + ringbuf reader

pkg/bpf/dnstrace/           NET-NEW  socket-filter or tc-egress program parsing UDP/53 (+ TCP/53) queries
  _cprog/dns.bpf.c                   emits {cgid, qname[253], qtype} to ringbuf
  dnstrace.go

pkg/bpf/tlspeek/            NET-NEW  cgroup_skb/egress, first N bytes of a new flow: detect TLS
  _cprog/tlspeek.bpf.c               ClientHello, extract SNI + ALPN + JA4 material -> ringbuf
  tlspeek.go

pkg/bpf/l7peek/             NET-NEW  plaintext HTTP on any port: first N bytes of flow ->
  _cprog/l7peek.bpf.c                request line + headers (bounded, e.g. 2KB) -> ringbuf
  l7peek.go

pkg/bpf/exectrace/          NET-NEW  tracepoint/sched/sched_process_exec, argv[0..N] + comm + ppid + cgid
  _cprog/exec.bpf.c                  -> ringbuf. Observation-only; complements the LSM exec hook.
  exectrace.go

pkg/bpf/ssltrace/           NET-NEW  PHASE 3+: uprobe SSL_write/SSL_read (and Go crypto/tls)
  _cprog/ssl.bpf.c
  ssltrace.go
  elf/                               symbol resolution: OpenSSL dynsym + Go .gopclntab

pkg/runtimeevent/           NET-NEW  the normalized event plane. This is the keystone.
  event.go                           type Event struct { Kind; Time; CgroupID; PID; Comm;
                                       Net *NetFacts; DNS *DNSFacts; TLS *TLSFacts;
                                       HTTP *HTTPFacts; Exec *ExecFacts; Pod PodIdentity }
  iface.go                           type Source interface { Run(ctx, chan<- Event) error }
                                     type Sink   interface { Handle(Event) }

pkg/collector/              NET-NEW  owns all Sources, one ringbuf reader goroutine per program,
  collector.go                       per-cgroup attach/detach driven by the existing PodEvent path,
  attach.go                          backpressure + drop counters

pkg/attribution/            NET-NEW  cgid -> {podUID, ns, name, labels, container, ownerRef}
  index.go                           reverse index maintained from podWatcher events;
                                     also pid -> cgid via /proc/<pid>/cgroup for uprobe events

pkg/detect/                 NET-NEW  the AI classifier. Pure functions over runtimeevent.Event.
  ai/providers.go                    provider catalog: hostname patterns, path patterns, header
                                     names, port defaults. Data-driven, hot-reloadable from a ConfigMap.
  ai/llm.go                          LLM classification + confidence scoring
  ai/mcp.go                          MCP: HTTP/SSE detection + stdio exec detection
  ai/a2a.go                          A2A: .well-known + JSON-RPC method detection
  ai/jsonrpc.go                      bounded JSON-RPC method sniffing (no full parse)
  classify.go                        Event -> *AIFacts (nil if not AI-related)

pkg/reporter/               NET-NEW  finding sink: OpenReports Report/ClusterReport writer with
  reporter.go                        fingerprint dedup + count/firstSeen/lastSeen. Re-establishes
  fingerprint.go                     what f806f25 deleted; see git show f806f25^:docs/dev/DESIGN.md
                                     for the prior contract (dedup, truncation annotation, caps).

pkg/inventory/              NET-NEW  discovery-mode aggregation: per-workload AI inventory,
  inventory.go                       feeds AIInventory CR status + a `kubectl` friendly view

pkg/metrics/                NET-NEW  prometheus collectors (events, drops, findings by class)
```

#### Extends existing

- `pkg/events/iface.go:22-25` — **extend `EventIface`** or, cleaner, leave it alone and add a parallel `runtimeevent.Sink` set; the existing interface is policy/pod-lifecycle-shaped and shouldn't be overloaded with per-packet events.
- `pkg/compiler/env.go:42-53` — register the new `ai` and `net` CEL libs alongside `http`/`resource`/`json`.
- `pkg/compiler/compiler.go:74-102` — extend the behavior switch for the new behavior kinds; **and add a second compilation mode** that produces a `bool`-typed predicate program rather than a `list(string)` (see §2.4).
- `pkg/compiler/policy.go:17-24` — `EvaluationResult` gains the compiled predicate + the parsed AI rule set.
- `api/v1alpha1/runtimepolicy_types.go:56-68` — new `PolicyBehavior` member and its XValidation update (`:55` currently hardcodes "exactly one of network, exec, or open").
- `pkg/containers/containers.go:89-119` — needs CRI-O/Docker path templates and a `/proc/<pid>/cgroup`-based fallback, because uprobe/tracepoint events arrive with a PID and the current code only maps pod→cgroup, never cgroup→pod or pid→pod.
- `pkg/lsmmgr/runtimepolicies.go:24` — instantiate the **`bprm_check_security`** target that already exists in `pkg/bpf/lsm/lsm.go:54-58` and wire `compiledRp.Exec` (currently computed and thrown away) so exec allow/deny becomes real. Needed for *blocking* stdio MCP.
- `cmd/kyverno-runtime/daemon.go:82-85` — construct the collector + attribution index + classifier + reporter and add them to the wiring.
- `charts/kyverno-runtime/templates/clusterrole.yaml` — add `openreports.io: reports, clusterreports` create/update/patch for the daemon (currently daemon RBAC is pods+runtimepolicies read-only).
- No gRPC transport work is proposed. #32 deletes `proto/learning.proto`, `pkg/srv`, and `pkg/controller/endpointslice_informer.go`, so there is no cross-daemon RPC path left to extend — and the old one carried raw little-endian `u32` IPs in a `map<uint32,uint32>`, which was never an adequate shape for inventory anyway. Daemons should write their own inventory shard directly to the API instead (see §2.7).

#### What the eBPF changes look like concretely

The existing programs are **map-lookup enforcers with no event channel**. Every new signal needs the opposite: a **ring buffer**. Concretely:

1. `netflow.bpf.c`: reuse the `cgroup_skb/egress` attach point already proven in `pkg/bpf/egressfilter/egressfilter.go:150-160`, but parse past the IP header into TCP/UDP to get `dport`, and on SYN (or on first data segment) push a `struct flow_event` to a `BPF_MAP_TYPE_RINGBUF`. Note the current `probe.c:8-19` declares its own `iphdr` with `ihl_version` packed — must compute IHL properly to find the L4 offset instead of assuming 20 bytes.
2. `tlspeek.bpf.c`: same attach point; keep a small per-flow state map (`{cgid,saddr,daddr,dport}` → bytes-seen) and on the first data segment, if `data[0]==0x16 && data[1]==0x03`, walk the ClientHello extensions for `server_name` (0x0000) and `alpn` (0x0010). Bounded loops with `#pragma unroll` and explicit `data_end` bounds checks on every read — the verifier will be the hard part, and TLS records can span segments (handle "ClientHello not in first segment" by giving up rather than reassembling in the kernel).
3. `dns.bpf.c`: cheapest useful program. On UDP dport 53 egress, parse the QNAME label sequence (bounded, ≤253 bytes, unrolled). Emit `{cgid, qname, qtype}`.
4. `l7peek.bpf.c`: on first data segment of a non-TLS flow, copy up to 2KB to the ring buffer and let **userspace** parse the request line + headers. Do not parse HTTP in BPF — the verifier cost is not worth it and userspace has `net/http`'s `textproto` reader.
5. `exec.bpf.c`: `tracepoint/sched/sched_process_exec` gives `filename` cheaply; argv needs reading `mm->arg_start`/`arg_end` via `bpf_probe_read_user` with a bounded loop. Emit first ~8 args, ~128B each.

Filtering must happen **in the kernel**, keyed on the same `cgids`-style map pattern already used at `lsm.bpf.c:111-114`, so only selected pods generate events. Otherwise a node-wide ring buffer of every egress packet will melt.

#### How a detector plugs into the pipeline

```text
BPF ringbufs ──> pkg/collector (one reader goroutine per program)
                     │  raw structs
                     ▼
              pkg/attribution  (cgid|pid -> PodIdentity, from podWatcher)
                     │  runtimeevent.Event (normalized, attributed)
                     ▼
              pkg/detect/ai.Classify(Event) -> *AIFacts
                     │
                     ├──> pkg/inventory   (mode: discover — aggregate, no findings)
                     ├──> pkg/policy eval (mode: monitor|enforce — event-time CEL predicate)
                     │        │
                     │        ├─ monitor ──> pkg/reporter (OpenReports) + metrics + k8s Event
                     │        └─ enforce ──> egressfilter.AddIps / lsm deny / (future) socket kill
                     └──> pkg/metrics
```

`pkg/detect` is a pure library (easy to unit-test with table-driven fixtures, no kernel needed) — this matters because BPF paths can't be tested in CI (`f9ec2c5` "replace eBPF-dependent E2E assertions with install gate" shows CI already can't run them).

### 2.4 Policy surface

#### The compiler problem, and the fix

Today `expression` must be `list(string)` evaluated at *policy* time (`pkg/compiler/compiler.go:143`). AI detection is inherently *per-event*: "this request had header X and path Y." So a second expression kind is needed: a **boolean predicate over an `event` variable**, compiled once and evaluated per event.

Add to `pkg/compiler`:

- `newEventEnv()` in `pkg/compiler/env.go` — same base env, plus `cel.Variable("event", AIEventType)` and the new `ai` lib.
- `compileMatchExpression()` in `pkg/compiler/compiler.go` asserting `types.BoolType` instead of `types.NewListType(types.StringType)`.
- Keep `http`/`resource` **out** of the event env — a per-event CEL program must not make network or API calls. This is a hard constraint: those libs are fine at policy-evaluation time (every 5m) and catastrophic at 10k events/s.

#### CRD additions (`api/v1alpha1/runtimepolicy_types.go`)

```go
// PolicyBehavior gains:
//   AI *AIBehavior `json:"ai,omitempty"`
// and the XValidation at :55 becomes a 4-way exactly-one check.

type AIBehavior struct {
    // Classes restricts which traffic classes this rule considers.
    // +kubebuilder:validation:items:Enum=llm;mcp;a2a
    Classes []AITrafficClass `json:"classes,omitempty"`

    // Allow / Deny use destination identities: hostnames (glob), CIDRs,
    // "provider:<name>" tokens resolved from the provider catalog,
    // or "mcp-server:<npm-package>" for stdio servers.
    Allow *BehaviorRule `json:"allow,omitempty"`
    Deny  *BehaviorRule `json:"deny,omitempty"`

    // Match is a boolean CEL predicate over the per-event `event` variable.
    // Evaluated per detected AI event, not at policy-evaluation time.
    // +optional
    Match string `json:"match,omitempty"`

    // MinConfidence gates findings by classifier confidence (0-100).
    // +optional
    MinConfidence *int32 `json:"minConfidence,omitempty"`

    // Severity for emitted findings.
    // +kubebuilder:validation:Enum=info;low;medium;high;critical
    Severity string `json:"severity,omitempty"`
}
```

And extend the mode enum (`:35`) to `monitor;enforce;discover` — see §2.7.

#### Realistic YAML

#### (1) Inventory / discovery — "what AI is my cluster using"

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: ai-discovery
spec:
  mode: discover              # no findings, no enforcement: populate inventory only
  podSelector: {}             # all pods
  behaviors:
  - ai:
      classes: [llm, mcp, a2a]
```

#### (2) Alert on any LLM egress not on the approved provider list

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: unsanctioned-llm-egress
spec:
  mode: monitor
  evaluationInterval: 15m     # refreshes the ConfigMap-sourced allowlist
  podSelector:
    matchLabels:
      ai.nirmata.io/workload: "true"
  variables:
  - name: approved
    expression: >-
      resource.get("v1", "configmaps", "kyverno-runtime", "approved-ai-providers")
        .data["providers"].split(",")
  behaviors:
  - ai:
      classes: [llm]
      severity: high
      minConfidence: 60
      allow:
        values: ["provider:anthropic", "provider:bedrock"]
        expression: "variables.approved"      # unioned, same semantics as today
      match: >-
        event.ai.class == "llm" &&
        !(event.ai.provider in ["anthropic", "bedrock"]) &&
        event.ai.confidence >= 60
```

Note this reuses the existing `values` + `expression` union semantics (`docs/runtimepolicy.md:17-32`) and the existing `resource` lib + `evaluationInterval` pattern (`docs/runtimepolicy.md:239-277`) verbatim — no new concepts for the author.

#### (3) Block MCP connections to non-allowlisted servers

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: mcp-allowlist
spec:
  mode: enforce
  podSelector:
    matchLabels:
      app: agent-runtime
  behaviors:
  - ai:
      classes: [mcp]
      severity: critical
      deny:
        values: ["*"]                       # default-deny, same sentinel as today
      allow:
        values:
        - "mcp.internal.corp"               # remote HTTP/SSE MCP
        - "mcp-server:@modelcontextprotocol/server-filesystem"   # stdio, allowed
        - "mcp-server:@modelcontextprotocol/server-git"
  # enforcement of remote MCP resolves allowed hostnames -> IPs and programs
  # the existing egress allow map; stdio enforcement uses the LSM exec hook.
```

#### (4) A2A: detect agent-card discovery leaving the cluster

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: external-a2a-discovery
spec:
  mode: monitor
  podSelector: {}
  behaviors:
  - ai:
      classes: [a2a]
      severity: medium
      match: >-
        event.http.path.startsWith("/.well-known/agent") &&
        !cidr("10.0.0.0/8").containsIP(event.net.destIP)
```

(`cidr()`/`containsIP` come from the already-registered `library.CIDR()` at `pkg/compiler/env.go:31`.)

#### (5) Metadata-only degraded mode is expressible, so users can reason about fidelity

```yaml
  behaviors:
  - ai:
      classes: [llm]
      severity: low
      match: >-
        event.ai.evidence == "sni" &&      # no plaintext available for this flow
        event.ai.provider == "unknown" &&
        event.net.destPort == 443
```

### 2.5 New CEL libraries / variables

**`event` variable** (new, event-env only) — an object type registered via a provider analogous to `pkg/compiler/variables.go`'s `variablesProvider`:

```text
event.kind                     string   "net"|"dns"|"tls"|"http"|"exec"
event.time                     timestamp
event.pod.namespace/.name/.uid string
event.pod.labels               map(string,string)
event.pod.container            string
event.workload.kind/.name      string   from ownerRef
event.process.pid              int
event.process.comm             string
event.process.argv             list(string)
event.net.destIP               string   (feed to library.IP()/CIDR())
event.net.destPort             int
event.net.protocol             string
event.dns.qname                string
event.tls.sni                  string
event.tls.alpn                 list(string)
event.tls.ja4                  string
event.http.method/.path/.host  string
event.http.headers             map(string,string)   lowercased keys
event.http.bodyPreview         string               bounded, redaction-aware
event.ai.class                 string   "llm"|"mcp"|"a2a"|""
event.ai.provider              string   "anthropic"|"openai"|"self-hosted"|"unknown"
event.ai.model                 string   when plaintext body available
event.ai.endpointKind          string   "messages"|"chat.completions"|"generateContent"|
                                        "mcp.streamable-http"|"mcp.stdio"|"a2a.agent-card"|…
event.ai.jsonrpcMethod         string   "tools/call", "message/send", …
event.ai.transport             string   "https"|"http"|"stdio"|"sse"
event.ai.confidence            int      0-100
event.ai.evidence              list(string)  ["dns","sni","http-path","header:anthropic-version"]
event.ai.sanctioned            bool     catalog lookup result
```

**`ai` CEL lib** (net-new, `pkg/compiler/libs/ai/`, mirroring the `kyverno/sdk` lib shape at `extensions/cel/libs/json/lib.go`):

```text
ai.isProvider(host, provider)  bool    catalog-aware host matching
ai.provider(host)              string  host -> provider name ("" if unknown)
ai.isLLMPath(path)             bool    /v1/messages, /v1/chat/completions, …
ai.isMCPMethod(method)         bool    tools/*, resources/*, prompts/*, sampling/*
ai.isA2AMethod(method)         bool    message/*, tasks/*
ai.isMCPServerPackage(arg)     bool    @modelcontextprotocol/server-*, *-mcp, mcp-server-*
ai.classify(event)             AIFacts recompute with policy-supplied overrides
```

Keeping the catalog behind functions (rather than inlining regexes in every policy) means provider coverage ships as data — a ConfigMap the classifier hot-reloads — so adding "Groq" or "Fireworks" is a config change, not a release.

### 2.6 Attribution

**Kernel-side events carry `cgroup_id` and `pid`. Today the code only maps pod→cgroup, never the reverse.** `pkg/containers/containers.go:68-87` computes `{ID: stat.Ino, Path}` per container and `ExtractCgids` (`:60-66`) hands them to BPF maps; nobody keeps a reverse index.

`pkg/attribution` (net-new) maintains, driven off the *existing* `podWatcher` fan-out (`pkg/controller/podwatcher.go:186-193`):

```text
cgroupID(uint64) -> PodIdentity{ podUID, namespace, name, labels,
                                containerName, containerID, ownerKind, ownerName, nodeName }
```

- Populated in a new `EventIface` implementation added to the `eventHandlers` slice at `cmd/kyverno-runtime/daemon.go:85` — this is a clean extension point: `PodEvent(pod, cgInfos, create)` already delivers exactly `{pod, []ContainerCgroupInfo}`.
- For uprobe-sourced events (which have a PID but possibly a stale cgid), fall back to reading `/proc/<pid>/cgroup` — available because the daemon runs with `hostPID: true` and mounts `/` (`daemonset.yaml:26,52-54`).
- Owner resolution (`Deployment`/`StatefulSet`/`CronJob` name) needs `ownerReferences` traversal, which needs ReplicaSet read RBAC — a new ClusterRole rule.
- **Two existing bugs to fix here**: `cgroupInfoFromContainer` only builds `cri-containerd-*.scope` paths (`:104-115`), so CRI-O and Docker nodes get zero attribution; and `containerID` parsing does `strings.SplitN(...)[1]` (`:74`) which **panics** if `ContainerID` is empty (a container that isn't running yet — the exact case the TODO at `:40-42` flags). Attribution failures currently manifest as "policy silently doesn't apply."
- **No WorkloadProfile tie-in.** An earlier draft of this proposal hung AI discovery off
  `WorkloadProfileSpec.BehaviorsToLearn`. That is no longer available: #32 removes `WorkloadProfile`,
  the learning-mode gRPC API, and the `ctrl` component outright, because pod targeting was a no-op
  and `behaviorsToLearn` was read by nothing (#43). Discovery mode in §2.7 is therefore proposed as
  a `RuntimePolicy` mode plus a dedicated inventory CR, with no dependency on the removed
  subsystem — which is the better factoring anyway, since it keeps discovery on the same object
  users already write policy against.

### 2.7 Reporting, and the `.mode` tie-in

#### Finding contents

A shadow-AI finding (an OpenReports `ReportResult`, namespaced `Report` in the workload's namespace):

```text
policy:      unsanctioned-llm-egress          severity: high    result: fail
source:      kyverno-runtime
subjects:    [Pod default/agent-7c9f-x2k]  + workload owner ref
description: "Unsanctioned LLM API egress: api.openai.com (openai, chat.completions)"
properties:
  ai.class:        llm | mcp | a2a
  ai.provider:     openai
  ai.endpointKind: chat.completions
  ai.model:        gpt-4o                    # only when plaintext available
  ai.transport:    https
  ai.confidence:   "95"
  ai.evidence:     "dns:api.openai.com,sni:api.openai.com,http-path:/v1/chat/completions,header:authorization=Bearer"
  ai.sanctioned:   "false"
  net.destIP:      104.18.7.192
  net.destPort:    "443"
  process.comm:    python3
  process.argv:    "python3 /app/agent.py"    # bounded
  container:       agent
  node:            ip-10-0-1-7
  firstSeen / lastSeen / count                # dedup by fingerprint
  fingerprint:     sha256(policy|podUID|class|provider|endpointKind|destHost)
```

**Never** put header *values* for `Authorization`/`x-api-key`/`api-key` or body content beyond a redacted, length-bounded preview into a finding. A Report is a cluster-readable object; leaking an API key into it is a worse outcome than the shadow AI. Redaction belongs in `pkg/detect`, before the event ever reaches the reporter, and should be non-configurable-off.

`pkg/reporter` should re-adopt the prior contract (fingerprint dedup, `firstTimestamp`/`lastTimestamp`/`count` merge, max-results cap with a `runtime.kyverno.io/truncated-results` annotation, skip no-op updates at capacity) — documented in `git show f806f25^:docs/dev/DESIGN.md`, deleted but battle-tested.

Also finally write `RuntimePolicyStatus.ObservedPods`/`ViolatingPods`/`LastEvaluatedTime` (`api/v1alpha1/runtimepolicy_types.go:82-94`) — declared, print-columned (`:102-104`), and never populated. Shadow-AI findings are the first thing that gives them meaning.

#### Modes — extend the `4a8bcb1` enum

| mode | today | proposed |
| --- | --- | --- |
| `enforce` | programs BPF allow/deny maps | unchanged; plus AI-class blocking |
| `monitor` | **no-op** (`egressmgr/runtimepolicies.go:16`, `lsmmgr/runtimepolicies.go:15`) | **attach collectors, classify, emit findings, do not block** |
| `discover` | — | **NET-NEW**: attach collectors, classify, aggregate into inventory, emit **no** per-event findings and no enforcement |

`monitor` becoming real is the single highest-leverage change in this plan: it turns `.mode` from a placeholder into the observe/enforce axis the product needs, and it's what makes shadow-AI detection expressible at all. The `discover`/`monitor` split matters operationally — discovery on a 500-pod cluster would generate tens of thousands of findings if it emitted per-event; it must aggregate instead.

For inventory surfacing, a net-new **cluster-scoped `AIInventory` CR** whose status holds the rollup (per workload: providers, endpoint kinds, models, transports, first/last seen, request counts) is better than stuffing it into RuntimePolicy status, and gives `kubectl get aiinventory` as the "what AI is my cluster using" answer. Each daemon should write **its own per-node shard** of that status directly to the API. There is no alternative to weigh any more — #32 removes the gRPC fan-out and the `ctrl` Deployment that drove it — but it was the better option regardless: it needs no always-on control-plane component, and it avoids a single cluster-scoped object being contended by every node in the DaemonSet. Sharding per node also means a node whose collectors are dropping events can report that fact locally rather than having it averaged away.

### 2.8 Phasing

**Phase 0 — foundations (no user-visible AI feature). ~3-4 weeks. Risk: low-medium.**
`pkg/runtimeevent`, `pkg/attribution` (+ fix the CRI path and empty-ContainerID panic in `pkg/containers/containers.go`), `pkg/collector` skeleton with one trivial ringbuf source, `pkg/reporter` (OpenReports writer + dedup), `pkg/metrics`, RBAC for reports. Make `mode: monitor` mean something. Risk: ring-buffer backpressure and event-volume blowup; mitigate with kernel-side cgroup filtering from day one and hard per-node rate caps with a drop counter.

**Phase 1 — metadata-only AI detection + stdio MCP. ~3-4 weeks. Risk: medium (BPF verifier).**
`pkg/bpf/dnstrace`, `pkg/bpf/netflow` (dst IP+port), `pkg/bpf/tlspeek` (SNI+ALPN), `pkg/bpf/exectrace` (argv), `pkg/detect/ai` with the provider catalog, `event` CEL variable + `ai` lib, `spec.behaviors[].ai`, `mode: discover` + `AIInventory`.
**This is the fastest useful signal and should be the first release**: full hosted-LLM-provider inventory, stdio-MCP detection via `npx @modelcontextprotocol/server-*`, and MCP-config-file discovery reusing the *already-working* `file_open` LSM hook. Risk concentrates in `tlspeek` (SNI extension walking under the verifier, ClientHello segment-spanning) — de-risk by shipping DNS + netflow + exec first and SNI second; DNS alone already covers hosted providers.

**Phase 2 — plaintext L7. ~2-3 weeks. Risk: low-medium.**
`pkg/bpf/l7peek` + userspace HTTP/JSON-RPC parsing. Unlocks: self-hosted OpenAI-compatible (Ollama `:11434`, vLLM `:8000`), in-cluster MCP over HTTP/SSE, all A2A `.well-known/agent.json` and JSON-RPC methods, model names. Cheap relative to its payoff because there's no crypto involved. Ship enforcement for AI classes here (default-deny MCP allowlist).

**Phase 3 — OpenSSL/BoringSSL uprobes. ~4-6 weeks. Risk: high.**
`pkg/bpf/ssltrace` + dynamic symbol resolution per container. Opt-in per policy. Covers Python/Node HTTPS, which is where the bulk of real LLM/MCP client code lives. Risks: per-container attach lifecycle, OpenSSL 1.1/3.x symbol variance, musl/Alpine, distroless, attach-storm on pod churn, and a genuine performance cost on write-heavy workloads. Gate behind an explicit opt-in and a documented perf budget.

**Phase 4 — Go `crypto/tls` uprobes. ~4-8 weeks. Risk: high, ongoing maintenance.**
`.gopclntab` symbol resolution, register-ABI argument extraction, return-site probing. Label experimental. Expect breakage on each Go release. Only worth it once Phase 3 proves demand.

**Phase 5 — polish.** Optional mesh/Envoy access-log enrichment source; ASN/prefix enrichment for provider IP ranges; correlation (exec of an AI SDK + egress to an unknown host = higher confidence); default policy library shipped in the chart (the Makefile already references a `templates/default-policies.yaml` that doesn't exist — `Makefile` kind-install-manifests guards on `-f`).

### 2.9 Known limitations and evasion paths

- **Encrypted DNS**: DoH/DoT to `1.1.1.1` or a sidecar resolver removes the DNS signal entirely; DoH is indistinguishable from HTTPS. Mitigate by treating DoH endpoints as their own detection ("workload bypassing cluster DNS") rather than trying to read them.
- **ECH (Encrypted Client Hello)**: removes SNI. Not yet common for LLM provider endpoints, but this is the signal most likely to erode over the next few years — plan for it rather than depending on SNI permanently.
- **IP-literal connections**: `https://104.18.7.192/v1/messages` with a `Host` header defeats DNS+SNI; only plaintext or IP-catalog matching helps. IP catalogs for provider CDNs (Cloudflare-fronted) are high-FP.
- **Self-hosted on 443 with a private CA**: no recognizable hostname, no plaintext, no provider match. Detectable only via body shape (needs plaintext) or SDK file-open fingerprints.
- **Static Go binaries** (Phase 4 caveat) and **stripped/obfuscated** builds: uprobe attach fails; degrades to metadata-only. Also anything using a bundled-static OpenSSL.
- **Proxy chaining**: routing LLM calls through an internal reverse proxy or a "gateway" service makes the egress originate from the *gateway's* pod, not the agent's. Attribution then names the wrong workload. Partial mitigation: detect the internal hop and treat the gateway as a known aggregation point, but per-caller attribution genuinely requires the gateway to propagate identity.
- **Non-HTTP transports**: gRPC-based inference (Vertex `PredictionService` over gRPC, Triton), WebSocket-based realtime APIs. `h2`/`websocket` ALPN + provider host still catches hosted cases; body parsing does not apply.
- **stdio MCP evasion**: renaming the server binary, running it from an unexpected path, or spawning via a shell wrapper defeats argv matching. `execve` of *something* is still observed — so a default-deny exec allowlist (Phase 2, using the LSM exec hook) is far more robust than an argv denylist.
- **cgroup attribution gaps**: cgroup v1 nodes (`containers.go:92` TODO) and CRI-O/Docker path shapes yield no attribution at all today; events would arrive unattributable and get dropped (per `Agents.md:61`'s existing "drop network events without pod metadata" rule).
- **Ring buffer drops** under load look identical to "no AI traffic." Drop counters must be exported as metrics *and* surfaced in the inventory as an explicit "coverage incomplete" signal, or users will read silence as safety.
- **Enforcement is coarse**: the existing egress enforcement is a per-pod IPv4 exact-match map with a 1024-entry cap (`_cprog/maps.h:8-20`) and no IPv6. "Block MCP to non-allowlisted servers" therefore degrades to "block these resolved IPs" — racy against DNS TTLs and round-robin, and silently ineffective for IPv6-reachable endpoints. Honest enforcement for hostname-based AI policy needs either a DNS-driven dynamic IP map (resolve-and-program on DNS response, which the `dnstrace` collector enables) or connection-level kill (`bpf_sock_ops` / `tcp_close`) — worth an explicit design decision in Phase 2.
- **`spec.mode` semantics**: today `monitor` silently disables a policy entirely. Any user who writes a monitor-mode AI policy before Phase 0 lands gets nothing, with no error. Consider a validating webhook or a status condition so "this policy is inert" is visible.
