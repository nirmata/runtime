# Detect AI SDKs, model files, and agent credentials on disk

## What this shows

A workload that talks to a model provider does two things before it sends a packet: it loads
an SDK, and it reads a credential. A workload that runs a model locally reads weights. All
three are file opens, and all three are visible whether or not the traffic that follows is
encrypted, tunnelled, or sent to an address nobody resolved.

That makes this the one AI signal that does not depend on the network at all. A DNS question
tells you a name was looked up; an `open` under `site-packages/anthropic/` tells you the SDK
is installed and being loaded in this pod, right now, by a process you can attribute.

Three groups are reported here:

- **SDK and framework installs** — `site-packages/openai/`, `node_modules/@anthropic-ai/sdk/`,
  `site-packages/langchain/`, and the rest.
- **Model artifacts and caches** — a `.safetensors`, `.gguf`, `.onnx` or `.ckpt` file, and the
  Hugging Face, Ollama and LM Studio cache directories.
- **Agent credential files** — `~/.claude/.credentials.json`, `~/.codex/auth.json`,
  `~/.gemini/oauth_creds.json`, and gcloud's application default credentials.

None of these can be written as an `open` value. An SDK directory's absolute path depends on
the interpreter version and the virtualenv; a model file has no fixed name; a credential file
sits under whichever home directory the container runs as. So `policy.yaml` observes `open`
broadly and narrows the *findings* with a
[monitorFilter](../../../docs/users/reference/runtimepolicy.md#filtering-monitor-findings).

The first expression is a guard. `event.open` exists only on a file observation, so without
`has(event.open)` the second expression would be evaluated against this pod's exec and
network observations too. Expressions are ANDed and short-circuit on the first false, which
is what makes the guard work.

The directory entries are written with both slashes — `/site-packages/anthropic/` rather than
`anthropic` — so that a `contains` match is a path component and not a substring. Without the
trailing slash, `anthropic` also matches a file named `anthropic-notes.txt`.

## Requires

File `open` observation requires a kernel booted with BPF-LSM active: `bpf` must appear in
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

1. Start the workload. It lays down an installed SDK, a cached model, a credential file, and
   one ordinary library, then idles:

   ```bash
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/ai-workload
   ```

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol detect-ai-sdks
   ```

   `Applied=True` with reason `Monitoring`.

3. Read one file from each group, and one that must not be reported:

   ```bash
   kubectl exec ai-workload -- cat /usr/lib/python3/site-packages/anthropic/__init__.py
   kubectl exec ai-workload -- cat /root/.ollama/models/blobs/model.gguf
   kubectl exec ai-workload -- cat /root/.claude/.credentials.json
   kubectl exec ai-workload -- cat /usr/lib/python3/site-packages/requests/__init__.py
   ```

## Verify

Both directions matter. A check that only asserts the SDK read was reported would also pass
against a policy that reports every file open — which is exactly what this policy would do
without its filter.

Observations are drained on a poll interval, 10 seconds by default (`--observe-interval`), so
allow about twenty.

```bash
kubectl get report kyverno-runtime-ai-workload -o yaml
```

- Three results, one per path read:

  ```yaml
  - source: kyverno-runtime
    policy: detect-ai-sdks
    rule: open
    result: fail
    description: 'monitor mode: open of /root/.claude/.credentials.json would have been denied by policy detect-ai-sdks'
    properties:
      behavior: open
      target: /root/.claude/.credentials.json
      enforced: "false"
  ```

- **No result for `requests/__init__.py`**, and none for the shell, `sh`, or anything else the
  pod opened. That absence is the filter working.

An `open` observation carries the resolved path and nothing else — no `comm`, no `pid`. The
LSM counter map is keyed on the path, so identical reads from two processes are one finding
with a `count`, not two.

## What this does not cover

- **A path longer than 127 bytes.** The kernel key is `char path[128]`, so a deeply nested
  virtualenv — `/opt/app/.venv/lib/python3.12/site-packages/…` — can be truncated before the
  component the filter is looking for. The finding still appears in a discovery run with no
  filter; it is the `contains` match that is lost.
- **A statically linked or vendored SDK.** A binary with the provider client compiled in
  opens nothing recognizable.
- **An SDK read from an image layer at build time.** This observes the running pod.
- **Evidence of a connection.** An installed SDK is evidence of intent, not of traffic. Pair
  it with [report-unexpected-dns](../report-unexpected-dns/) for the names actually resolved.

## Clean up

```bash
kubectl delete rpol detect-ai-sdks
kubectl delete -f client.yaml
```
