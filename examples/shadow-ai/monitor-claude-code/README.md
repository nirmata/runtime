# Run Claude Code in a container and monitor it

## What this shows

This example runs the real Claude Code CLI in a Kubernetes pod and uses one monitor-mode
`RuntimePolicy` to report the pod's process execution, file opens, IPv4 destinations,
classified egress protocols, and DNS questions. Nothing is blocked.

The image is built before the pod starts, so package installation does not fill the report.
The pod initially runs only `sleep`; the script waits until Nirmata Runtime has matched the
pod before launching Claude Code. That avoids missing Claude's startup activity while the
eBPF programs are being attached.

Claude runs in non-interactive `--bare` mode with an explicit tool allow list, five-turn cap,
and USD 0.50 budget cap. Its task deliberately executes commands, reads a file, writes a file,
and calls the Anthropic API, providing activity for every applicable observer.

## Requires

- A kind cluster with Nirmata Runtime installed. From the repository root, `make kind` creates
  one named `kyverno-runtime`.
- Docker, kind, and kubectl.
- An Anthropic API key in `ANTHROPIC_API_KEY`. The script stores it in a Kubernetes Secret and
  never writes it to a manifest.
- BPF-LSM for `open` and `exec` observations. Check the node, not the distroless daemon pod:

  ```bash
  kubectl debug node/kyverno-runtime-control-plane -it --image=busybox:1.36 -- \
    cat /host/sys/kernel/security/lsm
  ```

  The output must contain `bpf`. Network, protocol, and DNS observation require cgroup v2 and
  BPF but not BPF-LSM. Docker Desktop's LinuxKit VM supports the full example.

## Run it

From this directory:

```bash
export ANTHROPIC_API_KEY='your-test-key'
./demo.sh
```

Use a short-lived, low-limit test key. Any credential placed in an agent container is available
to that agent. If the kind cluster has another name, set it explicitly:

```bash
KIND_CLUSTER_NAME=my-cluster ./demo.sh
```

The script builds the image, loads it into kind, creates the Secret, applies the policy and pod,
waits for observation to attach, and runs this bounded Claude Code task:

```text
Inspect this container: run uname -a and pwd, read /etc/os-release, then write a short summary
to /workspace/claude-observation-demo.txt.
```

The Dockerfile follows Anthropic's supported npm installation path. The default installs the
current release. Pin the package version for a reproducible run:

```bash
CLAUDE_CODE_VERSION=2.x.y ./demo.sh
```

## Verify

The script prints a compact list of findings. The complete namespaced OpenReports object is:

```bash
kubectl get report kyverno-runtime-claude-code-demo -o yaml
```

Expect findings in these categories:

- `exec`: the Claude launcher, Node runtime, and commands Claude chose to execute;
- `open`: Claude's runtime files, `/etc/os-release`, configuration, and workspace files;
- `network`: destination IPv4 addresses contacted by the CLI;
- `protocol`: classified TLS traffic;
- `dns`: names such as the Anthropic API endpoint and cluster resolver queries.

Monitor mode reports what a corresponding default-deny policy would reject, but leaves every
operation untouched. `enforced: "false"` on each result confirms that distinction.

## What this does not capture

This is runtime activity monitoring, not full syscall or packet capture. It does not expose
prompts, responses, HTTP paths, request bodies, TLS contents, file contents, IPv6 destinations,
or exact ordering within a polling window. Network findings have no port dimension. DNS covers
UDP/53 questions, not DNS over HTTPS or TLS.

Open and exec observations use bounded maps, and Reports hold at most 500 results. Claude and
Node open many files during startup, so a busy run can reach those bounds. Use a narrower
`monitorFilter` when the goal is detection rather than a discovery inventory. See the
[limits of monitor mode](../../../docs/users/reference/runtimepolicy.md#limits-of-monitor-mode).

## Clean up

```bash
./demo.sh cleanup
```

Cleanup deletes the policy, pod, and Secret. The locally built Docker image remains available for
another run.
