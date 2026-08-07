# User documentation

Kyverno policies for eBPF runtime enforcement. Guides and reference for running Nirmata
Runtime and writing `RuntimePolicy` objects.

- [Quickstart](quickstart.md) — kind cluster to a kernel-enforced egress block in under
  five minutes.
- [Concepts](concepts.md) — the per-node daemon, how enforcement works, allow and deny
  semantics, modes, scoping, and what monitor mode can see.
- [Installation](installation.md) — platform requirements, the Helm chart and its values,
  daemon flags, and verifying an install.
- [Examples](examples.md) — catalog of the scenarios under
  [`examples/`](../../examples/), grouped by feature.
- [Detecting shadow MCP](shadow-mcp.md) — finding the MCP servers a workload launches,
  the configuration and credentials it reads, and the endpoints it reaches.
- [Troubleshooting](troubleshooting.md) — why nothing is being blocked, missing Reports,
  rejected policy targets, and dropped events.

## Reference

- [RuntimePolicy](reference/runtimepolicy.md) — the full spec, status conditions,
  Reports, and the limits of monitor mode.
- [CEL](reference/cel.md) — where expressions appear, the expression contract, and the
  available libraries.
- [Metrics](reference/metrics.md) — the Prometheus counters and what each one means.

Runnable manifests live in [`examples/`](../../examples/). Architecture and build
documentation is under [`docs/dev/`](../dev/).
