# Troubleshooting

## The policy is applied but nothing is blocked

Work through these in order.

1. **Is `spec.mode` set?** A `RuntimePolicy` with no `mode` is loaded but inert: it
   neither enforces nor reports.

   ```bash
   kubectl get rpol <name> -o jsonpath='{.spec.mode}'
   ```

2. **For `open`/`exec` policies: is the node's kernel booted with BPF-LSM?** File
   `open` and process `exec` enforcement require a kernel booted with BPF-LSM active:
   `bpf` must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel boot
   parameter). Stock distributions and hosted CI runners are typically not booted with
   it. This is the single most likely reason a new user sees no `open`/`exec`
   enforcement.

   ```bash
   kubectl debug node/<node> -it --image=busybox:1.36 -- cat /host/sys/kernel/security/lsm
   ```

   Read it from the node, not from the daemon pod: that image is distroless and has
   neither a shell nor `cat`. If the file is missing entirely, securityfs is not
   mounted where you are looking — that is not evidence BPF-LSM is off.

3. **For `network` policies: is the node on cgroup v2?** Network egress enforcement
   and observation require only a cgroup v2 host and BPF support; a stock kind cluster
   on a Linux host qualifies.

   ```bash
   kubectl -n kyverno-runtime exec <daemon-pod> -- stat -fc %T /host/sys/fs/cgroup
   ```

   Expect `cgroup2fs`.

4. **What do the policy's own conditions say?**

   ```bash
   kubectl get rpol <name> -o yaml
   ```

   Check `status.conditions`: `Applied` says whether the policy is loaded on this node
   and in which mode; `TargetsValid` says whether every `network` target in the policy
   could be programmed.

## No Reports appear in monitor mode

- `spec.mode` must be `monitor`. `enforce` mode blocks but never emits findings.
- Allow up to about 20 seconds: BPF counters are drained every `--observe-interval`
  (default 10s), and findings are buffered and flushed every 10 seconds.
- Check `status.conditions` for `ObservationAvailable=False`: it means a loaded LSM
  program has no observation maps, so a monitor-mode policy on that node would
  silently produce no findings.
- A finding for a pod whose namespace is not a valid DNS-1123 label is dropped rather
  than written to an invalid object name.

## TargetsValid is False

`status.conditions` type `TargetsValid`, reason `UnsupportedTargets`, means one or more
`network` targets could not be programmed into the kernel maps. IPv6 addresses,
hostnames, and CIDRs wider than `/24` are rejected rather than silently skipped; a CIDR
of `/24` or narrower is expanded into individual addresses. The condition's message
lists each rejected value and the reason it was rejected:

```bash
kubectl get rpol <name> -o yaml
```

## Events are being dropped

`nirmata_runtime_events_dropped_total` is labeled by `source` and `reason`. Three
reasons are produced:

| Reason | Meaning |
| --- | --- |
| `buffer_full` | The collector's fan-in buffer was full when an event arrived. |
| `unattributed` | A finding could not be attributed to a pod. |
| `unattributed_kernel_deny` | The kernel denied an operation but no tracked enforce-mode policy's lists explain it. |

`nirmata_runtime_attribution_misses_total` counts observations the local pod index
could not tie to any pod at all. Host- and node-level processes are never attributed,
by design.

## Getting daemon logs

```bash
kubectl -n kyverno-runtime logs -l app.kubernetes.io/name=kyverno-runtime
```

`--log-level` controls verbosity (default `0`; higher is more verbose). The chart does
not currently expose it as a value.
