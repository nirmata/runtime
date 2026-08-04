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

## A DNS name I expected to see is not reported

Work down this list; the first three are far more common than a bug.

1. **The answer was cached, so no question was asked.** A resolution is not a connection,
   and a connection does not imply a resolution. If the workload's resolver, its libc, or a
   sidecar already held the address, nothing went on the wire. Restart the pod after the
   policy is applied and look again — a cold resolver asks.

2. **The name is covered by the allow list.** `dns.allow` is the expected set, so a name in
   it is deliberately silent. That includes a name a left-wildcard covers. To see everything
   the workload resolves, add a second policy over the same pods with
   `deny.values: ["*"]` and no allow list.

3. **The question is not one this hook reads.** Only UDP datagrams to port 53 are read. DNS
   over HTTPS, DNS over TLS, and DNS over TCP/53 produce no observation, and a workload that
   dials an address it never resolved asks nothing at all.

4. **The pod is not selected.** A pod is observed exactly while some policy with a `dns`
   behavior selects it, and a behavior with no `allow` and no `deny` entry is inert — it
   selects nothing and observes nothing. Check the selector against the pod's labels:

   ```bash
   kubectl get rpol <name> -o jsonpath='{.spec.podSelector}'
   kubectl get pod <pod> --show-labels
   ```

5. **The policy did not compile.** `mode: enforce` with a `dns` behavior, an address or a
   misplaced wildcard as a value: each fails the whole policy, so no behavior in it is in
   force. See [Applied is False](#applied-is-false).

6. **The question was lost, and counted.** Check the DNS loss counters before concluding
   nothing was asked:

   ```bash
   curl -s localhost:9090/metrics | grep 'events_dropped_total{source="dnsquery"'
   ```

   `ringbuf_full` means the daemon fell behind; `name_unreadable` means the name exceeded
   the 128-byte width. Both are in [Metrics](reference/metrics.md#dns-question-loss).

7. **The program never loaded.** DNS observation is best effort: a kernel that will not load
   the `cgroup_skb` program leaves every other behavior working and logs the reason once at
   startup.

   ```bash
   kubectl -n kyverno-runtime logs -l app.kubernetes.io/name=kyverno-runtime | grep -i 'dns question observation disabled'
   ```

Two more things that look like a miss and are not: the name is reported as the pod's
resolver asked it, so `search`-domain expansions such as
`api.example.com.default.svc.cluster.local` appear under their expanded form rather than the
name in your policy; and a wildcard never matches its own apex, so `*.example.com` leaves
`example.com` reported as unexpected.

## TargetsValid is False

`status.conditions` type `TargetsValid` goes `False` for one of two reasons, and the
condition's message names the offending values in both cases:

```bash
kubectl get rpol <name> -o yaml
```

`UnsupportedTargets` means one or more `network` targets could not be programmed into the
kernel maps. CIDRs wider than `/24` and domain names whose DNS wire encoding exceeds 128
bytes are rejected rather than silently skipped; a CIDR of `/24` or narrower is expanded
into individual addresses. A value the grammar refuses outright — a malformed Service name,
an IPv6 literal, a wildcard — does not reach this condition when it is written as a
literal: it fails the policy to compile, and appears under `Applied` instead. See
[Applied is False](#applied-is-false).

`UnresolvedServices` means a value named a cluster Service that is not in the daemon's
cache — a typo, a namespace that was never created, or a Service deleted after the policy
was written. It contributes no addresses, so under default-deny the destination is fully
blocked, which from inside the workload looks like a network outage. Check the Service
exists in the namespace the name carries:

```bash
kubectl -n <namespace> get svc <name>
```

A Service name that is rejected outright rather than left unresolved reaches
`UnsupportedTargets`, for one of three reasons: it carries the cluster domain but is
neither `<service>.<namespace>.svc.<cluster-domain>` nor
`<hostname>.<service>.<namespace>.svc.<cluster-domain>`; it is a cluster name written
without its domain, such as `redis.default.svc`; or one of its labels is malformed — the
service label must start with a letter, while namespace and hostname labels may also
start with a digit.

A value that resolves nothing and reports nothing is almost always a short form. `redis.default`
is a valid external name, so no condition complains, but a pod's resolver expands short names
through its search domains and asks for `redis.default.svc.cluster.local` instead, which the
policy never named. Write cluster Services in full.

## Applied is False

`CompileFailed` means the spec could not be compiled, and **nothing in the policy is in
force** — not the offending rule, and not the rules either side of it. The message carries
the field path, the value and the reason, so it points at one entry in one behavior:

```bash
kubectl get rpol <name> -o jsonpath='{.status.conditions[?(@.type=="Applied")].message}'
```

Causes are a value the grammar refuses (a malformed cluster Service name, an IPv6 literal, a
wildcard such as `*.example.com`), an `expression` that does not compile, or one that returns
something other than `list(string)`. Correcting the spec applies immediately; there is
nothing to restart.

`NoMode` means the policy omits `spec.mode`. It is loaded and inert by design: no programs
are attached, nothing is blocked and no findings are produced. Set `enforce` or `monitor`.

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
