# Metrics

The daemon serves Prometheus metrics on `--metrics-addr` (default `:9090`, set by the chart's
`daemon.metrics.port`). Setting the flag to the empty string disables the endpoint; the counters
themselves keep working.

## Counters

Every metric is prefixed `nirmata_runtime_`.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `nirmata_runtime_events_ingested_total` | `source`, `kind` | Observations ingested by the collector. |
| `nirmata_runtime_events_dropped_total` | `source`, `reason` | Dropped observations. |
| `nirmata_runtime_attribution_misses_total` | — | Observations that could not be tied to a pod. |
| `nirmata_runtime_findings_emitted_total` | `policy`, `behavior` | Findings handed to the reporter. |
| `nirmata_runtime_monitor_filter_eval_errors_total` | `policy`, `expression` | `spec.monitorFilter` expressions that failed to evaluate. The finding is reported anyway. |
| `nirmata_runtime_report_writes_total` | `result` | Report write attempts. |

`nirmata_runtime_findings_emitted_total` no longer carries a `severity` label (every value was
`medium`; nothing ever varied it). A PromQL selector or grouping that names it, such as
`findings_emitted_total{severity="medium"}` or `sum by (severity) (...)`, silently stops matching
after upgrade instead of erroring — remove that selector and grouping from dashboards and alerts.

Label values:

| Label | Values |
| --- | --- |
| `source` | `egress-observe`, `lsm-observe` (the two poll sources), `dnsquery` (the DNS question source), `exec-trace` (the streamed exec source), `monitor`, `reporter` |
| `kind` | `net`, `protocol`, `exec`, `open`, `dns` |
| `reason` | `buffer_full`, `unattributed`, `unattributed_kernel_deny`, `count_map_full`, `ringbuf_full`, `name_unreadable`, `undecodable`, `queue_full`, `send_failed` |
| `behavior` | `network`, `protocol`, `exec`, `open`, `dns` |
| `result` | `ok`, `error`, `skipped` |

The pipeline-wide drop reasons:

- `buffer_full` — the collector's event buffer was full when a source produced an observation.
  Raise `--event-buffer-size`.
- `unattributed` — a finding reached the reporter without a namespace it could write a Report
  into.
- `unattributed_kernel_deny` — the kernel denied something, but no enforce-mode policy the
  daemon tracks explains the deny. Kept distinct from `unattributed` so the two gaps stay
  tellable apart.
- `count_map_full` — a per-cgroup kernel count map had no room for a new
  `(path, decision)` or `(destination, decision)` pair, so the operation went uncounted. The
  operation itself was still allowed or denied as the policy says; only the observation was
  lost. Climbing means one workload is touching more distinct paths or destinations within a
  poll interval than the map holds (2048), so narrow the `podSelector` of the policies
  selecting it, or accept the gap knowingly.

## DNS question loss

The DNS question source counts three ways a question can be lost, all under
`nirmata_runtime_events_dropped_total{source="dnsquery"}`. They exist because a lost
observation and an absent one look identical at the sink, and only the counter tells them
apart:

| `reason` | Where | Meaning |
| --- | --- | --- |
| `ringbuf_full` | kernel | The ring buffer had no room, because the reader is behind. The question left the pod; only the record was lost. |
| `name_unreadable` | kernel | The question name could not be read: truncated, carrying a compression pointer, or longer than the 128-byte name width. |
| `undecodable` | userspace | A record whose bytes the decoder rejected. |

How to read them:

- `ringbuf_full` climbing means questions are arriving faster than the daemon drains them.
  The buffer holds roughly 450 records. A large step usually means one workload resolving in
  a tight loop; narrow the `podSelector` of the `dns` policies, or accept the gap knowingly.
- `name_unreadable` climbing means real questions are being asked whose names exceed what a
  policy could have named anyway, since the same 128-byte width bounds policy values. A
  steady trickle is normal on a workload with long generated hostnames.
- `undecodable` should be flat at zero. Anything else means the kernel record layout and the
  Go decoder disagree, which is a bug and not a tuning problem.

The two kernel counters are cumulative and read every 30 seconds, so they move in steps
rather than continuously, and each read also logs the delta with its reason. `undecodable`
is counted per record, as it happens.

Silence here is meaningful in one direction only: a flat counter means no question was lost,
not that questions were asked. `nirmata_runtime_events_ingested_total{kind="dns"}` is what
says observation is producing.

## Push sink loss

The push sink counts two ways a finding can fail to reach the collector, both under
`nirmata_runtime_events_dropped_total{source="pushsink"}`. Neither affects the `Report`
objects, which are written on an independent path:

| `reason` | Meaning |
| --- | --- |
| `queue_full` | The send queue was full, so the oldest queued finding was dropped to make room. The sink never blocks the event path. |
| `send_failed` | The stream refused a finding. The stream is reopened and the next finding goes out on the new one. |

How to read them:

- `queue_full` climbing means findings are being produced faster than the collector accepts
  them, or the collector has stopped reading. The queue holds 4096 findings; what it drops is
  the oldest, so a burst costs the beginning of the burst.
- `send_failed` climbing means the stream keeps breaking. Check the collector, then the
  certificates: a daemon whose client certificate the collector rejects keeps reconnecting,
  backing off to one attempt a minute.

Both are flat at zero when `--push-target` is unset, because nothing is queued at all.

## Reading them

```bash
pod=$(kubectl -n kyverno-runtime get pod -l app.kubernetes.io/name=kyverno-runtime -o name | head -1)
kubectl -n kyverno-runtime port-forward "$pod" 9090:9090 &
curl -s localhost:9090/metrics | grep nirmata_runtime
```

Each node runs its own daemon, so this reads one node's counters.

What to look at:

- `nirmata_runtime_findings_emitted_total` staying at zero while a `monitor` policy is applied
  means nothing matched, or the observation path is not producing — check the
  `ObservationAvailable` condition on the policy.
- `nirmata_runtime_attribution_misses_total` rising steadily is expected on a busy node: node
  and host-process activity is never attributed to a pod. A step change alongside missing
  findings for a specific workload is not.
- `nirmata_runtime_events_dropped_total` and `nirmata_runtime_report_writes_total{result="error"}`
  are the two counters worth alerting on.
- `nirmata_runtime_monitor_filter_eval_errors_total` above zero means a
  [monitorFilter](runtimepolicy.md#filtering-monitor-findings) expression is failing at
  evaluation time; the `expression` label carries that expression's `name`. The filter fails
  open, so the effect is findings it should have narrowed showing up in the Report — noise to
  fix, not a gap to worry about.

More on each of these in [Troubleshooting](../troubleshooting.md).
