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
| `nirmata_runtime_findings_emitted_total` | `policy`, `behavior`, `severity` | Findings handed to the reporter. |
| `nirmata_runtime_report_writes_total` | `result` | Report write attempts. |

Label values:

| Label | Values |
| --- | --- |
| `source` | `egress-observe`, `lsm-observe` (the two poll sources), `monitor`, `reporter` |
| `kind` | `net`, `exec`, `open` |
| `reason` | `buffer_full`, `unattributed`, `unattributed_kernel_deny` |
| `behavior` | `network`, `exec`, `open` |
| `result` | `ok`, `error`, `skipped` |

The three drop reasons mean different things:

- `buffer_full` — the collector's event buffer was full when a source produced an observation.
  Raise `--event-buffer-size`.
- `unattributed` — a finding reached the reporter without a namespace it could write a Report
  into.
- `unattributed_kernel_deny` — the kernel denied something, but no enforce-mode policy the
  daemon tracks explains the deny. Kept distinct from `unattributed` so the two gaps stay
  tellable apart.

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

More on each of these in [Troubleshooting](../troubleshooting.md).
