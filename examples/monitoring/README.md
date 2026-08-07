# Monitor mode

Recording what a workload does without blocking any of it. Observe-mode programs are loaded
with empty deny maps so they cannot refuse an operation, and the finding says what *would*
have been denied — which is how an enforcement policy is usually arrived at: watch first,
then turn the same behaviors to `enforce`.

Findings arrive as OpenReports `Report` objects in the workload's namespace. What monitor
mode can and cannot see is listed in
[limits of monitor mode](../../docs/users/reference/runtimepolicy.md#limits-of-monitor-mode).

| Directory | Scenario | Requires |
| --- | --- | --- |
| [monitor-egress](monitor-egress/) | Audit where a workload actually connects before turning enforcement on | cgroup v2 |
| [monitor-workload-baseline](monitor-workload-baseline/) | Record every file, binary, and destination a workload touches, without blocking | BPF-LSM for `open` and `exec`; `network` findings alone need only cgroup v2 |
| [monitor-static-pods](monitor-static-pods/) | Confirm the daemon can observe kubeadm's static control-plane pods | cgroup v2 |

The [shadow-ai/](../shadow-ai/) examples are monitor-mode too. They live there rather than
here because the signal they narrow to is what makes them worth reading, not the mode.
