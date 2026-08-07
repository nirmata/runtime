# File and process control

Deciding which files a workload may read and which binaries it may run. An `open` behavior
is keyed on the resolved absolute path, and an `exec` behavior on the resolved binary path —
neither accepts a glob, a prefix, or a basename, and `exec` cannot match arguments because
the hook that can refuse an exec cannot read them.

All of these require a kernel booted with BPF-LSM active: `bpf` must appear in
`/sys/kernel/security/lsm`. Stock distributions and hosted CI runners are typically not
booted with it; Docker Desktop's LinuxKit VM is.

| Directory | Scenario | Mode |
| --- | --- | --- |
| [deny-sensitive-file-access](deny-sensitive-file-access/) | Block reads of credential files (`/etc/shadow`, SSH keys) even from a shell inside the pod | enforce |
| [restrict-exec-allowlist](restrict-exec-allowlist/) | Prevent shell or netcat execution in a hardened pod: default-deny exec with an allow-list | enforce |
| [enforce-workload-baseline](enforce-workload-baseline/) | Lock a workload to its known-good files, binaries, and destinations | enforce |

To record what a workload touches before locking it down, use
[monitoring/monitor-workload-baseline](../monitoring/monitor-workload-baseline/), which is
the same three behaviors in monitor mode.

The same two hooks carry most of the AI signals: an SDK load, a model file, and an agent
launch are an `open` and an `exec` like any other. Those live in
[shadow-ai/](../shadow-ai/).
