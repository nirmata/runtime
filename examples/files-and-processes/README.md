# File and process control

Deciding which files a workload may read and which binaries it may run. An `open` behavior
is keyed on the resolved absolute path, and an `exec` behavior on the resolved binary path —
neither accepts a glob, a prefix, or a basename, and `exec` cannot match arguments because
the hook that can refuse an exec cannot read them.

All of these need BTF, plus either BPF-LSM (`bpf` in `/sys/kernel/security/lsm`) or, for
the `fmod_ret` fallback, kernel 5.7 or later with the BPF JIT on x86-64 or arm64 — see
[platform support](../../docs/users/platforms.md). Docker Desktop's LinuxKit VM has BPF-LSM
active.

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
