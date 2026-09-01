# Platform support

What each behavior needs from the kernel, and which managed Kubernetes node images give
you that today. Read this before writing an `open` or `exec` policy: a node booted without BPF-LSM reaches
them through a different kernel hook with its own prerequisites, and one rule interaction
differs there.

## Behavior vs. kernel requirement

| Behavior | Kernel requirement | Typical availability |
| --- | --- | --- |
| `network` | cgroup v2, BPF (`cgroup_skb` programs) | Universal on modern kernels; any cgroup v2 host qualifies. |
| `protocol` | cgroup v2, BPF (`cgroup_skb` programs) | Same as `network`; enforced by a second program on the same cgroup. |
| `dns` | cgroup v2, BPF (`cgroup_skb` programs) | Same as `network`; observation only, never enforced. |
| `open` | cgroup v2, BPF, BTF (`/sys/kernel/btf/vmlinux`), and either `bpf` in the active LSM list or `CONFIG_BPF_JIT` + BPF trampolines for `fmod_ret` (5.7+, x86-64 or arm64) | Which hook is used depends on BPF-LSM; check the node, see below. |
| `exec` | Same as `open` | Same as `open`, and one rule interaction differs — see below. |

`network`, `protocol`, and `dns` are all `cgroup_skb/egress` programs attached to the
pod's own cgroup, so they need nothing beyond a cgroup v2 host and a kernel that can load
BPF — the bar a stock kind cluster on Linux already clears.

`open` and `exec` attach one of two ways, decided once when the daemon starts. Where
BPF-LSM is active it uses the `file_open` and `bprm_check_security` LSM hooks. Where it is
not, it falls back to a `fmod_ret` program on `security_file_open`, which needs no boot
parameter — a modify-return program may attach to any kernel function whose name begins
with `security_`. The fallback is not unconditional: it needs kernel 5.7 or later with
BTF exposed at `/sys/kernel/btf/vmlinux`, the BPF JIT enabled (`CONFIG_BPF_JIT`, which BPF
trampolines require), and an architecture with trampoline support — x86-64 and arm64.
Where those hold, both paths enforce, and the daemon logs which one it chose. Where
neither path is available the daemon reports it and `open`/`exec` policies do not enforce.

Verify a node before relying on either:

```bash
test -r /sys/kernel/btf/vmlinux && echo "BTF ok"
cat /sys/kernel/security/lsm          # 'bpf' present -> LSM path
sysctl net.core.bpf_jit_enable        # non-zero -> trampolines available
```

Whether BPF-LSM is active is a boot-time decision, not a runtime capability check — a
kernel compiled with `CONFIG_BPF_LSM=y` still refuses the LSM attach if `bpf` is not also
in the active LSM list. Check the active list directly:

```bash
cat /sys/kernel/security/lsm
```

`bpf` has to appear in that comma-separated list. It is set by the `lsm=` kernel boot
parameter (or the distribution kernel's compiled-in default for that parameter), and
nothing short of a reboot changes it.

### What differs without BPF-LSM

Executing a file opens it. On a BPF-LSM node both hooks see that single event: `file_open`
matches the binary against your `open` rules and `bprm_check_security` matches the same
file against your `exec` rules, so an exec is subject to both rule sets. On the fallback
one program on `security_file_open` sees the event once and routes it by the kernel's exec
flag, so an exec is matched against `exec` rules only.

What to design around: a path in `open.deny` still blocks ordinary opens on either kind of
node, but only prevents the file being **executed** on a BPF-LSM node. If you are relying
on an `open` deny to stop execution, name the path in `exec.deny` too and the policy holds
on both.

## Node image vs. BPF-LSM availability

| Platform / node image | BPF-LSM active by default | Source |
| --- | --- | --- |
| Amazon EKS — Amazon Linux 2023 | Yes | [Bottlerocket bpf-lsm tracking issue](https://github.com/bottlerocket-os/bottlerocket/issues/1063) |
| Amazon EKS — Bottlerocket | Yes | [Bottlerocket bpf-lsm tracking issue](https://github.com/bottlerocket-os/bottlerocket/issues/1063) |
| GKE — Container-Optimized OS | Yes | [Azure Linux `CONFIG_BPF_LSM` tracking issue](https://github.com/microsoft/azurelinux/issues/6843) |
| GKE — Ubuntu node image | No | [Ubuntu "activate bpf LSM by default" bug](https://bugs.launchpad.net/bugs/2036281) |
| AKS — default Ubuntu node image | No | [Ubuntu "activate bpf LSM by default" bug](https://bugs.launchpad.net/bugs/2036281) |
| AKS — Azure Linux node image | No (upstream request open) | [Azure Linux `CONFIG_BPF_LSM` tracking issue](https://github.com/microsoft/azurelinux/issues/6843) |
| RHEL 8.5+ / OpenShift on RHEL 8.5+ | Yes | [Red Hat 8.9 release notes, Available BPF Features](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/8.9_release_notes/available_bpf_features) |
| Oracle Linux UEK R7U3+ | Yes | [Oracle UEK 7.3 release notes, BPF-LSM Enabled at Boot](https://docs.oracle.com/en/operating-systems/uek/7/relnotes7.3/7.3-feature-bpf-lsm.html) |
| Plain Ubuntu (any version, unmodified) | No | [Ubuntu "activate bpf LSM by default" bug](https://bugs.launchpad.net/bugs/2036281) |

`CONFIG_BPF_LSM=y` has been in Ubuntu's kernel config since Hirsute, but Ubuntu has kept
`bpf` out of the active LSM list: the tracked concern is the per-hook indirect call
overhead of registering BPF-LSM on every LSM hook for every process, not a missing
feature. That decision, still open as of the bug above, is why AKS's default node image
and GKE's Ubuntu node image both ship without it, and why a stock Ubuntu box behaves the
same regardless of cloud.

Net effect for a managed cluster: **every pool in the table enforces `open` and `exec`.**
EKS, GKE on Container-Optimized OS, RHEL 8.5+ and Oracle UEK R7U3+ do it through the LSM
hooks; AKS's default node pool, GKE's Ubuntu node pools and stock Ubuntu do it through the
fallback, with the exec/open interaction described above.

### Enabling it yourself

You do not need BPF-LSM for `open` and `exec` to be enforced — you need it for an exec to
be matched against your `open` rules as well. On a self-managed node (or an AKS/GKE-Ubuntu
pool you control), add `bpf` to the existing `lsm=` list rather than replacing it, then
reboot:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,bpf"
```

```bash
sudo update-grub
sudo reboot
cat /sys/kernel/security/lsm   # confirm "bpf" now appears
```

The exact existing list varies by distribution — append `bpf`, don't overwrite it, or you
disable whatever LSMs (AppArmor, SELinux, Landlock) were already active. Managed node
pools that don't expose GRUB or a boot-parameter setting (most default AKS and GKE pools)
require switching to a node image that ships BPF-LSM already active, per the table above;
there is no per-pod or per-cluster override. Such a pool still enforces both behaviors
through the fallback.

## Checking any node directly

Regardless of platform, the authoritative check is always the same file, read from the
node itself:

```bash
kubectl debug node/<node> -it --image=busybox:1.36 -- cat /host/sys/kernel/security/lsm
```

Read it from the node, not the daemon pod — the daemon image is distroless and has
neither a shell nor `cat`. An absent file means securityfs is not mounted where you are
looking, which is not evidence BPF-LSM is off.

## Can I tell, from the cluster, whether enforcement is actually active?

Only partially today. `status.conditions` on a `RuntimePolicy` reports `Applied=True`
once a node's daemon has compiled and loaded the policy, in whichever mode it requested —
that is what "loaded" means. It does not confirm that the daemon's programs attached on
that node, so a node whose kernel refused them can show the same `Applied=True` as a node
enforcing every rule. `EnforcementAvailable=False` is the condition that reports an attach
or map-programming failure; read that rather than `Applied` before concluding a rule can
fire.

Neither condition tells you which hook set a node is using, so neither tells you whether
an `open` deny also stops execution there. That is a property of the node's boot, and the
kernel file above is the only direct answer.

`ObservationAvailable=False` is a narrower signal for monitor mode: it means the loaded
program has no observation maps, so a monitor-mode policy on that node would silently
produce no findings. It doesn't help in `enforce` mode.

Given that, the practical check is still the kernel file above, done once per node image
if you depend on the BPF-LSM interaction, plus the symptoms in
[Troubleshooting](troubleshooting.md#the-policy-is-applied-but-nothing-is-blocked). IPv6
and dual-stack clusters carry a separate, `network`-specific enforcement gap — see
[limits of network enforcement](reference/runtimepolicy.md#limits-of-network-enforcement).

## BTF and CO-RE

All behaviors need BTF at `/sys/kernel/btf/vmlinux` for CO-RE relocation when the daemon
loads its eBPF programs, and the `open`/`exec` fallback additionally needs it to resolve
its attach target. Every platform in the table above ships it; it is called out here only
because [Installation](installation.md) checks for it alongside cgroup v2.
