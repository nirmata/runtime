# Platform support

What each behavior needs from the kernel, and which managed Kubernetes node images give
you that today. Read this before writing an `open` or `exec` policy: on the wrong node
image the policy loads, `Applied` shows `True`, and nothing is ever blocked.

## Behavior vs. kernel requirement

| Behavior | Kernel requirement | Typical availability |
| --- | --- | --- |
| `network` | cgroup v2, BPF (`cgroup_skb` programs) | Universal on modern kernels; any cgroup v2 host qualifies. |
| `protocol` | cgroup v2, BPF (`cgroup_skb` programs) | Same as `network`; enforced by a second program on the same cgroup. |
| `dns` | cgroup v2, BPF (`cgroup_skb` programs) | Same as `network`; observation only, never enforced. |
| `open` | Kernel booted with BPF-LSM active | Not universal — see the platform table below. |
| `exec` | Kernel booted with BPF-LSM active | Not universal — see the platform table below. |

`network`, `protocol`, and `dns` are all `cgroup_skb/egress` programs attached to the
pod's own cgroup, so they need nothing beyond a cgroup v2 host and a kernel that can load
BPF — the bar a stock kind cluster on Linux already clears.

`open` and `exec` are different in kind, not just degree: they attach to the
`file_open` and `bprm_check_security` LSM hooks, and the kernel only calls into a BPF-LSM
program if BPF-LSM is one of the active LSMs for that boot. That is a boot-time decision,
not a runtime capability check — a kernel that was compiled with `CONFIG_BPF_LSM=y` still
refuses the attach if `bpf` is not also in the active LSM list. Check the active list
directly:

```bash
cat /sys/kernel/security/lsm
```

`bpf` has to appear in that comma-separated list. It is set by the `lsm=` kernel boot
parameter (or the distribution kernel's compiled-in default for that parameter), and
nothing short of a reboot changes it.

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

Net effect for a managed cluster: **EKS and GKE on Container-Optimized OS enforce `open`
and `exec` out of the box; AKS's default node pool and GKE's Ubuntu node pools do not.**

### Enabling it yourself

On a self-managed node (or an AKS/GKE-Ubuntu pool you control), add `bpf` to the existing
`lsm=` list rather than replacing it, then reboot:

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
there is no per-pod or per-cluster override.

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
that is what "loaded" means. It does not currently confirm that the kernel accepted the
LSM attach for `open`/`exec` on that node, so a node without BPF-LSM active can show the
same `Applied=True` as a node correctly enforcing every rule. This is a known gap, not a
documented guarantee: do not read `Applied=True` as proof that `open`/`exec` rules can
fire on a given node.

`ObservationAvailable=False` is a narrower, more reliable signal for monitor mode: it
means a loaded LSM program has no observation maps, so a monitor-mode policy on that node
would silently produce no findings. It doesn't help in `enforce` mode, and it doesn't
tell you BPF-LSM is inactive versus some other attach failure.

Given that gap, the practical check is still the kernel file above, done once per node
image before you rely on `open`/`exec` enforcement, plus the symptoms in
[Troubleshooting](troubleshooting.md#the-policy-is-applied-but-nothing-is-blocked). IPv6
and dual-stack clusters carry a separate, `network`-specific enforcement gap — see
[limits of network enforcement](reference/runtimepolicy.md#limits-of-network-enforcement).

## BTF and CO-RE

All behaviors additionally need BTF at `/sys/kernel/btf/vmlinux` for CO-RE relocation when
the daemon loads its eBPF programs. Every platform in the table above ships it; it is
called out here only because [Installation](installation.md) checks for it alongside
cgroup v2 and BPF-LSM.
