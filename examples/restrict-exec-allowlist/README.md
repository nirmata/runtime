# Default-deny exec with an allow-list

## What this shows

Process `exec` enforcement under default deny. `deny.values: ["*"]` on the `exec` behavior
means no binary may be executed in the matched pod unless the `allow` list names it, so
dropping a netcat or a downloader into the container does not make it runnable. The allow
list here is built from a literal `values` list unioned with a CEL `expression` over
`spec.variables`.

The check runs in the kernel's `bprm_check_security` LSM hook and returns `-EPERM`, so it
covers every `execve` in the pod's cgroup, not just what a `kubectl exec` starts.

Under a default deny the allow list has to name every binary the workload itself executes.
Processes already running when the policy lands keep running — the hook fires on `execve`,
not on live processes — but anything the container starts afterwards must be allow-listed.

Paths are matched exactly as the kernel resolves them. In the `busybox` image every applet
is a hard link, so `/bin/cat` is its own path; in images where the applets are symlinks to
a single multi-call binary, that binary's path is what the hook sees.

## Requires

File `open` and process `exec` enforcement require a kernel booted with BPF-LSM active:
`bpf` must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel boot
parameter). Stock distributions and hosted CI runners are typically not booted with it;
Docker Desktop's LinuxKit VM is, so a kind cluster on macOS runs these examples.

Check before you start — if `bpf` is missing, the LSM programs cannot even be loaded and
nothing below will be blocked:

```bash
kubectl debug node/<node> -it --image=busybox:1.36 -- cat /host/sys/kernel/security/lsm
```

Read it from the node, not from the agent pod: that image is distroless and has neither
a shell nor `cat`.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy runs in `mode: enforce`.

## Run it

1. Start the client and confirm both binaries run before any policy exists:

   ```bash
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/lsm-client
   kubectl exec lsm-client -- /bin/nc -h; echo "baseline nc exit=$?"
   kubectl exec lsm-client -- /bin/cat /etc/hosts >/dev/null; echo "baseline cat exit=$?"
   ```

   `busybox` rejects `-h` and prints netcat's usage, exiting 1, so the signal that netcat
   ran is the usage text — not the exit code.

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol restrict-exec-allowlist
   ```

   `Applied=True` with reason `Enforcing`.

## Verify

Both directions matter. A check that only asserts `/bin/nc` fails would also pass against
a program that denies every exec.

```bash
kubectl exec lsm-client -- /bin/nc -h; echo "denied exit=$?"
kubectl exec lsm-client -- /bin/cat /etc/hosts >/dev/null; echo "allowed exit=$?"
```

- The `/bin/nc` attempt fails with an exec error from the container runtime and prints no
  netcat usage: the binary never started. Allow a few seconds after applying the policy for
  the daemon to program the pod's path map.
- `allowed exit=0` — `/bin/cat` is on the allow list and still runs, as does `/bin/sh`,
  so `kubectl exec lsm-client -- sh` still gets you a shell. It is a shell that can only
  run three binaries.

## Clean up

```bash
kubectl delete rpol restrict-exec-allowlist
kubectl delete -f client.yaml
```
