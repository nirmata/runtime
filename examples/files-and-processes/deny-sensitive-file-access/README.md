# Block reads of credential files

## What this shows

File `open` enforcement. The policy denies `/etc/shadow` as a literal `values` entry and
adds two more paths through a CEL `expression` that reads `spec.variables`. The two sides
of a rule are unioned, so the effective deny list is all three paths.

The block happens in the kernel's `file_open` LSM hook, which returns `-EPERM`. A shell
inside the pod cannot read the file either — there is no path through the container
runtime, a `kubectl exec`, or a compromised process that avoids the hook.

Path matching is exact. The kernel maps are keyed on the resolved path string, so
`/etc/shadow` denies exactly that path and no directory prefix.

## Requires

File `open` and process `exec` enforcement needs BTF at
`/sys/kernel/btf/vmlinux`, plus either BPF-LSM active (`bpf` in `/sys/kernel/security/lsm`) or, for the `fmod_ret` fallback, kernel 5.7 or later with the
BPF JIT on x86-64 or arm64. Docker Desktop's LinuxKit VM has BPF-LSM active, so a kind
cluster on macOS runs this example. See [platform support](../../../docs/users/platforms.md).

Check before you start — where neither hook runs, nothing below is blocked and the policy
reports `EnforcementAvailable=False`:

```bash
kubectl debug node/<node> -it --image=busybox:1.36 -- sh -c 'cat /host/sys/kernel/security/lsm; uname -rm'
```

`bpf` in the first line means the LSM hooks; otherwise the second line must show kernel 5.7
or later on `x86_64` or `aarch64`.

Read it from the node, not from the agent pod: that image is distroless and has neither
a shell nor `cat`.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
The policy runs in `mode: enforce`.

## Run it

1. Start the client and confirm the file is readable before any policy exists:

   ```bash
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/lsm-client
   kubectl exec lsm-client -- cat /etc/shadow >/dev/null && echo baseline-readable
   ```

2. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol deny-sensitive-file-access
   ```

   `Applied=True` with reason `Enforcing`.

## Verify

Both directions matter. A check that only asserts `/etc/shadow` is unreadable would also
pass against a program that denies every open.

```bash
kubectl exec lsm-client -- cat /etc/shadow; echo "denied exit=$?"
kubectl exec lsm-client -- cat /etc/hosts >/dev/null; echo "allowed exit=$?"
```

- `cat: can't open '/etc/shadow': Permission denied` and `denied exit=1` — the LSM hook
  refused the open. Allow a few seconds after applying the policy for the daemon to
  program the pod's path map.
- `allowed exit=0` — every path not on the deny list is untouched.

## Clean up

```bash
kubectl delete rpol deny-sensitive-file-access
kubectl delete -f client.yaml
```
