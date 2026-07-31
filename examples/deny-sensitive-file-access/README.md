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

File `open` and process `exec` enforcement require a kernel booted with BPF-LSM active:
`bpf` must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel boot
parameter). Stock distributions and hosted CI runners are typically not booted with it.

Check before you start — if `bpf` is missing, the LSM programs cannot even be loaded and
nothing below will be blocked:

```bash
kubectl -n kyverno-runtime exec \
  "$(kubectl -n kyverno-runtime get pod -l app.kubernetes.io/name=kyverno-runtime \
       -o jsonpath='{.items[0].metadata.name}')" \
  -- cat /host/sys/kernel/security/lsm
```

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
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
