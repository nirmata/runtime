# Lock a workload to its known-good baseline

## What this shows

All three behaviors enforced by one policy: default-deny egress with an allow-list,
default-deny exec with an allow-list, and an explicit deny on a sensitive file path. This
is the enforcing end of the workflow that
[monitor-workload-baseline](../monitor-workload-baseline/) starts — collect the baseline in
`mode: monitor`, then commit it as `mode: enforce`.

`open` is an explicit deny list rather than a default deny, because a workload opens far
more paths than a reviewer can enumerate, and a default-denied `open` behavior stops the
process at the first unlisted file. `exec` and `network` are narrow enough to allow-list.

Under a default-denied `exec` the allow list must name every binary the container executes,
including the ones its own entrypoint runs at startup. Processes already running when the
policy lands are unaffected — the hook fires on `execve`, not on live processes — so this
policy is safe to apply to a running pod but would block a restart of a container whose
startup path is not allow-listed.

`network` allow and deny entries are unioned across every matching policy and one matching
policy setting the default-deny sentinel is enough to flip egress for all of them. `open`
and `exec` compose differently: their effective lists intersect across policies, so a
second policy allowing more binaries does not widen this one.

## Requires

File `open` and process `exec` enforcement require a kernel booted with BPF-LSM active:
`bpf` must appear in `/sys/kernel/security/lsm` (set with the `lsm=` kernel boot
parameter). Stock distributions and hosted CI runners are typically not booted with it;
Docker Desktop's LinuxKit VM is, so a kind cluster on macOS runs these examples.

Network egress enforcement and observation require only a cgroup v2 host and BPF support;
a stock kind cluster on a Linux host qualifies.

Check before you start — without BPF-LSM the `exec` and `open` halves of this policy are
not enforced, while the `network` half still is:

```bash
kubectl debug node/<node> -it --image=busybox:1.36 -- cat /host/sys/kernel/security/lsm
```

Read it from the node, not from the agent pod: that image is distroless and has neither
a shell nor `cat`.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy runs in `mode: enforce`.

## Run it

1. Start the workload and two targets, one of which will be allow-listed:

   ```bash
   kubectl apply -f nginx.yaml
   kubectl apply -f targets.yaml
   kubectl wait --for=condition=Ready pod/nginx pod/baseline-target-allowed pod/baseline-target-denied
   ```

2. Confirm the baseline before any policy exists. If this fails, nothing below proves
   anything:

   ```bash
   ALLOWED=$(kubectl get pod baseline-target-allowed -o jsonpath='{.status.podIP}')
   DENIED=$(kubectl get pod baseline-target-denied -o jsonpath='{.status.podIP}')
   kubectl exec nginx -- /usr/bin/curl -sS -m 3 -o /dev/null "http://${ALLOWED}:8080/"; echo "baseline allowed exit=$?"
   kubectl exec nginx -- /usr/bin/curl -sS -m 3 -o /dev/null "http://${DENIED}:8080/"; echo "baseline denied exit=$?"
   kubectl exec nginx -- /bin/ls / >/dev/null; echo "baseline ls exit=$?"
   kubectl exec nginx -- /bin/cat /etc/shadow >/dev/null; echo "baseline shadow exit=$?"
   ```

3. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol enforce-workload-baseline
   ```

   `Applied=True` with reason `Enforcing`. Egress is now denied except for the cluster DNS
   address in the manifest's `allow` list.

4. Pod IPs are assigned at scheduling time, so the allowed destination cannot be written
   into a committed manifest. Add it to the live policy:

   ```bash
   kubectl patch rpol enforce-workload-baseline --type json \
     -p "[{\"op\": \"add\", \"path\": \"/spec/behaviors/0/network/allow/values/-\", \"value\": \"${ALLOWED}\"}]"
   ```

## Verify

Every behavior is checked in both directions. A one-sided check would also pass against a
program that blocks everything — which for this policy would mean a dead workload.

```bash
kubectl get pod nginx
kubectl exec nginx -- /usr/bin/curl -sS -m 3 -o /dev/null "http://${ALLOWED}:8080/"; echo "allowed egress exit=$?"
kubectl exec nginx -- /usr/bin/curl -sS -m 3 -o /dev/null "http://${DENIED}:8080/"; echo "denied egress exit=$?"
kubectl exec nginx -- /bin/cat /etc/nginx/nginx.conf >/dev/null; echo "allowed open exit=$?"
kubectl exec nginx -- /bin/cat /etc/shadow; echo "denied open exit=$?"
kubectl exec nginx -- /bin/ls /; echo "denied exec exit=$?"
```

- `kubectl get pod nginx` still reports `1/1 Running`. The readiness probe is an inbound
  request from the kubelet, and nginx keeps answering it: the policy does not touch
  ingress, and nginx's own `/usr/sbin/nginx` is allow-listed.
- `allowed egress exit=0` and `denied egress exit=28` (curl's timeout) — the allow-list
  entry works and everything else is dropped.
- `allowed open exit=0`, and the `/etc/shadow` read fails with
  `cat: /etc/shadow: Permission denied` — only the listed path is denied.
- The `/bin/ls` attempt fails with an exec error from the container runtime and prints no
  listing: it is not on the exec allow list, while `/bin/cat` and `/usr/bin/curl` used by
  the checks above are.

Allow a few seconds after each policy change for the daemon to reprogram the pod's maps.

## Clean up

```bash
kubectl delete rpol enforce-workload-baseline
kubectl delete -f nginx.yaml -f targets.yaml
```
