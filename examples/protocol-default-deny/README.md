# Allow only HTTP/1.1, on every port

## What this shows

The `protocol` behavior decides by what a connection *says*, not where it goes. Both
attempts below use the same destination pod and the same TCP port 80; the only difference
is the first thing the client writes. `deny.values: ["*"]` makes this a default deny, so
`http/1.1` is the one shape of egress that survives.

Traffic matching no signature classifies as `unclassified`. That is observation vocabulary
— it appears in findings, metrics and logs — and never a policy value: no `allow` entry can
cover it, so under this default deny it is denied. The client here connects by address and
needs no name resolution; a workload that resolves names would need `dns` in the allow list
too, since a default deny covers that as well.

## Requires

cgroup v2 and BPF — a stock kind cluster qualifies. No BPF-LSM needed.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy runs in `mode: enforce`.

## Run it

1. Start the target and the client:

   ```bash
   kubectl apply -f target.yaml -f client.yaml
   kubectl wait --for=condition=Ready pod/protocol-target pod/protocol-client
   TARGET=$(kubectl get pod protocol-target -o jsonpath='{.status.podIP}')
   ```

2. Confirm both shapes of traffic work before any policy exists. If this fails, the
   "blocked" result below proves nothing:

   ```bash
   kubectl exec protocol-client -- wget -q -T 3 -O /dev/null "http://${TARGET}/" && echo baseline-http-ok
   kubectl exec protocol-client -- sh -c "echo 'SSH-2.0-demo' | nc -w 3 ${TARGET} 80 >/dev/null && echo baseline-ssh-ok"
   ```

3. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol protocol-default-deny
   ```

## Verify

```bash
kubectl exec protocol-client -- wget -q -T 3 -O /dev/null "http://${TARGET}/"; echo "http/1.1 exit=$?"
kubectl exec protocol-client -- sh -c "echo 'SSH-2.0-demo' | nc -w 3 ${TARGET} 80"; echo "ssh exit=$?"
```

- `http/1.1 exit=0` — the request opens with `GET / HTTP/1.1`, classifies as `http/1.1`, and is
  allowed.
- `ssh exit=1` — the same port, but the connection opens with an SSH banner. It classifies
  as `ssh`, which no `allow` entry covers.

The verdict is deferred until the first data segment exists, so a denial is a
mid-connection drop: `nc` connects, writes, and then stalls until its timeout rather than
failing at `connect`. Give the daemon a few seconds after applying the policy before the
first attempt behaves differently.

## Clean up

```bash
kubectl delete rpol protocol-default-deny
kubectl delete -f client.yaml -f target.yaml
```
