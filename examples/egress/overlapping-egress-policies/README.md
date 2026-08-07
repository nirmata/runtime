# Two policies over one pod

## What this shows

Nothing stops two `RuntimePolicy` objects from selecting the same pod, and they share one
set of eBPF maps. The interesting case is what happens when one of them goes away: an
address both policies asked for must survive, and an address only the departing policy
asked for must not.

Both policies here set a default deny. `overlap-shared` is allow-listed by both;
`overlap-single` only by `overlap-a`. Deleting `overlap-a` should revoke exactly one of
them.

## Requires

cgroup v2 and BPF — a stock kind cluster qualifies. No BPF-LSM needed.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).
Both policies run in `mode: enforce`, and assume the `default` namespace.

## Run it

```bash
kubectl apply -f backends.yaml -f client.yaml
kubectl wait --for=condition=Ready pod/overlap-shared-backend pod/overlap-single-backend pod/overlap-client
kubectl apply -f policies.yaml
kubectl get rpol overlap-a overlap-b
```

## Verify

Both allow-listed Services answer while both policies exist:

```bash
kubectl exec overlap-client -- wget -q -T 3 -O /dev/null http://overlap-shared/; echo "shared exit=$?"
kubectl exec overlap-client -- wget -q -T 3 -O /dev/null http://overlap-single/; echo "single exit=$?"
```

Now delete the policy that is the sole owner of one of them:

```bash
kubectl delete rpol overlap-a
sleep 5
kubectl exec overlap-client -- wget -q -T 3 -O /dev/null http://overlap-shared/; echo "shared after delete exit=$?"
kubectl exec overlap-client -- wget -q -T 3 -O /dev/null http://overlap-single/; echo "single after delete exit=$?"
```

- `shared after delete exit=0` — `overlap-b` still wants it, so it stays programmed.
- `single after delete exit=1` — nothing wants it any more, and `overlap-b`'s default deny
  still applies.

The same refcount governs the default-deny flag itself: it clears only when the last
policy asking for it detaches. Delete `overlap-b` too and the pod's egress opens up again.

## Clean up

```bash
kubectl delete rpol overlap-a overlap-b --ignore-not-found
kubectl delete -f client.yaml -f backends.yaml
```
