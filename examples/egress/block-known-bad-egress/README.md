# Block known-bad egress

## What this shows

A single denied destination address. The policy selects the `egress-client` pod by label
and denies its egress to one IPv4 address in `enforce` mode. Every other destination the
pod uses is untouched, so the block is visible as one command that stops working while a
second, near-identical command keeps working.

The denied address belongs to a pod in the cluster (`egress-target-denied`). In a real
policy this is where a threat-intel address goes; here it is an in-cluster HTTP server so
that both the before state and the after state are unambiguous. `egress-target-allowed`
serves the same content from a different address and is never denied — it is the control.

Because egress matching is by destination IPv4 address, the address is only known once the
target pod is running, so the policy ships as `policy.tmpl.yaml` and one `sed` fills the
address in.

This is the scenario the [quickstart](../../../docs/users/quickstart.md) walks through.

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support;
a stock kind cluster on a Linux host qualifies.

Nirmata Runtime must already be installed — see
[installation](../../../docs/users/installation.md).

## Run it

Run these from this directory.

1. Start the client and the two targets, and wait for them:

   ```bash
   kubectl apply -f client.yaml -f targets.yaml
   kubectl wait --for=condition=Ready pod/egress-client pod/egress-target-denied pod/egress-target-allowed --timeout=90s
   ```

2. Record both target addresses:

   ```bash
   DENIED=$(kubectl get pod egress-target-denied -o jsonpath='{.status.podIP}')
   ALLOWED=$(kubectl get pod egress-target-allowed -o jsonpath='{.status.podIP}')
   echo "denied=$DENIED allowed=$ALLOWED"
   ```

3. Confirm the client can reach both before any policy exists:

   ```bash
   kubectl exec egress-client -- wget -q -T 3 -O - "http://$DENIED:8080/"
   kubectl exec egress-client -- wget -q -T 3 -O - "http://$ALLOWED:8080/"
   ```

   Each prints `ok`.

4. Apply the policy with the denied address filled in:

   ```bash
   sed "s/DENIED_IP/$DENIED/" policy.tmpl.yaml | kubectl apply -f -
   ```

   The applied policy is this, with `DENIED_IP` replaced:

   ```yaml
   apiVersion: runtime.nirmata.io/v1alpha1
   kind: RuntimePolicy
   metadata:
     name: block-known-bad-egress
   spec:
     mode: enforce
     podSelector:
       matchLabels:
         app: egress-client
     behaviors:
     - network:
         deny:
           values:
           - "10.244.0.8"
   ```

## Verify

The policy reports that a daemon has it loaded, and in which mode:

```bash
kubectl get rpol block-known-bad-egress
```

```text
NAME                     MODE      APPLIED   REASON      AGE
block-known-bad-egress   enforce   True      Enforcing   20s
```

The denied address is now unreachable from that pod:

```bash
kubectl exec egress-client -- wget -q -T 3 -O - "http://$DENIED:8080/"
echo "exit=$?"
```

This prints a non-zero `exit=` and no `ok`. The daemon programs the kernel map on its own
schedule, so retry for a few seconds if the first attempt still prints `ok`.

Both directions matter: a policy that broke all networking would also pass the check
above. The control address, which the policy does not deny, still works:

```bash
kubectl exec egress-client -- wget -q -T 3 -O - "http://$ALLOWED:8080/"
```

This still prints `ok`.

## Clean up

```bash
kubectl delete -f client.yaml -f targets.yaml
kubectl delete rpol block-known-bad-egress
```
