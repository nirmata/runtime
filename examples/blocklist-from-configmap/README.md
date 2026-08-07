# Egress blocklist managed in a ConfigMap

## What this shows

The deny list lives outside the policy. `resource.get("v1", "configmaps", "default",
"ip-blocklist").data["ips"].split(",")` reads the ConfigMap at evaluation time, so a
security team can change the blocklist without touching the `RuntimePolicy` and without a
Nirmata Runtime restart.

`evaluationInterval: 30s` is what makes that work: the expression is evaluated on that
cadence, and the resulting deny list is diffed into the kernel maps. Without it the policy
would only be re-evaluated when the policy or a matched pod changes, and a ConfigMap edit
would go unnoticed.

Every value the expression returns must be programmable — an IPv4 address, an IPv4 CIDR of
`/24` or narrower, a fully qualified domain name, or the `"*"` default-deny sentinel. An
IPv6 literal, or a CIDR wider than `/24`, is rejected and surfaces as a
`TargetsValid=False` condition naming the value.

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support;
a stock kind cluster on a Linux host qualifies.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).

The chart's default ClusterRole grants the daemon no access to ConfigMaps, so the
`resource` lookup fails until you add a rule. `rbac-values.yaml` in this directory is the
values snippet:

```bash
helm upgrade kyverno-runtime oci://ghcr.io/nirmata/kyverno-runtime/kyverno-runtime \
  --namespace kyverno-runtime --reuse-values -f rbac-values.yaml
```

The expression names the `default` namespace, so apply the manifests there.

The policy runs in `mode: enforce`.

## Run it

1. Start the target, the client and the initial blocklist:

   ```bash
   kubectl apply -f configmap.yaml
   kubectl apply -f target.yaml
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/blocklist-target pod/blocklist-client
   ```

   The shipped ConfigMap lists one documentation-range address, so the blocklist starts out
   with nothing the client would ever contact.

2. Apply the policy and confirm the target is reachable:

   ```bash
   kubectl apply -f policy.yaml
   TARGET=$(kubectl get pod blocklist-target -o jsonpath='{.status.podIP}')
   kubectl exec blocklist-client -- wget -q -T 3 -O /dev/null "http://${TARGET}:8080/"; echo "before exit=$?"
   kubectl get rpol blocklist-from-configmap
   ```

   `Applied=True` with reason `Enforcing`, `TargetsValid=True`, and `before exit=0`.

3. Add the target's address to the blocklist. No policy edit:

   ```bash
   kubectl patch configmap ip-blocklist --type merge \
     -p "{\"data\":{\"ips\":\"192.0.2.55,${TARGET}\"}}"
   ```

## Verify

Both directions matter: the same command that succeeded in step 2 must now fail, and it
must fail because of the ConfigMap edit alone.

```bash
sleep 35
kubectl exec blocklist-client -- wget -q -T 3 -O /dev/null "http://${TARGET}:8080/"; echo "after exit=$?"
```

- `after exit=1` — the next evaluation picked up the new entry and programmed it. The wait
  is bounded by `evaluationInterval`.
- Remove the entry again and the address becomes reachable within another interval, which
  is the check that the deny list is being diffed rather than accumulated:

  ```bash
  kubectl patch configmap ip-blocklist --type merge -p '{"data":{"ips":"192.0.2.55"}}'
  sleep 35
  kubectl exec blocklist-client -- wget -q -T 3 -O /dev/null "http://${TARGET}:8080/"; echo "restored exit=$?"
  ```

If `after exit=0` never changes, check the daemon logs for a ConfigMap access error — that
is the missing RBAC rule above.

## Clean up

```bash
kubectl delete rpol blocklist-from-configmap
kubectl delete -f client.yaml -f target.yaml -f configmap.yaml
```
