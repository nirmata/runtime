# Egress blocklist parsed out of a JSON blob

## What this shows

The three CEL libraries composing. A `spec.variables` entry calls `resource.get(...)` to
read a ConfigMap and hands the raw string to `json.unmarshal(...)`; the behavior expression
then indexes into the parsed object and coerces the result with
`variables.blocklist["ips"].map(x, string(x))`.

The coercion is required, not decorative: `json.unmarshal` returns `dyn`, and a rule's
expression must type-check to `list(string)`. Staging the parse in a variable keeps the
behavior expression readable and lets several behaviors share one parsed document.

This runs in `mode: monitor`, so a match is reported and not blocked — the deny list is
sourced from mutable external state, and observing what it would block is the safer first
step. Switching `mode` to `enforce` blocks the same addresses with no other change.

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support;
a stock kind cluster on a Linux host qualifies.

Nirmata Runtime must be installed — see [installation](../../../docs/users/installation.md).

The chart's default ClusterRole grants the daemon no access to ConfigMaps, so the
`resource` lookup fails until you add a rule. `rbac-values.yaml` in this directory is the
values snippet:

```bash
helm upgrade kyverno-runtime oci://ghcr.io/nirmata/charts/kyverno-runtime \
  --namespace kyverno-runtime --reuse-values -f rbac-values.yaml
```

The expression names the `default` namespace, so apply the manifests there.

The policy runs in `mode: monitor`.

## Run it

1. Start the target, the client and the JSON blocklist:

   ```bash
   kubectl apply -f configmap.yaml
   kubectl apply -f target.yaml
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/json-target pod/json-client
   ```

2. Put the target's address in the JSON document. `kubectl create --dry-run` keeps the
   value a single JSON string rather than trying to patch inside one:

   ```bash
   TARGET=$(kubectl get pod json-target -o jsonpath='{.status.podIP}')
   kubectl create configmap ip-blocklist-json \
     --from-literal=ips="{\"ips\": [\"${TARGET}\"]}" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

3. Apply the policy and make the client connect to the listed address:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol blocklist-from-json
   kubectl exec json-client -- wget -q -T 3 -O /dev/null "http://${TARGET}:8080/"; echo "exit=$?"
   ```

   `Applied=True` with reason `Monitoring`.

## Verify

Two things have to be true: the listed address was still reachable, and the attempt was
reported.

- `exit=0` above. Monitor mode leaves the kernel maps empty, so a listed address is
  observed rather than blocked.
- A Report result names the policy. Observation is poll-based: counters are drained every
  `--observe-interval` (10s by default) and findings are flushed every 10s, so allow up to
  ~20 seconds.

  ```bash
  kubectl get report "kyverno-runtime-$(kubectl get pod json-client -o jsonpath='{.spec.nodeName}')" \
    -o yaml
  ```

  The result carries `policy: blocklist-from-json`, `rule: network`, `result: fail`,
  `subjects[0]` naming `json-client`, and a `destIP` property equal to `$TARGET`. The
  `enforced: "false"` property is what distinguishes "would have been denied" from a
  kernel block.

If no result appears, check the daemon logs for a ConfigMap access error — that is the
missing RBAC rule above — and confirm the JSON in the ConfigMap parses.

## Clean up

```bash
kubectl delete rpol blocklist-from-json
kubectl delete -f client.yaml -f target.yaml -f configmap.yaml
```
