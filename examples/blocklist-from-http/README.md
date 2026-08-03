# Egress blocklist from an HTTP feed

## What this shows

The deny list is pulled from an HTTP endpoint at evaluation time, the shape a
threat-intelligence feed takes. `http.get(url)` returns a value shaped like
`{"statusCode": ..., "body": ...}`, and `body` is `dyn`, so the CEL checker cannot infer
that it is a list of strings. `.map(x, string(x))` is the coercion that gives the
expression the `list(string)` type every rule requires.

`evaluationInterval: 30s` re-fetches the feed on that cadence. Without it the policy would
be evaluated only when the policy or a matched pod changes, and the feed could go stale
indefinitely.

The feed pod serves its own pod IP, so the deny list resolves to a real in-cluster
destination without any manifest carrying a placeholder. A second pod that the feed does
not list is the control.

## Requires

Network egress enforcement and observation require only a cgroup v2 host and BPF support;
a stock kind cluster on a Linux host qualifies.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy's URL names the `default` namespace, so apply the manifests there. No extra
RBAC is needed: the daemon fetches over the network rather than through the API server.

The policy runs in `mode: enforce`.

## Run it

1. Start the feed, the control target and the client:

   ```bash
   kubectl apply -f ip-server.yaml
   kubectl apply -f target.yaml
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/ip-server pod/http-target pod/http-client
   ```

2. Look at what the feed serves and confirm both destinations are reachable before the
   policy exists:

   ```bash
   kubectl exec http-client -- wget -q -T 3 -O - http://ip-server.default.svc.cluster.local:8080
   FEED=$(kubectl get pod ip-server -o jsonpath='{.status.podIP}')
   CONTROL=$(kubectl get pod http-target -o jsonpath='{.status.podIP}')
   kubectl exec http-client -- wget -q -T 3 -O /dev/null "http://${FEED}:8080/"; echo "baseline feed exit=$?"
   kubectl exec http-client -- wget -q -T 3 -O /dev/null "http://${CONTROL}:8080/"; echo "baseline control exit=$?"
   ```

   The feed returns a JSON array holding one address: its own pod IP.

3. Apply the policy:

   ```bash
   kubectl apply -f policy.yaml
   kubectl get rpol blocklist-from-http
   ```

   `Applied=True` with reason `Enforcing`, and `TargetsValid=True` — the fetched value was
   programmable.

## Verify

Both directions matter. A check that only asserts the listed address is unreachable would
also pass against a program that drops every packet.

```bash
kubectl exec http-client -- wget -q -T 3 -O /dev/null "http://${FEED}:8080/"; echo "listed exit=$?"
kubectl exec http-client -- wget -q -T 3 -O /dev/null "http://${CONTROL}:8080/"; echo "unlisted exit=$?"
```

- `listed exit=1` — the address the feed returned is blocked in the kernel.
- `unlisted exit=0` — the address the feed did not return is untouched.

The daemon reaches the feed through cluster DNS and a ClusterIP Service; the client pod's
egress restrictions do not apply to it. If `TargetsValid` is `False`, the feed returned a
value that cannot be programmed — the condition message names it.

## Clean up

```bash
kubectl delete rpol blocklist-from-http
kubectl delete -f client.yaml -f target.yaml -f ip-server.yaml
```
