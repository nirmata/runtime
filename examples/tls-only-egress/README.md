# TLS-only egress, classified from the wire

## What this shows

Constrain a pod to speaking only TLS, and prove that the constraint is about the protocol
rather than the port. A single plain-TCP listener on port 443 answers every probe, so the
destination, the port and the server are identical across all of them. The only thing that
varies is the bytes the client sends first, and that is what the classifier reads.

`deny.values: ["*"]` on the `protocol` behavior is the same default-deny sentinel the
`network` behavior uses: it flips the pod from allow-all-except-denied to
deny-all-except-allowed. The `allow` list then names the only protocols the pod may still
speak — here `tls`, plus `dns` so the workload keeps resolving names.

Traffic that matches no signature classifies as `unclassified`. That is not a value a
policy can allow, so under this default deny it is denied. An SSH client on port 443 is
denied because it is SSH, not because of where it is going.

## Requires

Network egress enforcement requires only a cgroup v2 host and BPF support; a stock kind
cluster on a Linux host qualifies.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).
The policy runs in `mode: enforce`.

## Run it

1. Start the target and the client:

   ```bash
   kubectl apply -f target.yaml
   kubectl apply -f client.yaml
   kubectl wait --for=condition=Ready pod/protocol-target pod/protocol-client
   ```

2. Record the target IP and confirm every probe reaches it before any policy exists. If
   this step fails, the "blocked" results below would prove nothing:

   ```bash
   IP=$(kubectl get pod protocol-target -o jsonpath='{.status.podIP}')

   # cleartext HTTP/1.1
   kubectl exec protocol-client -- sh -c \
     "printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 3 ${IP} 443" | head -1

   # an SSH client banner
   kubectl exec protocol-client -- sh -c \
     "printf 'SSH-2.0-OpenSSH_9.6\r\n' | nc -w 3 ${IP} 443" | head -1
   ```

   Both print a response line: the listener answers real HTTP with `200` and anything else
   with `400`, so a delivered segment always produces bytes.

3. Apply the policy and wait for it to be programmed:

   ```bash
   kubectl apply -f policy.yaml
   kubectl wait --for=condition=Applied rpol/tls-only-egress
   ```

4. Re-run both probes. Each now produces no output at all — the first data segment is
   dropped in the kernel, so the connection stalls and `nc` times out:

   ```bash
   kubectl exec protocol-client -- sh -c \
     "printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 3 ${IP} 443" | head -1   # denied: http/1.1
   kubectl exec protocol-client -- sh -c \
     "printf 'SSH-2.0-OpenSSH_9.6\r\n' | nc -w 3 ${IP} 443" | head -1   # denied: ssh on 443
   kubectl exec protocol-client -- sh -c \
     "printf 'not a protocol' | nc -w 3 ${IP} 443" | head -1            # denied: unclassified
   ```

5. Confirm DNS still resolves, since `dns` is allowed:

   ```bash
   kubectl exec protocol-client -- nslookup kubernetes.default.svc.cluster.local
   ```

6. Clean up:

   ```bash
   kubectl delete -f policy.yaml -f client.yaml -f target.yaml
   ```

## What to notice

The three denied probes and the allowed DNS lookup differ only in their first bytes. No
port, address or Service distinguishes them, which is the point: a `network` policy or a
NetworkPolicy allowing port 443 permits all three.

Denial is a dropped first data segment rather than a TCP reset, so a blocked client sees a
stall and a timeout instead of a refused connection. `cgroup_skb` cannot forge a reset.

HTTP/3 would also be denied here. It classifies as `quic`, not `tls`, so an allow list
written to mean "only HTTPS" blocks QUIC-capable clients. That is the safer default —
HTTP/3 bypasses a TCP-based TLS inspection proxy. To permit both, write
`allow: ["tls", "quic", "dns"]` and accept that the QUIC half cannot be inspected.

The full set of protocol values and the boundaries of classification are in the
[RuntimePolicy reference](../../docs/users/reference/runtimepolicy.md#limits-of-protocol-classification).
