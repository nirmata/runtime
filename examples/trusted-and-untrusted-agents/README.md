# A trusted agent and an untrusted one, under one runtime

## What this shows

Two workloads that need opposite treatment, expressed with the same primitives.

The **trusted agent** is one the platform team runs and has declared. It gets a hard
boundary: TLS, to one Service, and nothing else. Both behaviors carry the `"*"` sentinel,
so each is deny-all-except-allowed, and a connection has to satisfy both — the right
destination over the wrong protocol is denied, and so is TLS to anywhere else.

The **untrusted agent** is one nobody declared: a sidecar someone added, a base image with
an SDK compiled in, a developer's script. Blocking it would break work nobody has audited
yet, so the policy does not block. It reports every LLM provider name the workload
resolves, which is the question an operator actually has about a workload they did not
deploy: *is this thing talking to a model, and which one?*

The asymmetry is the point. Enforcement needs a declared, testable destination; discovery
does not, and paying for it with a `monitor` policy costs nothing the workload can notice.

## Requires

- **Trusted policy**: cgroup v2 and BPF, for the egress and protocol classifiers. A stock
  kind cluster on a Linux host qualifies. No BPF-LSM.
- **Untrusted policy**: DNS question observation, same requirement.

Nirmata Runtime must be installed — see [installation](../../docs/users/installation.md).

## Run it

```sh
kubectl apply -f clients.yaml
kubectl apply -f trusted-policy.yaml
kubectl apply -f untrusted-policy.yaml
```

The trusted policy names `kubernetes.default.svc.cluster.local` so the example runs with
no extra infrastructure — the API server is a real Service serving real TLS. Swap in your
gateway Service; the value must be the full `<name>.<namespace>.svc.cluster.local` form,
since a shorter one is treated as an ordinary domain and never matches what the hook
observes.

### The trusted agent

Allowed — TLS to the named Service:

```sh
kubectl exec trusted-agent -- curl -sS -o /dev/null -k https://kubernetes.default.svc
```

Denied — TLS to somewhere else:

```sh
kubectl exec trusted-agent -- curl -sS -m 5 https://api.openai.com
```

Denied — the right destination, wrong protocol. The connection is refused by the protocol
behavior, not the network one:

```sh
kubectl exec trusted-agent -- curl -sS -m 5 http://kubernetes.default.svc
```

### The untrusted agent

Nothing is blocked. Resolving a provider name produces a finding:

```sh
kubectl exec untrusted-agent -- curl -sS -m 5 -o /dev/null https://api.anthropic.com
kubectl exec untrusted-agent -- nslookup api.openai.com
```

Resolving anything else does not:

```sh
kubectl exec untrusted-agent -- nslookup example.com
```

```sh
kubectl get reports -A -l kyverno-runtime/policy=untrusted-agent-llm-egress
```

Findings are advisory: `result: warn`, `enforced: "false"`, and no "would have been denied"
wording, because nothing was blocked.

## Reading the policies

`*.openai.com` covers `api.openai.com` and not the apex `openai.com`, which is why any
provider whose apex serves the API is listed twice. A wildcard matches on a label boundary,
so `*.openai.com` does not cover `evilopenai.com`.

A wildcard is the leftmost label and nothing else, which decides how two providers can be
written at all. Bedrock's region sits in the middle of `bedrock-runtime.us-east-1.amazonaws.com`,
so each region is its own value and a region nobody listed is not reported. Vertex puts its
region in a *prefix* of one label — `us-central1-aiplatform.googleapis.com` — so the only
expressible form is `*.googleapis.com`, which also reports `storage.googleapis.com` and the
rest of Google's APIs. Both are the honest reading: a value that matched neither would look
correct and report nothing.

Naming the providers in `deny` rather than putting `"*"` there is what keeps the report
readable. `deny.values: ["*"]` reports every name the workload resolves — the discovery
form to start from when you do not yet know what a workload talks to, shown in
[report-unexpected-dns](../report-unexpected-dns/). The inverse shape, an `allow` list of
the names a workload is *expected* to resolve, is the one to grow into once the trusted
agent's traffic is understood.

## What this does not cover

- **An agent that skips DNS.** A workload dialling a hardcoded address sends no question,
  so the untrusted policy reports nothing. Catching that needs a `network` behavior in
  `monitor` mode with `deny.values: ["*"]`, which reports every destination and is
  correspondingly noisy.
- **Which model, which prompt, which tool.** The trusted agent's TLS is opaque here: the
  classifier sees a handshake and its ALPN, never what travels inside. Deciding about the
  content of a model call belongs to a proxy that terminates the TLS.
- **A provider not on the list.** The deny list is a list of names, and a new endpoint is
  a name nobody has added yet. This trades coverage for a readable report; the discovery
  form above is what closes the gap, at the cost of volume.
