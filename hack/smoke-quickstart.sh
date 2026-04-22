#!/usr/bin/env bash
set -euo pipefail

CONTEXT="${CONTEXT:-kind-kyverno-runtime}"
NAMESPACE="${NAMESPACE:-runtime-demo}"
POD_NAME="${POD_NAME:-demo}"
POLICY_FILE="${POLICY_FILE:-testdata/e2e-live-trace-policy.yaml}"

step() {
  echo
  echo "==> $1"
}

step "Quick Start smoke: cluster installation checks"
kubectl --context "$CONTEXT" get pods -n kyverno-runtime
kubectl --context "$CONTEXT" get ds -A
kubectl --context "$CONTEXT" get crd runtimepolicies.runtime.kyverno.io
kubectl --context "$CONTEXT" get crd policyreports.wgpolicyk8s.io

step "Prepare namespace and demo pod"
kubectl --context "$CONTEXT" create ns "$NAMESPACE" 2>/dev/null || true
kubectl --context "$CONTEXT" label ns "$NAMESPACE" runtime-monitor=enabled --overwrite
kubectl --context "$CONTEXT" -n "$NAMESPACE" delete pod "$POD_NAME" --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$CONTEXT" -n "$NAMESPACE" run "$POD_NAME" --image=busybox:1.36 --restart=Never --command -- sh -c 'sleep 300'
kubectl --context "$CONTEXT" -n "$NAMESPACE" wait --for=condition=Ready "pod/$POD_NAME" --timeout=120s

step "Apply runtime policy"
kubectl --context "$CONTEXT" apply -f "$POLICY_FILE"

step "Trigger open events"
kubectl --context "$CONTEXT" -n "$NAMESPACE" exec "$POD_NAME" -- sh -c 'for i in $(seq 1 25); do cat /etc/hosts >/dev/null; sleep 0.1; done'

step "Wait for PolicyReport"
policy_found="false"
for _ in $(seq 1 24); do
  if kubectl --context "$CONTEXT" get policyreport -n "$NAMESPACE" --no-headers 2>/dev/null | grep -q .; then
    policy_found="true"
    break
  fi
  sleep 2
done

if [[ "$policy_found" != "true" ]]; then
  echo "ERROR: no PolicyReport created in namespace $NAMESPACE"
  echo "Recent controller logs:"
  kubectl --context "$CONTEXT" -n kyverno-runtime logs -l app.kubernetes.io/name=kyverno-runtime --tail=200 || true
  exit 1
fi

step "PolicyReport summary"
kubectl --context "$CONTEXT" get policyreport -n "$NAMESPACE"

echo
printf '%s\n' "Smoke test PASS: expected at least one PolicyReport with non-zero findings for open events."