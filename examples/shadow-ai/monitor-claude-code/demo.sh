#!/usr/bin/env bash

set -euo pipefail

example_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cluster_name=${KIND_CLUSTER_NAME:-kyverno-runtime}
image=nirmata-claude-code-demo:local
claude_code_version=${CLAUDE_CODE_VERSION:-latest}

if [[ ${1:-} == cleanup ]]; then
  kubectl delete runtimepolicy monitor-claude-code --ignore-not-found
  kubectl delete pod claude-code-demo --ignore-not-found
  kubectl delete secret claude-code-demo-auth --ignore-not-found
  exit
fi

if [[ -z ${ANTHROPIC_API_KEY:-} ]]; then
  echo "ANTHROPIC_API_KEY must be set" >&2
  exit 1
fi

for command in docker kind kubectl; do
  if ! command -v "$command" >/dev/null; then
    echo "$command is required" >&2
    exit 1
  fi
done

docker build \
  --build-arg CLAUDE_CODE_VERSION="$claude_code_version" \
  -t "$image" "$example_dir"
kind load docker-image --name "$cluster_name" "$image"

kubectl create secret generic claude-code-demo-auth \
  --from-literal=ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$example_dir/policy.yaml"
kubectl apply -f "$example_dir/pod.yaml"
kubectl wait --for=condition=Ready pod/claude-code-demo --timeout=120s
kubectl wait \
  --for=jsonpath='{.status.conditions[?(@.type=="PodsMatched")].status}'=True \
  runtimepolicy/monitor-claude-code --timeout=90s

kubectl exec claude-code-demo -- claude --bare -p \
  "Inspect this container: run uname -a and pwd, read /etc/os-release, then write a short summary to /workspace/claude-observation-demo.txt." \
  --allowedTools "Bash,Read,Write" \
  --permission-mode dontAsk \
  --max-turns 5 \
  --max-budget-usd 0.50

echo "Waiting for observation polling and report flushing..."
for _ in {1..30}; do
  if kubectl get report kyverno-runtime-claude-code-demo >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

kubectl get report kyverno-runtime-claude-code-demo \
  -o jsonpath='{range .results[*]}{.rule}{"\t"}{.description}{"\n"}{end}'

echo
echo "Full report: kubectl get report kyverno-runtime-claude-code-demo -o yaml"
echo "Cleanup: $example_dir/demo.sh cleanup"
