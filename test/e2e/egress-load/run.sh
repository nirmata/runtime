#!/usr/bin/env bash
#
# Egress load harness. Runs k6 in the cluster against an allow-listed Service and
# a denied CIDR, then asserts what the load is actually for: that the observation
# plane neither loses events silently nor grows the Report with request volume.
#
# There is deliberately no chainsaw-test.yaml in this directory. E2E_HOSTED_DIRS
# globs test/e2e/*/chainsaw-test.yaml, so adding one would enrol a two-minute
# load run into the parallel correctness lane, where it would contend with the
# suites it is supposed to be measuring against.
#
# Requires: a cluster with the chart installed (make kind-install), kubectl and
# curl on the host. k6 runs as a pod, so no local install.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NAMESPACE="${NAMESPACE:-egress-load}"
DAEMON_NAMESPACE="${DAEMON_NAMESPACE:-kyverno-runtime}"
DENIED_ADDR="${DENIED_ADDR:-203.0.113.10:80}"
METRICS_PORT="${METRICS_PORT:-19090}"
# The load hits two destinations under two policies. Findings are fingerprinted
# per (policy, pod, behavior, destination), so the ceiling is small and fixed;
# the slack absorbs anything else the k6 image happens to dial.
MAX_RESULTS="${MAX_RESULTS:-16}"
# Below this the run did not generate enough traffic for the comparison against
# MAX_RESULTS to mean anything.
MIN_REQS="${MIN_REQS:-1000}"
KEEP="${KEEP:-0}"

policies="e2e-egress-load-enforce e2e-egress-load-monitor"
pf_pid=""

cleanup() {
  if [ -n "${pf_pid}" ]; then
    kill "${pf_pid}" 2>/dev/null || true
  fi
  if [ "${KEEP}" = "1" ]; then
    echo "KEEP=1: leaving namespace ${NAMESPACE} and the policies in place"
    return
  fi
  # shellcheck disable=SC2086
  kubectl delete runtimepolicy ${policies} --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete namespace "${NAMESPACE}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  kubectl -n "${DAEMON_NAMESPACE}" logs -l app.kubernetes.io/name=kyverno-runtime \
    --all-containers --tail=200 2>/dev/null || true
  exit 1
}

# scrape_metrics <outfile> appends every daemon pod's /metrics to outfile.
scrape_metrics() {
  local out="$1" pod scraped
  : > "${out}"
  for pod in $(kubectl -n "${DAEMON_NAMESPACE}" get pods -l app.kubernetes.io/name=kyverno-runtime \
                 -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'); do
    kubectl -n "${DAEMON_NAMESPACE}" port-forward "pod/${pod}" "${METRICS_PORT}:9090" \
      >/tmp/egress-load-pf.log 2>&1 &
    pf_pid=$!
    scraped=0
    sleep 3   # give a moment to the port foward to be fully initialized
    for _ in $(seq 1 30); do
      if curl -sS -m 2 "http://127.0.0.1:${METRICS_PORT}/metrics" >> "${out}"; then
        scraped=1
        break
      fi
      sleep 1
    done
    kill "${pf_pid}" 2>/dev/null || true
    wait "${pf_pid}" 2>/dev/null || true
    pf_pid=""
    [ "${scraped}" -eq 1 ] || fail "could not scrape /metrics from ${pod}: $(cat /tmp/egress-load-pf.log)"
  done
}

# count_map_full_drops <metricsfile> <source-label>
count_map_full_drops() {
  grep '^nirmata_runtime_events_dropped_total{' "$1" 2>/dev/null \
    | grep "source=\"$2\"" \
    | grep 'reason="count_map_full"' \
    | awk '{s += $NF} END {print s + 0}' || true
}

daemon_restarts() {
  kubectl -n "${DAEMON_NAMESPACE}" get pods -l app.kubernetes.io/name=kyverno-runtime \
    -o jsonpath='{.items[*].status.containerStatuses[*].restartCount}' \
    | tr ' ' '\n' | awk '{s += $1} END {print s + 0}'
}

echo "== namespace ${NAMESPACE}"
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "== target Deployment and Service"
kubectl -n "${NAMESPACE}" apply -f "${here}/manifests/target.yaml"
kubectl -n "${NAMESPACE}" rollout status deployment/egress-load-target --timeout=180s

allowed_ip="$(kubectl -n "${NAMESPACE}" get svc egress-load-target -o jsonpath='{.spec.clusterIP}')"
[ -n "${allowed_ip}" ] || fail "Service egress-load-target has no ClusterIP"
allowed_addr="${allowed_ip}:80"
echo "allowed=${allowed_addr} denied=${DENIED_ADDR}"

echo "== policies"
sed "s/TEST_NAMESPACE/${NAMESPACE}/" "${here}/manifests/policies.tmpl.yaml" \
  | kubectl apply -f -
# A rejected target programs nothing, and nothing programmed satisfies every
# bound below for the wrong reason.
for p in ${policies}; do
  ok=0
  for _ in $(seq 1 60); do
    status="$(kubectl get "runtimepolicy/${p}" \
      -o jsonpath="{.status.conditions[?(@.type=='TargetsValid')].status}" 2>/dev/null || true)"
    if [ "${status}" = "True" ]; then
      ok=1
      break
    fi
    sleep 2
  done
  [ "${ok}" -eq 1 ] \
    || fail "policy ${p} never reported TargetsValid=True: $(kubectl get "runtimepolicy/${p}" -o jsonpath="{.status.conditions}")"
done

restarts_before="$(daemon_restarts)"
echo "== daemon restarts before: ${restarts_before}"
scrape_metrics /tmp/egress-load-metrics-before.txt
drops_before_egress="$(count_map_full_drops /tmp/egress-load-metrics-before.txt egress-observe)"
echo "== count_map_full before: egress-observe=${drops_before_egress}"

echo "== k6"
kubectl -n "${NAMESPACE}" delete configmap egress-load-script egress-load-env --ignore-not-found
kubectl -n "${NAMESPACE}" create configmap egress-load-script \
  --from-file="k6-egress-storm.js=${here}/k6-egress-storm.js"
kubectl -n "${NAMESPACE}" create configmap egress-load-env \
  --from-literal="ALLOWED_ADDR=${allowed_addr}" \
  --from-literal="DENIED_ADDR=${DENIED_ADDR}"
kubectl -n "${NAMESPACE}" apply -f "${here}/manifests/k6.yaml"

# Both terminal phases end the wait: a generator that crashed has to be reported
# as a crashed generator, not as a timeout.
phase=""
for _ in $(seq 1 120); do
  phase="$(kubectl -n "${NAMESPACE}" get pod egress-load-k6 -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  case "${phase}" in
    Succeeded|Failed) break ;;
  esac
  sleep 5
done
echo "--- k6 output ---"
kubectl -n "${NAMESPACE}" logs pod/egress-load-k6 || true
[ "${phase}" = "Succeeded" ] || fail "k6 pod ended in phase '${phase:-unknown}'"

reqs="$(kubectl -n "${NAMESPACE}" logs pod/egress-load-k6 2>/dev/null \
  | sed -n 's/^K6_HTTP_REQS=\([0-9][0-9]*\).*/\1/p' | tail -1)"
[ -n "${reqs}" ] || fail "k6 did not report a request total"
[ "${reqs}" -ge "${MIN_REQS}" ] \
  || fail "k6 made only ${reqs} requests (need >= ${MIN_REQS}); the run is too small to bound anything"
echo "== k6 requests: ${reqs}"

# One observe interval plus one report flush, so the last observations reach the
# Report before it is read.
sleep 25

echo "== drop accounting"
scrape_metrics /tmp/egress-load-metrics-after.txt
grep '^nirmata_runtime_events_dropped_total{' /tmp/egress-load-metrics-after.txt \
  || echo "(no drop series at all)"

drops_after_egress="$(count_map_full_drops /tmp/egress-load-metrics-after.txt egress-observe)"
delta=$(( drops_after_egress - drops_before_egress ))
echo "count_map_full during the run: egress-observe delta=${delta}"

# A full count map is legitimate under load. Silence is not: the metric and the
# operator-visible log line are one signal, and a metric that moved without a log
# line means the drop path stopped reporting itself.
if [ "${delta}" -gt 0 ]; then
  if kubectl -n "${DAEMON_NAMESPACE}" logs -l app.kubernetes.io/name=kyverno-runtime \
       --all-containers --tail=2000 2>/dev/null | grep -q "kernel dropped egress observations"; then
    echo "OK: ${delta} dropped observations, accounted for in both the metric and the log"
  else
    fail "events_dropped_total moved by ${delta} count_map_full drops but the daemon logged none of them"
  fi
else
  echo "OK: no observations dropped"
fi

echo "== daemon health"
restarts_after="$(daemon_restarts)"
[ "${restarts_after}" -eq "${restarts_before}" ] \
  || fail "daemon restarted under load (${restarts_before} -> ${restarts_after})"
echo "OK: daemon restartCount unchanged at ${restarts_after}"

echo "== report shape"
kubectl -n "${NAMESPACE}" get reports.openreports.io \
  -o jsonpath='{range .items[*].results[*]}{.policy}{" "}{.rule}{" "}{.properties.destIP}{" "}{.properties.enforced}{" "}{.properties.count}{"\n"}{end}' \
  > /tmp/egress-load-results.txt \
  || fail "no Report in ${NAMESPACE}; ${reqs} requests produced no findings at all"

echo "--- results (policy rule destIP enforced count) ---"
cat /tmp/egress-load-results.txt
results="$(grep -c . /tmp/egress-load-results.txt || true)"
[ "${results}" -gt 0 ] || fail "${reqs} requests produced an empty Report"

# The invariant the load exists to test: the Report is sized by the number of
# distinct (destination, decision) pairs the policies name, not by how many
# packets went to them.
if [ "${results}" -gt "${MAX_RESULTS}" ]; then
  fail "${results} results from ${reqs} requests exceeds the ${MAX_RESULTS} the destinations can explain; findings are tracking request volume"
fi
echo "OK: ${results} results from ${reqs} requests"

kubectl -n "${NAMESPACE}" get reports.openreports.io -o yaml
echo "PASS"
