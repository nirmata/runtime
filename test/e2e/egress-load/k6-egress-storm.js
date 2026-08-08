// Egress load generator for the observation plane.
//
// Both destinations are addresses, never names: the enforce policy under test
// default-denies egress for this pod, so a DNS lookup would itself be dropped
// and every request would fail for a reason that has nothing to do with the
// policy. run.sh resolves the Service ClusterIP on the host and passes both
// through the environment.
//
// Nothing here asserts. The assertions are in run.sh, against the daemon's
// /metrics and the Report it wrote -- a threshold on the client would only
// re-measure the client.
import http from 'k6/http';
import { sleep } from 'k6';

const allowed = `http://${__ENV.ALLOWED_ADDR}/`;
const denied = `http://${__ENV.DENIED_ADDR}/`;

export const options = {
  scenarios: {
    storm: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '30s', target: 25 },
        { duration: '60s', target: 50 },
        { duration: '30s', target: 0 },
      ],
      gracefulRampDown: '5s',
    },
  },
};

export function setup() {
  // The daemon programs the cgroup maps from its own informer events, so the
  // first requests of an unpaced run would race the attach and land before
  // enforcement exists.
  sleep(15);
}

export default function () {
  http.get(allowed, { timeout: '3s', tags: { dest: 'allowed' } });
  http.get(denied, { timeout: '3s', tags: { dest: 'denied' } });
}

// Replaces the default summary with one line run.sh can read. The request total
// is the whole point of the comparison it makes: findings must be bounded by the
// number of distinct destinations, not by this number.
export function handleSummary(data) {
  const reqs = data.metrics.http_reqs ? data.metrics.http_reqs.values.count : 0;
  return { stdout: `K6_HTTP_REQS=${reqs}\n` };
}
