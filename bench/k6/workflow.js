// k6 workload for benchmarks P1, P2a, P2b, P3 (EXPERIMENTS.md sections 10-11). One script, parameterised by -e variables.
// Iteration structure (10.1):
//   C   (P2a/P2b): ott_issue -> harness (read OTT from the OOB sink, poll 20 ms up to 2 s) -> op
//   B,D (P2a/P2b):              harness (equivalent sink read, returns empty)                -> op
//   P3  (C only):  ott_issue -> harness (drain)                                              (no op)
//   P1  (A,B):     op = GET /api/profile (no harness step)
// Only `ott_issue` and `op` requests are server measurements. `harness` requests and idle gaps are never measured.
// Every request carries tags bench, config, step. The run is one constant-VU scenario of warmup + measure seconds;
// an iteration belongs to the phase it STARTED in and only 'measure' iterations are recorded.
import http from 'k6/http';
import exec from 'k6/execution';
import { sleep } from 'k6';
import { SharedArray } from 'k6/data';
import { Trend, Counter } from 'k6/metrics';

const BENCH = __ENV.BENCH;             // P1 | P2a | P2b | P3
const CONFIG = __ENV.CONFIG;           // A | B | C | D
const VUS = Number(__ENV.VUS);
const WARMUP_S = Number(__ENV.WARMUP_S);
const MEASURE_S = Number(__ENV.MEASURE_S);
const BASE = __ENV.BASE_URL;
const SINK = __ENV.SINK_URL;
const READ_KEY = __ENV.SINK_READ_KEY;
const PW = __ENV.BENCH_PASSWORD;       // fixed newPassword (and currentPassword for D): credentials never drift
const SUMMARY_PATH = __ENV.SUMMARY_PATH;
const POLL_MS = 20;
const POLL_TIMEOUT_MS = 2000;

const users = new SharedArray('users', () => JSON.parse(open(__ENV.USERS_FILE)));

const mk = (n) => ({ ms: new Trend(`${n}_ms`, true), okMs: new Trend(`${n}_ok_ms`, true), n: new Counter(`${n}_n`),
  fail: new Counter(`${n}_fail`), sum: new Counter(`${n}_sum`), sumsq: new Counter(`${n}_sumsq`) });
const M = { op: mk('op'), issue: mk('issue'), wf: mk('wf') };
const harnessN = new Counter('harness_n');
const harnessFailures = new Counter('harness_failures');
const itersAttempted = new Counter('iters_attempted');
const itersComplete = new Counter('iters_complete');
const itersIncomplete = new Counter('iters_incomplete');
const startMs = new Counter('scenario_start_ms');

export const options = {
  discardResponseBodies: true,
  scenarios: { load: { executor: 'constant-vus', vus: VUS, duration: `${WARMUP_S + MEASURE_S}s`, gracefulStop: '15s' } },
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(95)', 'p(99)'],
  systemTags: ['status', 'method', 'name', 'scenario'],
};

function record(m, res, expectedStatus) {
  const d = res.timings.duration;
  const ok = res.status === expectedStatus;
  m.ms.add(d); m.n.add(1); m.sum.add(d); m.sumsq.add(d * d);
  if (ok) m.okMs.add(d); else m.fail.add(1);
  return ok;
}

function readInbox(userId, tags) {
  return http.get(`${SINK}/inbox/${userId}`, { headers: { 'x-sink-key': READ_KEY }, responseType: 'text', tags });
}

export default function () {
  const u = users[(__VU - 1) % users.length];
  if (__VU === 1 && exec.vu.iterationInScenario === 0) startMs.add(exec.scenario.startTime);
  const elapsed = Date.now() - exec.scenario.startTime;
  const measuring = elapsed >= WARMUP_S * 1000 && elapsed < (WARMUP_S + MEASURE_S) * 1000;
  const auth = { 'Content-Type': 'application/json', Authorization: `Bearer ${u.access}` };
  const tag = (step) => ({ bench: BENCH, config: CONFIG, step });
  if (measuring) itersAttempted.add(1);
  let complete = true; let wf = 0; let ottValue = null;

  const doIssue = () => {
    const operation = BENCH === 'P2b' ? 'confirm_email' : 'change_password';
    const purpose = BENCH === 'P2b' ? 'account_security' : 'change_password';
    const r = http.post(`${BASE}/api/ott/request`, JSON.stringify({ purpose, operation }), { headers: auth, tags: tag('ott_issue') });
    if (measuring) { const ok = record(M.issue, r, 202); if (!ok) complete = false; wf += r.timings.duration; }
    return r.status === 202;
  };
  // Poll the OOB inbox. Returns the OTT, or null after POLL_TIMEOUT_MS (a harness_failure).
  const awaitOtt = () => {
    const t0 = Date.now();
    for (;;) {
      const r = readInbox(u.id, tag('harness'));
      if (measuring) harnessN.add(1);
      if (r.status === 200) { const msgs = r.json(); if (msgs.length) return msgs[msgs.length - 1].token; }
      if (Date.now() - t0 >= POLL_TIMEOUT_MS) return null;
      sleep(POLL_MS / 1000);
    }
  };

  if (BENCH === 'P1') {
    const r = http.get(`${BASE}/api/profile`, { headers: auth, tags: tag('op') });
    if (measuring) { const ok = record(M.op, r, 200); wf += r.timings.duration; if (!ok) complete = false; }
  } else if (BENCH === 'P3') {
    const issued = doIssue();
    if (issued) {
      const t = awaitOtt(); // drains the message so the sink does not accumulate
      if (t === null && measuring) { harnessFailures.add(1); complete = false; }
    }
  } else { // P2a / P2b
    if (CONFIG === 'C') {
      const issued = doIssue();
      if (issued) ottValue = awaitOtt();
      if (!issued || ottValue === null) {
        if (issued && measuring) harnessFailures.add(1); // OTT never arrived: skip op, not an op error
        if (measuring) { itersIncomplete.add(1); }
        return;
      }
    } else {
      readInbox(u.id, tag('harness')); // equivalent sink read; returns empty for B and D
      if (measuring) harnessN.add(1);
    }
    const body = {};
    if (BENCH === 'P2a') body.newPassword = PW;
    if (CONFIG === 'D') body.currentPassword = PW;
    if (CONFIG === 'C') body.ott = ottValue;
    const path = BENCH === 'P2a' ? '/api/auth/change-password' : '/api/auth/confirm-email';
    const r = http.post(`${BASE}${path}`, JSON.stringify(body), { headers: auth, tags: tag('op') });
    if (measuring) { const ok = record(M.op, r, 200); wf += r.timings.duration; if (!ok) complete = false; }
  }

  if (measuring) {
    if (complete) { itersComplete.add(1); M.wf.ms.add(wf); M.wf.n.add(1); M.wf.sum.add(wf); M.wf.sumsq.add(wf * wf); }
    else itersIncomplete.add(1);
  }
}

const val = (data, name, key) => (data.metrics[name] && data.metrics[name].values && data.metrics[name].values[key] !== undefined ? data.metrics[name].values[key] : 0);
function describe(data, n) {
  const count = val(data, `${n}_n`, 'count'); const sum = val(data, `${n}_sum`, 'count'); const sumsq = val(data, `${n}_sumsq`, 'count');
  const mean = count ? sum / count : null;
  const std = count > 1 ? Math.sqrt(Math.max(0, (sumsq - count * mean * mean) / (count - 1))) : null;
  const t = (key) => (count ? val(data, `${n}_ms`, key) : null);
  const ok = (key) => (val(data, `${n}_ok_ms`, key) || null);
  return { count, failed: val(data, `${n}_fail`, 'count'), mean, std, min: t('min'), median: t('med'), p95: t('p(95)'), p99: t('p(99)'), max: t('max'),
    okMedian: count ? ok('med') : null, okP95: count ? ok('p(95)') : null };
}

export function handleSummary(data) {
  const summary = {
    meta: { bench: BENCH, config: CONFIG, vus: VUS, warmupS: WARMUP_S, measureS: MEASURE_S, scenarioStartMs: val(data, 'scenario_start_ms', 'count'),
      testRunDurationMs: data.state ? data.state.testRunDurationMs : null },
    op: describe(data, 'op'), issue: describe(data, 'issue'), workflow: describe(data, 'wf'),
    harness: { requests: val(data, 'harness_n', 'count'), failures: val(data, 'harness_failures', 'count') },
    iterations: { attempted: val(data, 'iters_attempted', 'count'), complete: val(data, 'iters_complete', 'count'), incomplete: val(data, 'iters_incomplete', 'count') },
  };
  summary.op.throughput = summary.op.count / MEASURE_S;
  summary.issue.throughput = summary.issue.count / MEASURE_S;
  summary.workflow.throughput = summary.workflow.count / MEASURE_S;
  return { [SUMMARY_PATH]: JSON.stringify(summary, null, 2) };
}
