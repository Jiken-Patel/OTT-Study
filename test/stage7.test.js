'use strict';
// Stage 7 development tests: condition list and block-randomized schedule.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { conditions, buildSchedule } = require('../bench/schedule');

test('conditions: 45 conditions at the default five load levels (EXPERIMENTS.md 11)', () => {
  const c = conditions();
  assert.equal(c.length, 45);
  const by = (b) => c.filter((x) => x.bench === b);
  assert.equal(by('P1').length, 10); assert.equal(by('P2a').length, 15); assert.equal(by('P2b').length, 15); assert.equal(by('P3').length, 5);
  assert.deepEqual([...new Set(by('P1').map((x) => x.config))].sort(), ['A', 'B']);
  assert.deepEqual([...new Set(by('P3').map((x) => x.config))], ['C']);
  assert.equal(buildSchedule({ runs: 30 }).length, 1350);
});

test('schedule: every condition appears exactly once per block; order is randomized; same seed reproduces it', () => {
  const s = buildSchedule({ runs: 6, seed: 42 });
  const conds = conditions();
  for (let run = 1; run <= 6; run++) {
    const block = s.filter((x) => x.run === run);
    assert.equal(block.length, conds.length);
    assert.equal(new Set(block.map((x) => `${x.bench}|${x.config}|${x.vus}`)).size, conds.length);
  }
  const key = (x) => `${x.bench}|${x.config}|${x.vus}`;
  const order = (run) => s.filter((x) => x.run === run).map(key).join(',');
  assert.notEqual(order(1), order(2));
  assert.deepEqual(buildSchedule({ runs: 6, seed: 42 }), s);
  assert.notDeepEqual(buildSchedule({ runs: 6, seed: 43 }), s);
});

test('schedule: configurations are interleaved (no config runs in one long streak)', () => {
  const s = buildSchedule({ runs: 10, seed: 7, benches: ['P2a'], levels: [10] });
  let maxStreak = 1; let streak = 1;
  for (let i = 1; i < s.length; i++) { streak = s[i].config === s[i - 1].config ? streak + 1 : 1; maxStreak = Math.max(maxStreak, streak); }
  assert.ok(maxStreak <= 4, `longest streak of one configuration: ${maxStreak}`);
});

test('conditions: filters by benchmark, configuration and level', () => {
  const c = conditions({ benches: ['P2b'], configs: ['C', 'D'], levels: [1, 50] });
  assert.equal(c.length, 4);
  assert.ok(c.every((x) => x.bench === 'P2b' && ['C', 'D'].includes(x.config) && [1, 50].includes(x.vus)));
  assert.throws(() => conditions({ benches: ['P9'] }), /unknown benchmark/);
});

// ---------------- sampler parsing ----------------
const { parseStat, parseStatm, summarizeWindow } = require('../bench/sampler');
test('sampler: /proc/<pid>/stat parsing survives spaces and parentheses in the command name', () => {
  const line = '1234 (node (worker) x) S 1 1234 1234 0 -1 4194560 1000 0 0 0 250 75 0 0 20 0 11 0 5000 100000000 20000 18446744073709551615';
  assert.deepEqual(parseStat(line), { utime: 250, stime: 75 });
  assert.equal(parseStatm('25000 20000 300 10 0 5000 0', 4096), 20000 * 4096);
});
test('sampler: window summary computes mean and peak per process within the window only', () => {
  const s = [{ t: 0, name: 'app', cpuPct: 999, rssMB: 1 }, { t: 1000, name: 'app', cpuPct: 50, rssMB: 100 }, { t: 2000, name: 'app', cpuPct: 150, rssMB: 120 },
    { t: 3000, name: 'app', cpuPct: 999, rssMB: 9 }, { t: 1500, name: 'db', cpuPct: 10, rssMB: 500 }];
  const w = summarizeWindow(s, 1000, 2000);
  assert.deepEqual(w.app, { samples: 2, cpuMeanPct: 100, cpuPeakPct: 150, memMeanMB: 110, memPeakMB: 120 });
  assert.equal(w.db.samples, 1);
});

// ---------------- analysis on synthetic runs with KNOWN effects ----------------
const fs = require('fs'); const os = require('os'); const path = require('path');
const { analyze, report } = require('../bench/analyze');
const { rng } = require('../bench/stats');

function writeRun(dir, { bench, config, vus, run, attempt = 1, valid = true, op, issue, workflow, incomplete = 0, harnessFailures = 0, attempted = 1000, cpuApp = 50 }) {
  const cfgDir = path.join(dir, 'raw', `config-${config}`); fs.mkdirSync(cfgDir, { recursive: true });
  const base = `${bench}_vu${vus}_run${String(run).padStart(2, '0')}_a${attempt}`;
  const stat = (m) => ({ count: 1000, failed: 0, mean: m, std: 1, median: m, p95: m * 1.5, p99: m * 2, throughput: 1000 / (m / 1000 * vus) });
  const summary = { op: op != null ? stat(op) : { count: 0, failed: 0, median: null, throughput: 0 }, issue: issue != null ? stat(issue) : { count: 0, failed: 0, median: null, throughput: 0 },
    workflow: stat(workflow != null ? workflow : (op || 0) + (issue || 0)), harness: { requests: 1000, failures: harnessFailures },
    iterations: { attempted, complete: attempted - incomplete, incomplete } };
  const resources = { perProcess: { app: { cpuMeanPct: cpuApp, cpuPeakPct: 99, memMeanMB: 120 }, mysql: { cpuMeanPct: 20, memMeanMB: 400 }, sink: { cpuMeanPct: 3, memMeanMB: 60 }, loadgen: { cpuMeanPct: 10, memMeanMB: 40 } } };
  fs.writeFileSync(path.join(cfgDir, `${base}.json`), JSON.stringify({ summary, resources, samples: [] }));
  fs.writeFileSync(path.join(cfgDir, `${base}.meta.json`), JSON.stringify({ valid, attempt, bench, config, vus, run, invalidReason: valid ? null : 'harness_failure rate 5% > 1%' }));
}

test('analysis: recovers a known 10% overhead, finds no difference where there is none, honours validity and retries', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ott-an-'));
  const r = rng(99); const noise = () => (r() - 0.5) * 1.0;
  for (let run = 1; run <= 30; run++) {
    writeRun(dir, { bench: 'P2b', config: 'B', vus: 10, run, op: 10 + noise() });
    writeRun(dir, { bench: 'P2b', config: 'C', vus: 10, run, op: 11 + noise(), issue: 6 + noise() });  // +10% on op
    writeRun(dir, { bench: 'P2b', config: 'D', vus: 10, run, op: 40 + noise() });
    writeRun(dir, { bench: 'P2a', config: 'B', vus: 10, run, op: 50 + noise() });
    writeRun(dir, { bench: 'P2a', config: 'C', vus: 10, run, op: 50 + noise(), issue: 6 + noise() }); // no difference on op
  }
  // run 1 of P2b/C: first attempt invalid, a valid retry exists (must be used); run 2 has ONLY an invalid attempt (must be excluded)
  writeRun(dir, { bench: 'P2b', config: 'C', vus: 10, run: 1, attempt: 1, valid: false, op: 999, harnessFailures: 99 });
  writeRun(dir, { bench: 'P2b', config: 'C', vus: 10, run: 1, attempt: 2, valid: true, op: 11, issue: 6 });
  writeRun(dir, { bench: 'P2b', config: 'C', vus: 10, run: 2, attempt: 1, valid: false, op: 999 });
  fs.rmSync(path.join(dir, 'raw', 'config-C', 'P2b_vu10_run02_a1.json')); // remove the valid attempt-1 file written above, keep only the invalid meta
  fs.writeFileSync(path.join(dir, 'raw', 'config-C', 'P2b_vu10_run02_a1.meta.json'), JSON.stringify({ valid: false, attempt: 1, bench: 'P2b', config: 'C', vus: 10, run: 2, invalidReason: 'k6 exit 1' }));

  const res = analyze(dir, { bootstrap: 2000, expectedRuns: 30 });
  assert.equal(res.invalid.length, 2);
  const cell = (b, c) => res.conditions.find((x) => x.bench === b && x.vus === 10 && x.config === c);
  assert.equal(cell('P2b', 'C').runs, 29, 'run 2 had no valid attempt; run 1 is counted once via its retry');
  assert.ok(cell('P2b', 'C').flags.some((f) => f.includes('29/30')));

  const prim = res.comparisons.filter((c) => c.family === 'primary');
  assert.equal(prim.length, 2); // P2a and P2b, B vs C, median
  const p2b = prim.find((c) => c.bench === 'P2b'); const p2a = prim.find((c) => c.bench === 'P2a');
  assert.ok(p2b.change_pct > 8 && p2b.change_pct < 12, `overhead ${p2b.change_pct}`);
  assert.ok(p2b.change_pct_lo < 10 && p2b.change_pct_hi > 10);
  assert.ok(p2b.p < 1e-6, `p ${p2b.p}`);
  assert.ok(p2a.p > 0.05, `P2a should show no difference, p ${p2a.p}`);
  assert.ok(prim.every((c) => c.p_holm >= c.p && c.p_holm <= 1));
  const sec = res.comparisons.filter((c) => c.family === 'secondary');
  assert.ok(sec.length > 10 && sec.every((c) => c.p_holm >= c.p));
  // P4 is derived from the P2 runs: C's workflow includes the issuance request, so it is much larger than B's operation
  const p4 = res.comparisons.find((c) => c.bench === 'P4b' && c.ref === 'B' && c.cmp === 'C' && c.metric === 'median');
  assert.ok(p4 && p4.median_cmp > p4.median_ref + 5);
  // the report states the closed-loop caveat and lists invalid attempts
  const md = report(res, null);
  assert.ok(md.includes('closed-loop') && md.includes('Invalid attempts') && md.includes('P2b: primary comparison'));
});

test('analysis: flags a saturated app process and a high error rate', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ott-an2-'));
  for (let run = 1; run <= 3; run++) writeRun(dir, { bench: 'P1', config: 'B', vus: 250, run, op: 10, cpuApp: 97 });
  const res = analyze(dir, { bootstrap: 200, expectedRuns: 3 });
  assert.ok(res.conditions[0].flags.some((f) => f.includes('saturation')));
});
