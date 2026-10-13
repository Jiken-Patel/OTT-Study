'use strict';
// Aggregation and output (EXPERIMENTS.md 14). Raw per-repetition records are written once and never overwritten
// (the output directory must be new or empty).
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const { PREDICTED, TEST_IDS, NA } = require('./matrix');

const same = (obs, pred) => {
  if (pred && typeof pred === 'object') return obs && typeof obs === 'object' && Object.keys(pred).every((k) => obs[k] === pred[k]);
  return obs === pred;
};
const label = (o) => (o && typeof o === 'object' ? Object.entries(o).map(([k, v]) => `${k}: ${v}`).join(', ') : String(o));
const median = (xs) => { const a = xs.filter((x) => x != null).sort((x, y) => x - y); return a.length ? a[Math.floor((a.length - 1) / 2)] : null; };
const p95 = (xs) => { const a = xs.filter((x) => x != null).sort((x, y) => x - y); return a.length ? a[Math.min(a.length - 1, Math.ceil(0.95 * a.length) - 1)] : null; };
// exact one-sided 95% upper bound on a per-run violation probability when 0 of n runs violated
const zeroUpper = (n) => 1 - Math.pow(0.05, 1 / n);

function summarize(testId, mode, reps, test) {
  const predicted = PREDICTED[testId][mode];
  const counts = {};
  for (const r of reps) { const k = label(r.outcome); counts[k] = (counts[k] || 0) + 1; }
  const matches = reps.filter((r) => !r.error && same(r.outcome, predicted)).length;
  const counted = reps.filter((r) => r.counted);
  const attempts = counted.reduce((n, r) => n + r.counted.attempts, 0);
  const successes = counted.reduce((n, r) => n + r.counted.successes, 0);
  const s = { test: testId, name: test.name, config: mode, reps: reps.length, predicted, predictedLabel: label(predicted),
    outcomes: counts, matchesPrediction: matches, allMatch: matches === reps.length, errors: reps.filter((r) => r.error).length,
    attackSuccess: counted.length ? { attempts, successes, rate: attempts ? successes / attempts : null } : null,
    latencyMs: { median: median(reps.map((r) => r.latencyMs)), p95: p95(reps.map((r) => r.latencyMs)) } };
  if (test.race) {
    const violations = reps.filter((r) => r.outcome === 'INVARIANT_VIOLATED').length;
    const sum = (k) => reps.reduce((n, r) => n + ((r.observed && r.observed[k]) || 0), 0);
    s.invariant = { runs: reps.length, violations, violationRate: violations / reps.length,
      upper95WhenZero: violations === 0 ? zeroUpper(reps.length) : null, concurrentRequestsSent: sum('concurrentSent'),
      successfulConsumptions: sum('successes'), duplicateSuccesses: sum('duplicates'), dbErrors: sum('dbErrors'),
      runsWithZeroSuccess: reps.filter((r) => r.observed && r.observed.zeroSuccess).length };
  }
  return s;
}

function metadata({ harness, args, started, finished }) {
  let commit = 'TBD';
  try { commit = execSync('git rev-parse HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch (e) { /* not a git checkout */ }
  const cpus = os.cpus();
  return { experimentDocVersion: '1.3', experimentVersion: 'v1', gitCommit: commit, started, finished, args,
    node: process.version, mysql: harness.mysqlVersion, os: `${os.platform()} ${os.release()}`,
    cpu: cpus.length ? `${cpus[0].model} x${cpus.length}` : 'unknown', totalMemoryGB: Math.round(os.totalmem() / 2 ** 30),
    appProfile: 'test', uvThreadpoolSize: process.env.UV_THREADPOOL_SIZE,
    rateLimitProfiles: { default: 'relaxed', T18_T20_T28: 'standard (fresh app per repetition)', T06: 'relaxed + OTT_EXPIRES_IN_SECONDS=2' },
    note: 'Predicted outcomes in this report are hypotheses from EXPERIMENTS.md section 9; only the observed counts are results.' };
}

function writeOutputs(outDir, { meta, summaries, rawByCell, includeRaw = true }) {
  fs.mkdirSync(outDir, { recursive: true });
  if (fs.readdirSync(outDir).filter((f) => f !== 'negative-control').length) throw new Error(`output directory ${outDir} is not empty (raw data is never overwritten)`);
  if (includeRaw) for (const [cfg, tests] of Object.entries(rawByCell)) {
    fs.mkdirSync(path.join(outDir, `config-${cfg}`), { recursive: true });
    for (const [id, payload] of Object.entries(tests)) fs.writeFileSync(path.join(outDir, `config-${cfg}`, `${id}.json`), JSON.stringify(payload, null, 2));
  }
  fs.writeFileSync(path.join(outDir, 'metadata.json'), JSON.stringify(meta, null, 2));
  fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summaries, null, 2));

  const cells = {}; for (const s of summaries) { (cells[s.test] = cells[s.test] || {})[s.config] = s; }
  const cell = (id, c) => {
    if (PREDICTED[id][c] === NA) return 'N/A';
    const s = cells[id] && cells[id][c];
    if (!s) return 'not run';
    const top = Object.entries(s.outcomes).sort((a, b) => b[1] - a[1]).map(([k, n]) => (s.reps === n ? k : `${k} (${n}/${s.reps})`)).join('; ');
    return `${top}${s.allMatch ? '' : ' ⚠ differs from prediction'}`;
  };
  const lines = ['# Observed outcomes (security harness)', '', `Generated ${meta.finished}. Predicted outcomes (EXPERIMENTS.md section 9) are hypotheses; this table shows what was observed.`, '',
    '| Test | A | B | C | D |', '|------|---|---|---|---|'];
  for (const id of TEST_IDS) lines.push(`| ${id} | ${['A', 'B', 'C', 'D'].map((c) => cell(id, c)).join(' | ')} |`);
  const bad = summaries.filter((s) => !s.allMatch);
  lines.push('', bad.length ? `## ⚠ ${bad.length} cell(s) differ from the prediction` : '## All executed cells match the prediction', '');
  for (const s of bad) lines.push(`- **${s.test} / Config ${s.config}**: predicted ${s.predictedLabel}; observed ${JSON.stringify(s.outcomes)}${s.errors ? ` (${s.errors} errors)` : ''}`);
  const rates = summaries.filter((s) => s.attackSuccess);
  lines.push('', '## Attack-success counts (BOUNDARY cases excluded)', '', 'Unauthorized successes over attempts. For the concurrency tests T15-T17 only successes beyond the ONE permitted consumption count.', '', '| Test | Config | successful / attempts |', '|------|--------|-----------------------|');
  for (const s of rates) lines.push(`| ${s.test} | ${s.config} | ${s.attackSuccess.successes} / ${s.attackSuccess.attempts} |`);
  const races = summaries.filter((s) => s.invariant);
  if (races.length) {
    lines.push('', '## Race-condition invariants', '', '| Test | Config | runs | violations | requests sent | successful consumptions | duplicates | db errors | 95% upper bound if 0 |', '|---|---|---|---|---|---|---|---|---|');
    for (const s of races) { const i = s.invariant; lines.push(`| ${s.test} | ${s.config} | ${i.runs} | ${i.violations} | ${i.concurrentRequestsSent} | ${i.successfulConsumptions} | ${i.duplicateSuccesses} | ${i.dbErrors} | ${i.upper95WhenZero == null ? '-' : (i.upper95WhenZero * 100).toFixed(2) + '%'} |`); }
  }
  fs.writeFileSync(path.join(outDir, 'matrix.md'), lines.join('\n') + '\n');
  return bad;
}

module.exports = { summarize, metadata, writeOutputs, same, label };
