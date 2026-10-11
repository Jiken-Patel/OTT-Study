'use strict';
// Analysis of benchmark runs (EXPERIMENTS.md sections 10.2, 12, 13). Usage:
//   node bench/analyze.js [--in results/performance] [--out <in>/analysis] [--bootstrap 10000] [--runs 30]
// The unit of analysis is ONE SUMMARY VALUE PER RUN. For each benchmark and load level:
//   two-sided Mann-Whitney U on the per-run values, the median difference with a 95% percentile-bootstrap CI,
//   and the overhead (cmp - ref) / ref * 100 on per-run medians with a bootstrap CI.
//   PRIMARY family   : B vs C on per-run median latency in P2a and P2b (reported unadjusted, as required, plus a
//                      Holm-adjusted p over this family as a conservative note).
//   SECONDARY family : everything else (C vs D, B vs D, A vs B, P4, other metrics); Holm-adjusted across them.
// Only valid runs are used; for a retried run the last valid attempt wins. P4 is derived from the P2 runs.
const fs = require('fs');
const path = require('path');
const { median, mannWhitneyU, bootstrapCI, holm, quantile } = require('./stats');

const PAIRS = { P1: [['A', 'B']], P2a: [['B', 'C'], ['C', 'D'], ['B', 'D']], P2b: [['B', 'C'], ['C', 'D'], ['B', 'D']], P3: [],
  P4a: [['B', 'C'], ['C', 'D'], ['B', 'D']], P4b: [['B', 'C'], ['C', 'D'], ['B', 'D']] };
const LATENCY_METRICS = ['median', 'p95', 'p99'];
const TEST_METRICS = ['median', 'p95', 'p99', 'throughput'];

function hashSeed(s) { let h = 2166136261; for (const ch of s) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; }

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p); else yield p;
  }
}

/** Load every run; keep the last valid attempt per (bench, config, vus, run). */
function loadRuns(inDir) {
  const raw = path.join(inDir, 'raw');
  const best = new Map(); const invalid = []; let total = 0;
  for (const f of walk(raw)) {
    if (!f.endsWith('.meta.json')) continue;
    total += 1;
    const meta = JSON.parse(fs.readFileSync(f, 'utf8'));
    const key = `${meta.bench}|${meta.config}|${meta.vus}|${meta.run}`;
    if (!meta.valid) { invalid.push({ key, attempt: meta.attempt, reason: meta.invalidReason }); continue; }
    const data = JSON.parse(fs.readFileSync(f.replace(/\.meta\.json$/, '.json'), 'utf8'));
    const prev = best.get(key);
    if (!prev || meta.attempt > prev.meta.attempt) best.set(key, { meta, data });
  }
  return { runs: [...best.values()], invalid, totalAttempts: total };
}

const err = (c) => (c.count ? c.failed / c.count : 0);
function metricsFor(bench, run) {
  const s = run.data.summary; const proc = (run.data.resources && run.data.resources.perProcess) || {};
  const cpu = (n) => (proc[n] && proc[n].cpuMeanPct != null ? proc[n].cpuMeanPct : null);
  const mem = (n) => (proc[n] && proc[n].memMeanMB != null ? proc[n].memMeanMB : null);
  let c; let errorRate;
  if (bench === 'P3') c = s.issue;
  else if (bench === 'P4a' || bench === 'P4b') { c = s.workflow; const it = s.iterations; errorRate = it.attempted ? Math.max(0, it.incomplete - s.harness.failures) / it.attempted : 0; }
  else c = s.op;
  return { mean: c.mean, std: c.std, median: c.median, p95: c.p95, p99: c.p99, throughput: c.throughput, errorRate: errorRate !== undefined ? errorRate : err(c),
    harnessFailures: s.harness.failures, cpuApp: cpu('app'), cpuMysql: cpu('mysql'), cpuSink: cpu('sink'), cpuLoadgen: cpu('loadgen'),
    memApp: mem('app'), memMysql: mem('mysql'), memSink: mem('sink'), appCpuPeak: proc.app ? proc.app.cpuPeakPct : null };
}

function analyze(inDir, { bootstrap = 10000, expectedRuns = null } = {}) {
  const { runs, invalid, totalAttempts } = loadRuns(inDir);
  // cells[bench][vus][config] = [metrics per run]
  const cells = {};
  const add = (bench, run) => {
    ((cells[bench] = cells[bench] || {})[run.meta.vus] = cells[bench][run.meta.vus] || {});
    (cells[bench][run.meta.vus][run.meta.config] = cells[bench][run.meta.vus][run.meta.config] || []).push({ run: run.meta.run, ...metricsFor(bench, run) });
  };
  for (const r of runs) {
    add(r.meta.bench, r);
    if (r.meta.bench === 'P2a') add('P4a', r);
    if (r.meta.bench === 'P2b') add('P4b', r);
  }
  const col = (arr, k) => arr.map((r) => r[k]).filter((v) => v !== null && v !== undefined && Number.isFinite(v));

  const conditions = []; const comparisons = [];
  for (const bench of Object.keys(cells)) for (const vus of Object.keys(cells[bench]).map(Number).sort((a, b) => a - b)) for (const config of Object.keys(cells[bench][vus]).sort()) {
    const arr = cells[bench][vus][config];
    const row = { bench, vus, config, runs: arr.length, expectedRuns };
    for (const k of ['median', 'p95', 'p99', 'mean', 'std', 'throughput', 'errorRate', 'harnessFailures', 'cpuApp', 'cpuMysql', 'cpuSink', 'cpuLoadgen', 'memApp', 'memMysql', 'memSink']) {
      const v = col(arr, k);
      row[`${k}_med`] = v.length ? median(v) : null; row[`${k}_q1`] = v.length ? quantile(v, 0.25) : null; row[`${k}_q3`] = v.length ? quantile(v, 0.75) : null;
    }
    const flags = [];
    if (col(arr, 'errorRate').some((e) => e > 0.01)) flags.push('error rate > 1% in some runs');
    if (arr.some((r) => r.appCpuPeak != null && r.cpuApp != null && r.cpuApp >= 90)) flags.push('app process at >= 90% of one core on average (possible saturation)');
    if (expectedRuns && arr.length < expectedRuns) flags.push(`only ${arr.length}/${expectedRuns} valid runs`);
    row.flags = flags;
    conditions.push(row);
  }
  for (const bench of Object.keys(cells)) for (const vus of Object.keys(cells[bench]).map(Number).sort((a, b) => a - b)) for (const [ref, cmp] of PAIRS[bench] || []) {
    const a = cells[bench][vus][ref]; const b = cells[bench][vus][cmp];
    if (!a || !b || a.length < 2 || b.length < 2) continue;
    for (const metric of TEST_METRICS) {
      const x = col(a, metric); const y = col(b, metric);
      if (x.length < 2 || y.length < 2) continue;
      const mw = mannWhitneyU(x, y);
      const seedBase = hashSeed(`${bench}|${vus}|${ref}|${cmp}|${metric}`);
      const d = bootstrapCI(x, y, { kind: 'diff', B: bootstrap, seed: seedBase });
      const o = bootstrapCI(x, y, { kind: 'overhead', B: bootstrap, seed: seedBase + 1 });
      const primary = (bench === 'P2a' || bench === 'P2b') && ref === 'B' && cmp === 'C' && metric === 'median';
      comparisons.push({ family: primary ? 'primary' : 'secondary', bench, vus, ref, cmp, metric, n_ref: x.length, n_cmp: y.length,
        median_ref: median(x), median_cmp: median(y), diff: d.estimate, diff_lo: d.lo, diff_hi: d.hi,
        change_pct: o.estimate, change_pct_lo: o.lo, change_pct_hi: o.hi, U: mw.U1, z: mw.z, p: mw.p, p_holm: null });
    }
  }
  for (const fam of ['primary', 'secondary']) {
    const idx = comparisons.map((c, i) => [c, i]).filter(([c]) => c.family === fam);
    const adj = holm(idx.map(([c]) => c.p));
    idx.forEach(([c], k) => { c.p_holm = adj[k]; });
  }
  return { conditions, comparisons, invalid, totalAttempts, validRuns: runs.length, expectedRuns };
}

// ------------------------------------------------------------------ output
const fmt = (v, d = 2) => (v === null || v === undefined || !Number.isFinite(v) ? '-' : Number(v).toFixed(d));
const fp = (p) => (p === null || p === undefined ? '-' : p < 0.0001 ? '<0.0001' : p.toFixed(4));
function csv(rows) {
  if (!rows.length) return '';
  const keys = Object.keys(rows[0]);
  const cell = (v) => (Array.isArray(v) ? `"${v.join('; ')}"` : v === null || v === undefined ? '' : typeof v === 'string' && /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : String(v));
  return [keys.join(','), ...rows.map((r) => keys.map((k) => cell(r[k])).join(','))].join('\n') + '\n';
}

function report(res, meta) {
  const L = [];
  L.push('# Performance analysis', '');
  L.push(`Valid runs analysed: **${res.validRuns}** (${res.totalAttempts} attempts on disk, ${res.invalid.length} invalid attempt(s) excluded).`);
  if (meta) L.push(`Machine: ${meta.machine.cpu}, ${meta.machine.memoryGB} GB, ${meta.machine.os}; Node ${meta.node}; MySQL ${meta.mysql}; ${meta.k6}; commit ${meta.gitCommit}; warm-up ${meta.warmupS} s, measurement ${meta.measureS} s.`);
  L.push('', '> **Read before interpreting.** The load generator is closed-loop: in Config C each virtual user also performs the issuance request and the OOB sink read, so at equal VU count C sends fewer simultaneous `op` requests than B or D. Compare latencies together with the achieved throughput below, and do not describe a latency difference as pure OTT overhead. Config C\'s cost also includes an in-process loopback HTTP handoff to the sink (likely cheaper than a real mail or SMS call). k6, the application, MySQL and the sink share one machine.', '');
  const byBench = (b) => res.comparisons.filter((c) => c.bench === b);
  const cond = (b, v, c) => res.conditions.find((x) => x.bench === b && x.vus === v && x.config === c);

  for (const bench of ['P2a', 'P2b']) {
    const rows = byBench(bench).filter((c) => c.family === 'primary');
    L.push(`## ${bench}: primary comparison, B vs C, per-run median latency (ms)`, '');
    if (!rows.length) { L.push('_no data_', ''); continue; }
    L.push('| VUs | runs B/C | median B | median C | diff (C-B) [95% CI] | overhead % [95% CI] | p (MWU) | p Holm (primary family) |', '|---|---|---|---|---|---|---|---|');
    const adjFam = holm(res.comparisons.filter((c) => c.family === 'primary').map((c) => c.p));
    const famRows = res.comparisons.filter((c) => c.family === 'primary');
    for (const c of rows) L.push(`| ${c.vus} | ${c.n_ref}/${c.n_cmp} | ${fmt(c.median_ref)} | ${fmt(c.median_cmp)} | ${fmt(c.diff)} [${fmt(c.diff_lo)}, ${fmt(c.diff_hi)}] | ${fmt(c.change_pct, 1)} [${fmt(c.change_pct_lo, 1)}, ${fmt(c.change_pct_hi, 1)}] | ${fp(c.p)} | ${fp(adjFam[famRows.indexOf(c)])} |`);
    L.push('');
  }
  L.push('## Achieved throughput of the measured operation (req/s, median of per-run values)', '', '| Bench | VUs | A | B | C | D |', '|---|---|---|---|---|---|');
  for (const bench of ['P1', 'P2a', 'P2b', 'P3']) {
    const vus = [...new Set(res.conditions.filter((c) => c.bench === bench).map((c) => c.vus))].sort((a, b) => a - b);
    for (const v of vus) L.push(`| ${bench} | ${v} | ${['A', 'B', 'C', 'D'].map((c) => { const x = cond(bench, v, c); return x ? fmt(x.throughput_med, 1) : '-'; }).join(' | ')} |`);
  }
  L.push('', '## Latency per condition (per-run medians: median [Q1, Q3], ms)', '', '| Bench | VUs | Config | runs | median | p95 | p99 | error rate | harness failures |', '|---|---|---|---|---|---|---|---|---|');
  for (const x of res.conditions) L.push(`| ${x.bench} | ${x.vus} | ${x.config} | ${x.runs} | ${fmt(x.median_med)} [${fmt(x.median_q1)}, ${fmt(x.median_q3)}] | ${fmt(x.p95_med)} | ${fmt(x.p99_med)} | ${fmt(x.errorRate_med, 4)} | ${fmt(x.harnessFailures_med, 0)} |`);
  L.push('', '## Resource use (mean CPU % of one core / mean RSS MB, median of per-run values)', '', '| Bench | VUs | Config | app CPU | MySQL CPU | sink CPU | load-gen CPU | app MB | MySQL MB | sink MB |', '|---|---|---|---|---|---|---|---|---|---|');
  for (const x of res.conditions.filter((c) => !c.bench.startsWith('P4'))) L.push(`| ${x.bench} | ${x.vus} | ${x.config} | ${fmt(x.cpuApp_med, 1)} | ${fmt(x.cpuMysql_med, 1)} | ${fmt(x.cpuSink_med, 1)} | ${fmt(x.cpuLoadgen_med, 1)} | ${fmt(x.memApp_med, 0)} | ${fmt(x.memMysql_med, 0)} | ${fmt(x.memSink_med, 0)} |`);
  const sec = res.comparisons.filter((c) => c.family === 'secondary' && c.metric === 'median');
  L.push('', '## Secondary comparisons on per-run median latency (Holm-adjusted across ALL secondary tests, incl. other metrics)', '', '| Bench | VUs | ref -> cmp | median ref | median cmp | change % [95% CI] | p (MWU) | p Holm |', '|---|---|---|---|---|---|---|---|');
  for (const c of sec) L.push(`| ${c.bench} | ${c.vus} | ${c.ref} -> ${c.cmp} | ${fmt(c.median_ref)} | ${fmt(c.median_cmp)} | ${fmt(c.change_pct, 1)} [${fmt(c.change_pct_lo, 1)}, ${fmt(c.change_pct_hi, 1)}] | ${fp(c.p)} | ${fp(c.p_holm)} |`);
  L.push('', 'P4 (step-up workflow) is derived from the P2 runs (issuance + operation for C, operation for B and D); it shares runs with P2, so P2 and P4 results are two views of the same data. Full results for every metric (median, p95, p99, throughput) are in `comparisons.csv`.');
  const flagged = res.conditions.filter((c) => c.flags.length);
  L.push('', '## Flags', '');
  if (!flagged.length) L.push('_none_'); for (const c of flagged) L.push(`- ${c.bench} / Config ${c.config} / ${c.vus} VUs: ${c.flags.join('; ')}`);
  if (res.invalid.length) { L.push('', '## Invalid attempts (excluded from the analysis, kept in the raw data)', ''); for (const i of res.invalid) L.push(`- ${i.key} attempt ${i.attempt}: ${i.reason}`); }
  return L.join('\n') + '\n';
}

function parseArgs(argv) {
  const a = { in: 'results/performance', out: null, bootstrap: 10000, runs: null };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i]; const v = argv[i + 1];
    if (k === '--in') { a.in = v; i++; } else if (k === '--out') { a.out = v; i++; } else if (k === '--bootstrap') { a.bootstrap = Number(v); i++; } else if (k === '--runs') { a.runs = Number(v); i++; }
    else throw new Error(`unknown argument ${k}`);
  }
  return a;
}

function main() {
  const args = parseArgs(process.argv);
  const out = path.resolve(args.out || path.join(args.in, 'analysis'));
  const res = analyze(path.resolve(args.in), { bootstrap: args.bootstrap, expectedRuns: args.runs });
  if (!res.validRuns) throw new Error(`no valid runs found under ${args.in}/raw`);
  fs.mkdirSync(out, { recursive: true });
  const any = [...walk(path.join(path.resolve(args.in), 'raw'))].find((f) => f.endsWith('.meta.json'));
  const meta = any ? JSON.parse(fs.readFileSync(any, 'utf8')) : null;
  fs.writeFileSync(path.join(out, 'conditions.csv'), csv(res.conditions));
  fs.writeFileSync(path.join(out, 'comparisons.csv'), csv(res.comparisons));
  fs.writeFileSync(path.join(out, 'analysis.json'), JSON.stringify(res, null, 2));
  fs.writeFileSync(path.join(out, 'report.md'), report(res, meta));
  console.log(`analysed ${res.validRuns} valid runs (${res.invalid.length} invalid attempts excluded) -> ${out}`);
}

if (require.main === module) main();
module.exports = { analyze, report, loadRuns, csv, PAIRS };
