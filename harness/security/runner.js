'use strict';
// Security test harness (EXPERIMENTS.md section 8). Usage:
//   npm run security -- [--configs A,B,C,D] [--tests T01,T02] [--reps 30] [--race-reps 100] [--out results/security]
//   npm run security -- --negative-control [--race-reps 100] [--unsafe-delay-ms 20] [--out results/security/negative-control]
// Every run starts from a freshly reset database and OOB sink. The output directory must not already contain data.
process.env.UV_THREADPOOL_SIZE = process.env.UV_THREADPOOL_SIZE || '16';
process.env.APP_PROFILE = 'test';
require('dotenv').config();
const path = require('path');
const fs = require('fs');
const { resetDb } = require('../../scripts/resetDb');
const sequelize = require('../../src/config/db');
const { Harness } = require('./env');
const { T, raceConsume } = require('./tests');
const { PREDICTED, TEST_IDS, NA } = require('./matrix');
const { summarize, metadata, writeOutputs } = require('./report');

function parseArgs(argv) {
  const a = { configs: ['A', 'B', 'C', 'D'], tests: null, reps: 30, raceReps: 100, out: 'results/security', negativeControl: false, unsafeDelayMs: 20 };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i]; const v = argv[i + 1];
    if (k === '--configs') { a.configs = v.split(','); i++; }
    else if (k === '--tests') { a.tests = v.split(','); i++; }
    else if (k === '--reps') { a.reps = Number(v); i++; }
    else if (k === '--race-reps') { a.raceReps = Number(v); i++; }
    else if (k === '--out') { a.out = v; i++; }
    else if (k === '--unsafe-delay-ms') { a.unsafeDelayMs = Number(v); i++; }
    else if (k === '--negative-control') a.negativeControl = true;
    else throw new Error(`unknown argument ${k}`);
  }
  return a;
}

/** Runs one test for one configuration; handles per-variant application lifecycle. */
async function runCell(harness, mode, id, test, args, shared) {
  const variant = test.variant || 'relaxed';
  const reps = test.race ? args.raceReps : args.reps;
  const out = [];
  let holder = null;
  const onRestart = async (v) => {
    if (holder) await holder.stop();
    holder = await harness.startApp(mode, v || variant);
    return harness.context(holder, onRestart);
  };
  const oneRep = async (n, ctx) => {
    const t0 = Date.now();
    try { const r = await test.run(ctx); return { rep: n, ...r, ms: Date.now() - t0 }; }
    catch (e) { return { rep: n, outcome: 'ERROR', error: String(e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e), ms: Date.now() - t0 }; }
  };

  if (variant === 'standard') {                    // fresh application (empty rate-limit stores) for every repetition
    for (let n = 1; n <= reps; n++) { const ctx = await onRestart('standard'); out.push(await oneRep(n, ctx)); await holder.stop(); holder = null; }
  } else {
    const key = `${mode}:${variant}`;
    if (!shared[key]) shared[key] = await harness.startApp(mode, variant);
    const ctx = harness.context(shared[key], async () => { throw new Error('restart is only for the standard variant'); });
    if (test.parallel) {                           // independent users, e.g. T06's 3 s waits
      for (let s = 1; s <= reps; s += 10) {
        const chunk = await Promise.all(Array.from({ length: Math.min(10, reps - s + 1) }, (_, j) => oneRep(s + j, ctx)));
        out.push(...chunk);
      }
    } else {
      for (let n = 1; n <= reps; n++) out.push(await oneRep(n, ctx));
    }
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv);
  const started = new Date().toISOString();
  const occupied = (d) => fs.existsSync(d) && fs.readdirSync(d).filter((f) => f !== 'negative-control').length > 0;
  if (!args.negativeControl && occupied(args.out)) throw new Error(`output directory ${args.out} is not empty`);
  const harness = new Harness();
  await resetDb();
  await harness.init();

  if (args.negativeControl) return negativeControl(harness, args, started);

  const summaries = []; const rawByCell = {};
  const ids = (args.tests || TEST_IDS);
  for (const mode of args.configs) {
    await resetDb(); await harness.inbox.reset();
    const shared = {}; rawByCell[mode] = {};
    for (const id of ids) {
      if (!PREDICTED[id]) throw new Error(`unknown test ${id}`);
      if (PREDICTED[id][mode] === NA) continue;
      process.stdout.write(`Config ${mode}  ${id}  ${T[id].name} ... `);
      const t0 = Date.now();
      const reps = await runCell(harness, mode, id, T[id], args, shared);
      const s = summarize(id, mode, reps, T[id]);
      summaries.push(s); rawByCell[mode][id] = { test: id, name: T[id].name, capability: T[id].cap, config: mode, predicted: PREDICTED[id][mode], reps };
      console.log(`${s.allMatch ? 'ok' : 'DIFFERS'}  (${JSON.stringify(s.outcomes)}, ${((Date.now() - t0) / 1000).toFixed(1)} s)`);
    }
    for (const a of Object.values(shared)) await a.stop();
  }
  const meta = metadata({ harness, args, started, finished: new Date().toISOString() });
  const bad = writeOutputs(path.resolve(args.out), { meta, summaries, rawByCell });
  await harness.close(); await sequelize.close();
  console.log(`\nWrote ${path.resolve(args.out)}  (${summaries.length} cells, ${bad.length} differ from prediction)`);
  process.exit(bad.length ? 2 : 0);
}

/** EXPERIMENTS.md 8.2: prove the race harness can detect a violation (Config C only). */
async function negativeControl(harness, args, started) {
  const outDir = path.resolve(args.out === 'results/security' ? 'results/security/negative-control' : args.out);
  process.env.UNSAFE_NON_ATOMIC_CONSUME = 'true';
  process.env.UNSAFE_DELAY_MS = String(args.unsafeDelayMs);
  const app = await harness.startApp('C', 'relaxed', { UNSAFE_NON_ATOMIC_CONSUME: 'true', UNSAFE_DELAY_MS: String(args.unsafeDelayMs) });
  const ctx = harness.context(app, async () => { throw new Error('n/a'); });
  const result = { startedAt: started, unsafeDelayMs: args.unsafeDelayMs, runsPerTest: args.raceReps, tests: {} };
  for (const [id, n] of [['T16', 20], ['T17', 50]]) {
    const reps = [];
    for (let i = 1; i <= args.raceReps; i++) reps.push({ rep: i, ...(await raceConsume(n)(ctx)) });
    const violations = reps.filter((r) => r.outcome === 'INVARIANT_VIOLATED').length;
    result.tests[id] = { concurrent: n, runs: reps.length, violations, maxSuccessesInOneRun: Math.max(...reps.map((r) => r.observed.successes)) };
    console.log(`negative control ${id}: ${violations}/${reps.length} runs violated the invariant`);
  }
  result.harnessHasPower = Object.values(result.tests).some((t) => t.violations > 0);
  result.note = result.harnessHasPower ? 'The race harness detected the deliberately unsafe consume.'
    : 'No violation detected: the harness lacks power. Raise --unsafe-delay-ms or the parallelism before interpreting T15-T17.';
  fs.mkdirSync(outDir, { recursive: true });
  if (fs.readdirSync(outDir).length) throw new Error(`output directory ${outDir} is not empty`);
  fs.writeFileSync(path.join(outDir, 'negative-control.json'), JSON.stringify(result, null, 2));
  delete process.env.UNSAFE_NON_ATOMIC_CONSUME; delete process.env.UNSAFE_DELAY_MS;
  await app.stop(); await harness.close(); await sequelize.close();
  console.log(result.note);
  process.exit(result.harnessHasPower ? 0 : 3);
}

main().catch((e) => { console.error(e); process.exit(1); });
