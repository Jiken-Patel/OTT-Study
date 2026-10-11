'use strict';
// Benchmark orchestrator (EXPERIMENTS.md sections 10-12, 14). Usage:
//   node bench/run.js [--out results/performance] [--runs 30] [--levels 1,10,50,100,250] [--benches P1,P2a,P2b,P3]
//                     [--configs A,B,C,D] [--warmup 10] [--measure 30] [--reset-wait 5] [--seed 1] [--resume]
//                     [--max-attempts 3] [--mysql-pid N] [--k6 k6] [--dry-run]
// Per run: reset DB (seeded users) and the OOB sink -> start the app as its own process (rate limits off, frozen
// config) -> k6 (warm-up + measurement) with 1 Hz CPU/memory sampling of app, MySQL, sink and k6 -> save raw output.
// Run order is a randomized complete block design (every condition once per block, random order per block).
// Raw files are never overwritten; --resume only skips runs that already have a valid result.
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFileSync, execSync } = require('child_process');
const bcrypt = require('bcrypt');
const { QueryTypes } = require('sequelize');
const { resetDb } = require('../scripts/resetDb');
const sequelize = require('../src/config/db');
const { loadConfig } = require('../src/config');
const { createTokenService } = require('../src/services/tokenService');
const { buildSchedule, DEFAULT_LEVELS } = require('./schedule');
const { createSampler, summarizeWindow } = require('./sampler');

const SEEDED_USERS = 1000;                       // frozen (EXPERIMENTS.md 4)
const BENCH_PASSWORD = 'bench-password-fixed-1'; // newPassword (and currentPassword for D) never changes
const HARNESS_FAILURE_LIMIT = 0.01;              // > 1% harness_failure iterations => invalid, repeat (10.1)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseArgs(argv) {
  const a = { out: 'results/performance', runs: 30, levels: DEFAULT_LEVELS, benches: undefined, configs: undefined, warmup: 10, measure: 30,
    resetWait: 5, seed: 1, resume: false, maxAttempts: 3, mysqlPid: null, k6: 'k6', dryRun: false };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i]; const v = argv[i + 1];
    const num = () => { i++; return Number(v); };
    if (k === '--out') { a.out = v; i++; } else if (k === '--runs') a.runs = num();
    else if (k === '--levels') { a.levels = v.split(',').map(Number); i++; }
    else if (k === '--benches') { a.benches = v.split(','); i++; } else if (k === '--configs') { a.configs = v.split(','); i++; }
    else if (k === '--warmup') a.warmup = num(); else if (k === '--measure') a.measure = num();
    else if (k === '--reset-wait') a.resetWait = num(); else if (k === '--seed') a.seed = num();
    else if (k === '--max-attempts') a.maxAttempts = num(); else if (k === '--mysql-pid') a.mysqlPid = num();
    else if (k === '--k6') { a.k6 = v; i++; }
    else if (k === '--resume') a.resume = true; else if (k === '--dry-run') a.dryRun = true;
    else throw new Error(`unknown argument ${k}`);
  }
  return a;
}

const freePort = () => new Promise((resolve, reject) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); s.on('error', reject); });

async function waitFor(url, timeoutMs = 20000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try { const r = await fetch(url); if (r.ok) return; } catch (e) { /* not up yet */ }
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${url}`);
}
function stopChild(child) {
  return new Promise((resolve) => {
    if (!child || child.exitCode !== null) return resolve();
    const t = setTimeout(() => child.kill('SIGKILL'), 5000);
    child.once('exit', () => { clearTimeout(t); resolve(); });
    child.kill('SIGTERM');
  });
}
function findMysqlPid(explicit) {
  if (explicit) return explicit;
  for (const name of ['mysqld', 'mariadbd']) {
    try { const out = execFileSync('pgrep', ['-x', name]).toString().trim().split('\n')[0]; if (out) return Number(out); } catch (e) { /* not found */ }
  }
  return null;
}
const gitCommit = () => { try { return execSync('git rev-parse HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch (e) { return 'TBD'; } };

async function seedUsers(hash) {
  const rows = []; const repl = [];
  for (let i = 0; i < SEEDED_USERS; i++) { rows.push('(?, ?)'); repl.push(`bench${i}@example.test`, hash); }
  await sequelize.query(`INSERT INTO users (email, password_hash) VALUES ${rows.join(',')}`, { replacements: repl, type: QueryTypes.INSERT });
  return sequelize.query('SELECT id FROM users ORDER BY id', { type: QueryTypes.SELECT });
}

async function main() {
  const args = parseArgs(process.argv);
  const schedule = buildSchedule({ runs: args.runs, seed: args.seed, benches: args.benches, configs: args.configs, levels: args.levels });
  const out = path.resolve(args.out); const rawDir = path.join(out, 'raw');
  if (args.dryRun) { console.log(`${schedule.length} runs; first 10:`); schedule.slice(0, 10).forEach((s) => console.log(JSON.stringify(s))); return; }

  fs.mkdirSync(rawDir, { recursive: true });
  const done = new Set();
  const metaFiles = fs.readdirSync(rawDir, { recursive: true }).filter((f) => String(f).endsWith('.meta.json'));
  if (metaFiles.length && !args.resume) throw new Error(`${out} already contains runs; use --resume to continue, or a new --out (raw data is never overwritten)`);
  for (const f of metaFiles) { const m = JSON.parse(fs.readFileSync(path.join(rawDir, String(f)), 'utf8')); if (m.valid) done.add(`${m.bench}|${m.config}|${m.vus}|${m.run}`); }
  fs.writeFileSync(path.join(out, `schedule-seed${args.seed}.json`), JSON.stringify(schedule));
  fs.mkdirSync(path.join(out, 'logs'), { recursive: true });

  const secrets = { JWT_ACCESS_SECRET: crypto.randomBytes(24).toString('hex'), JWT_REFRESH_SECRET: crypto.randomBytes(24).toString('hex') };
  const sinkKeys = { deliver: crypto.randomBytes(12).toString('hex'), read: crypto.randomBytes(12).toString('hex') };
  const pwHash = await bcrypt.hash(BENCH_PASSWORD, 12);
  const [{ v: mysqlVersion }] = await sequelize.query('SELECT VERSION() AS v', { type: QueryTypes.SELECT });
  const k6Version = execFileSync(args.k6, ['version']).toString().trim();
  const mysqlPid = findMysqlPid(args.mysqlPid);
  const machine = { os: `${os.platform()} ${os.release()}`, cpu: `${os.cpus()[0] ? os.cpus()[0].model : 'unknown'} x${os.cpus().length}`, memoryGB: Math.round(os.totalmem() / 2 ** 30) };
  if (!mysqlPid) console.warn('warning: MySQL pid not found; its CPU/memory will not be recorded (use --mysql-pid)');
  if (os.cpus().length < 4) console.warn(`warning: only ${os.cpus().length} CPU core(s): k6, the app, MySQL and the sink will compete. Results from this machine are not representative.`);

  // Persistent OOB sink process (cleared before every run).
  const sinkPort = await freePort();
  const sinkProc = spawn(process.execPath, [path.join(__dirname, '..', 'sink', 'server.js')], { stdio: 'ignore',
    env: { PATH: process.env.PATH, OOB_SINK_PORT: String(sinkPort), OOB_SINK_DELIVER_KEY: sinkKeys.deliver, OOB_SINK_READ_KEY: sinkKeys.read } });
  const sinkUrl = `http://127.0.0.1:${sinkPort}`;
  await waitFor(`${sinkUrl}/health`);

  const total = schedule.length; let index = 0; const tStart = Date.now();
  let aborted = false;
  process.on('SIGINT', () => { aborted = true; console.log('\nstopping after the current run (use --resume to continue)...'); });
  try {
    for (const cond of schedule) {
      index += 1;
      if (aborted) break;
      const key = `${cond.bench}|${cond.config}|${cond.vus}|${cond.run}`;
      if (done.has(key)) continue;
      for (let attempt = 1; attempt <= args.maxAttempts; attempt++) {
        const r = await oneRun({ cond, attempt, args, rawDir, out, secrets, sinkKeys, sinkUrl, sinkPid: sinkProc.pid, mysqlPid, pwHash, mysqlVersion, k6Version, machine });
        const s = r.summary; const el = (Date.now() - tStart) / 1000; const perRun = el / Math.max(1, index);
        console.log(`[${index}/${total}] ${cond.bench} ${cond.config} vu${cond.vus} run${String(cond.run).padStart(2, '0')}${attempt > 1 ? ` (attempt ${attempt})` : ''}  `
          + (s ? `${cond.bench === 'P3' ? 'issue' : 'op'} median ${(cond.bench === 'P3' ? s.issue : s.op).median?.toFixed(1)} ms  p95 ${(cond.bench === 'P3' ? s.issue : s.op).p95?.toFixed(1)} ms  `
            + `${(cond.bench === 'P3' ? s.issue : s.op).throughput.toFixed(1)} req/s  err ${(cond.bench === 'P3' ? s.issue : s.op).failed}  harnessFail ${s.harness.failures}` : 'NO SUMMARY')
          + `  ${r.valid ? 'valid' : `INVALID (${r.invalidReason})`}  eta ${(perRun * (total - index) / 3600).toFixed(1)} h`);
        if (r.valid) break;
      }
    }
  } finally {
    await stopChild(sinkProc); await sequelize.close();
  }
}

async function oneRun({ cond, attempt, args, rawDir, out, secrets, sinkKeys, sinkUrl, sinkPid, mysqlPid, pwHash, mysqlVersion, k6Version, machine }) {
  const { bench, config, vus, run } = cond;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = `${bench}_vu${vus}_run${String(run).padStart(2, '0')}${attempt > 1 ? `_retry${attempt - 1}` : ''}_${stamp}`;
  const cfgDir = path.join(rawDir, `config-${config}`); fs.mkdirSync(cfgDir, { recursive: true });

  // 1. reset database (seed) and clear the OOB sink
  await resetDb();
  const ids = await seedUsers(pwHash);
  await fetch(`${sinkUrl}/reset`, { method: 'POST', headers: { 'x-sink-key': sinkKeys.read } });
  await sleep(args.resetWait * 1000); // settle (the ~5 s reset allowance in EXPERIMENTS.md 11)

  // 2. start the application as its own process
  const port = await freePort(); const baseUrl = `http://127.0.0.1:${port}`;
  const appEnv = { PATH: process.env.PATH, HOME: process.env.HOME, APP_PROFILE: 'development', AUTH_MODE: config, RATE_LIMIT_PROFILE: 'off',
    ENABLE_SIMULATED_OPERATIONS: 'true', PORT: String(port), UV_THREADPOOL_SIZE: '16', ...secrets,
    DB_HOST: process.env.DB_HOST || '127.0.0.1', DB_PORT: process.env.DB_PORT || '3306', DB_NAME: process.env.DB_NAME || 'ott_study',
    DB_USER: process.env.DB_USER || 'ott', DB_PASSWORD: process.env.DB_PASSWORD || '',
    ...(config === 'C' ? { OOB_SINK_URL: sinkUrl, OOB_SINK_KEY: sinkKeys.deliver } : {}) };
  const logFd = fs.openSync(path.join(out, 'logs', `${base}.app.log`), 'w');
  const app = spawn(process.execPath, [path.join(__dirname, '..', 'src', 'server.js')], { env: appEnv, stdio: ['ignore', logFd, logFd] });
  let result;
  try {
    await waitFor(`${baseUrl}/api/health`);

    // 3. tokens for the first `vus` seeded users (equivalent to a login; login is not benchmarked)
    const cfg = loadConfig({ ...appEnv, ...(config === 'C' ? {} : {}) });
    const ts = createTokenService(cfg);
    const users = ids.slice(0, vus).map((u) => ({ id: u.id, access: ts.signAccess(u.id).token }));
    const usersFile = path.join(os.tmpdir(), `ott-bench-users-${process.pid}.json`);
    fs.writeFileSync(usersFile, JSON.stringify(users));

    // 4. k6 + resource sampling
    const summaryPath = path.join(os.tmpdir(), `ott-bench-summary-${process.pid}.json`);
    try { fs.unlinkSync(summaryPath); } catch (e) { /* none */ }
    const k6Env = { PATH: process.env.PATH, HOME: process.env.HOME, BENCH: bench, CONFIG: config, VUS: String(vus), WARMUP_S: String(args.warmup), MEASURE_S: String(args.measure),
      BASE_URL: baseUrl, SINK_URL: sinkUrl, SINK_READ_KEY: sinkKeys.read, BENCH_PASSWORD, USERS_FILE: usersFile, SUMMARY_PATH: summaryPath };
    const k6 = spawn(args.k6, ['run', '--quiet', '--no-usage-report', path.join(__dirname, 'k6', 'workflow.js')], { env: k6Env, stdio: ['ignore', 'pipe', 'pipe'] });
    let k6err = ''; k6.stderr.on('data', (d) => { k6err += d; }); k6.stdout.on('data', () => {});
    const sampler = createSampler({ app: app.pid, mysql: mysqlPid, sink: sinkPid, loadgen: k6.pid });
    sampler.start();
    const k6Exit = await new Promise((resolve) => k6.on('exit', resolve));
    const samples = sampler.stop();

    // 5. results
    let summary = null;
    try { summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8')); } catch (e) { /* missing */ }
    let valid = true; let invalidReason = null;
    if (k6Exit !== 0 || !summary) { valid = false; invalidReason = `k6 exit ${k6Exit}${k6err ? `: ${k6err.slice(0, 200)}` : ''}`; }
    else {
      const attempted = summary.iterations.attempted;
      const hf = attempted ? summary.harness.failures / attempted : 0;
      if (hf > HARNESS_FAILURE_LIMIT) { valid = false; invalidReason = `harness_failure rate ${(hf * 100).toFixed(2)}% > 1%`; }
      else if (!attempted) { valid = false; invalidReason = 'no iterations in the measurement window'; }
    }
    const startMs = summary ? summary.meta.scenarioStartMs : 0;
    const from = startMs + args.warmup * 1000; const to = from + args.measure * 1000;
    const resources = startMs ? { window: { fromMs: from, toMs: to }, method: sampler.method, perProcess: summarizeWindow(samples, from, to) } : null;
    const meta = { valid, invalidReason, attempt, bench, config, vus, run, warmupS: args.warmup, measureS: args.measure, rateLimitProfile: 'off',
      appProfile: 'development', seededUsers: SEEDED_USERS, date: new Date().toISOString(), node: process.version, mysql: mysqlVersion, k6: k6Version, machine,
      gitCommit: gitCommit(), experimentDocVersion: '1.3', experimentVersion: 'v1', scheduleSeed: args.seed, pids: { app: app.pid, mysql: mysqlPid, sink: sinkPid, k6: k6.pid } };
    fs.writeFileSync(path.join(cfgDir, `${base}.json`), JSON.stringify({ summary, resources, samples }, null, 2), { flag: 'wx' });
    fs.writeFileSync(path.join(cfgDir, `${base}.meta.json`), JSON.stringify(meta, null, 2), { flag: 'wx' });
    result = { valid, invalidReason, summary };
  } finally {
    await stopChild(app); fs.closeSync(logFd);
  }
  return result;
}

main().catch((e) => { console.error(e); process.exit(1); });
