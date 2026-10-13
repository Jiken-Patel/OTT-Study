'use strict';
// Resource sampling (EXPERIMENTS.md 12): CPU and memory of the server process, MySQL, the OOB sink and the load
// generator, sampled at 1 Hz. Linux reads /proc (instantaneous CPU from tick deltas). Elsewhere it falls back to
// `ps` (cumulative-average CPU, flagged as such): use Linux for the real runs.
const fs = require('fs');
const { execFileSync } = require('child_process');

let CLK_TCK = 100; let PAGE = 4096;
try {
  CLK_TCK = Number(execFileSync('getconf', ['CLK_TCK']).toString().trim()) || 100;
  PAGE = Number(execFileSync('getconf', ['PAGESIZE']).toString().trim()) || 4096;
} catch (e) { /* defaults */ }

/** /proc/<pid>/stat -> { utime, stime } in clock ticks. The command name may contain spaces/parentheses. */
function parseStat(text) {
  const rest = text.slice(text.lastIndexOf(')') + 2).split(' '); // rest[0] is field 3 (state)
  return { utime: Number(rest[11]), stime: Number(rest[12]) };
}
/** /proc/<pid>/statm -> resident set size in bytes. */
function parseStatm(text, pageSize = PAGE) { return Number(text.trim().split(/\s+/)[1]) * pageSize; }

const hasProc = fs.existsSync('/proc/self/stat');
const unsupported = process.platform === 'win32'; // no /proc and no ps: record nothing rather than wrong numbers

function readProc(pid) {
  const st = parseStat(fs.readFileSync(`/proc/${pid}/stat`, 'utf8'));
  return { ticks: st.utime + st.stime, rss: parseStatm(fs.readFileSync(`/proc/${pid}/statm`, 'utf8')) };
}
function readPs(pid) {
  const out = execFileSync('ps', ['-o', '%cpu=,rss=', '-p', String(pid)]).toString().trim().split(/\s+/);
  return { cpuPct: Number(out[0]), rss: Number(out[1]) * 1024 };
}

function createSampler(pids) { // pids: { name: pid | null }
  const samples = []; const last = {}; let timer = null;
  const tick = () => {
    if (unsupported) return;
    const now = Date.now();
    for (const [name, pid] of Object.entries(pids)) {
      if (!pid) continue;
      try {
        if (hasProc) {
          const r = readProc(pid); const prev = last[name]; last[name] = { t: now, ticks: r.ticks };
          if (prev) samples.push({ t: now, name, cpuPct: ((r.ticks - prev.ticks) / CLK_TCK) / ((now - prev.t) / 1000) * 100, rssMB: r.rss / 2 ** 20 });
        } else {
          const r = readPs(pid); samples.push({ t: now, name, cpuPct: r.cpuPct, rssMB: r.rss / 2 ** 20 });
        }
      } catch (e) { /* process gone */ }
    }
  };
  return {
    method: unsupported ? 'unsupported' : hasProc ? 'proc-delta' : 'ps-average',
    start() { tick(); timer = setInterval(tick, 1000); },
    stop() { clearInterval(timer); tick(); return samples; },
  };
}

/** Mean and peak CPU (% of one core) and memory (MB) per process within [fromMs, toMs]. */
function summarizeWindow(samples, fromMs, toMs) {
  const out = {};
  for (const name of new Set(samples.map((s) => s.name))) {
    const w = samples.filter((s) => s.name === name && s.t >= fromMs && s.t <= toMs);
    if (!w.length) { out[name] = { samples: 0 }; continue; }
    const mean = (k) => w.reduce((a, s) => a + s[k], 0) / w.length;
    out[name] = { samples: w.length, cpuMeanPct: mean('cpuPct'), cpuPeakPct: Math.max(...w.map((s) => s.cpuPct)),
      memMeanMB: mean('rssMB'), memPeakMB: Math.max(...w.map((s) => s.rssMB)) };
  }
  return out;
}

module.exports = { parseStat, parseStatm, createSampler, summarizeWindow, CLK_TCK, PAGE };
