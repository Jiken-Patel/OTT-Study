'use strict';
// Condition list (EXPERIMENTS.md 11) and randomized-complete-block schedule (section 12).
const { rng } = require('./stats');

const BENCH_CONFIGS = { P1: ['A', 'B'], P2a: ['B', 'C', 'D'], P2b: ['B', 'C', 'D'], P3: ['C'] };
const DEFAULT_LEVELS = [1, 10, 50, 100, 250];

function conditions({ benches = Object.keys(BENCH_CONFIGS), configs = null, levels = DEFAULT_LEVELS } = {}) {
  const out = [];
  for (const bench of benches) {
    if (!BENCH_CONFIGS[bench]) throw new Error(`unknown benchmark ${bench}`);
    for (const config of BENCH_CONFIGS[bench]) {
      if (configs && !configs.includes(config)) continue;
      for (const vus of levels) out.push({ bench, config, vus });
    }
  }
  return out;
}

function shuffle(xs, rand) { const a = [...xs]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }

/**
 * One block per repetition: every condition runs exactly once per block, in a random order (seeded).
 * Configurations are therefore interleaved and slow drift (thermal, cache, background load) is not confounded
 * with configuration.
 */
function buildSchedule({ runs = 30, seed = 1, ...cond } = {}) {
  const conds = conditions(cond); const rand = rng(seed);
  const schedule = [];
  for (let run = 1; run <= runs; run++) for (const c of shuffle(conds, rand)) schedule.push({ ...c, run });
  return schedule;
}

module.exports = { conditions, buildSchedule, BENCH_CONFIGS, DEFAULT_LEVELS };
