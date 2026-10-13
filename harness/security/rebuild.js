'use strict';
// Regenerates summary.json and matrix.md from an existing results/security directory WITHOUT touching the raw
// per-repetition files. Used after a reporting correction: raw data stay exactly as measured.
//   node harness/security/rebuild.js --in results/security --out results/security-report-v2
// Corrections applied (reporting only, no new measurements):
//   T15-T17: attack-success successes = duplicate successes only (the single permitted consumption is not an attack success)
//   T27    : observed.successes = permitted consumptions (it was previously not recorded in that field)
const fs = require('fs');
const path = require('path');
const { T } = require('./tests');
const { PREDICTED, TEST_IDS, NA } = require('./matrix');
const { summarize, writeOutputs } = require('./report');

function parseArgs(argv) {
  const a = { in: 'results/security', out: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--in') a.in = argv[++i]; else if (argv[i] === '--out') a.out = argv[++i]; else throw new Error(`unknown argument ${argv[i]}`);
  }
  if (!a.out) throw new Error('--out is required (a new, empty directory)');
  return a;
}

function correct(id, rep) {
  const r = { ...rep };
  if (['T15', 'T16', 'T17'].includes(id) && r.observed && !r.error) r.counted = { attempts: r.observed.concurrentSent, successes: r.observed.duplicates };
  if (id === 'T27' && r.observed && !r.error) r.observed = { ...r.observed, successes: (r.observed.consumeStatuses && r.observed.consumeStatuses['200']) || 0 };
  return r;
}

function main() {
  const args = parseArgs(process.argv);
  const inDir = path.resolve(args.in);
  const meta = JSON.parse(fs.readFileSync(path.join(inDir, 'metadata.json'), 'utf8'));
  const summaries = [];
  for (const mode of ['A', 'B', 'C', 'D']) {
    const dir = path.join(inDir, `config-${mode}`);
    if (!fs.existsSync(dir)) continue;
    for (const id of TEST_IDS) {
      const f = path.join(dir, `${id}.json`);
      if (!fs.existsSync(f) || PREDICTED[id][mode] === NA) continue;
      const raw = JSON.parse(fs.readFileSync(f, 'utf8'));
      summaries.push(summarize(id, mode, raw.reps.map((r) => correct(id, r)), T[id]));
    }
  }
  meta.rebuild = { from: inDir, at: new Date().toISOString(),
    corrections: ['T15-T17 attack-success counts only duplicate successes', 'T27 permitted consumptions recorded in observed.successes'],
    note: 'Raw per-repetition files are unchanged; only the aggregation was corrected.' };
  const bad = writeOutputs(path.resolve(args.out), { meta, summaries, rawByCell: {}, includeRaw: false });
  console.log(`rebuilt ${summaries.length} cells -> ${path.resolve(args.out)} (${bad.length} differ from prediction)`);
}
main();
