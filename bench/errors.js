'use strict';
// Lists benchmark runs with failed operation requests, so the "error rate > 1%" flag can be investigated.
// Usage: node bench/errors.js [results/performance]
const fs = require('fs');
const path = require('path');
const root = path.resolve(process.argv[2] || 'results/performance');
const rows = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) walk(f);
    else if (f.endsWith('.json') && !f.endsWith('.meta.json') && f.includes(`${path.sep}raw${path.sep}`)) {
      let j; try { j = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (err) { continue; }
      const s = j.summary; if (!s) continue;
      for (const [name, m] of [['op', s.op], ['issue', s.issue]]) {
        if (m && m.count && m.failed > 0) rows.push({ file: e.name, step: name, failed: m.failed, count: m.count, rate: (100 * m.failed / m.count).toFixed(2) + '%',
          harnessFailures: s.harness ? s.harness.failures : null });
      }
    }
  }
})(path.join(root, 'raw'));
rows.sort((a, b) => parseFloat(b.rate) - parseFloat(a.rate));
if (!rows.length) console.log('no run had failed requests');
else { console.table(rows); console.log(`${rows.length} run/step combinations with failures. Check results/performance/logs/<same name>.app.log for server-side errors.`); }
