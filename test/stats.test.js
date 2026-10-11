'use strict';
// Statistics tests. Reference values (U, p) were computed with scipy 1.17
// scipy.stats.mannwhitneyu(x, y, alternative='two-sided', use_continuity=True, method='asymptotic').
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { median, quantile, mannWhitneyU, bootstrapCI, holm, normalSf, rng } = require('../bench/stats');

const FIX = {"shifted": {"x": [8.576, 11.264, 9.129, 9.741, 9.925, 9.259, 8.632, 10.649, 10.361, 8.047, 12.347, 10.968, 9.241, 10.902, 9.533, 9.939, 10.789, 8.743, 10.576, 11.399, 11.322, 9.7, 10.903, 8.378, 9.842, 10.449, 8.656, 9.918, 11.725, 12.618], "y": [11.533, 11.594, 9.449, 9.149, 8.905, 11.25, 11.502, 9.809, 9.126, 10.909, 10.975, 10.443, 12.124, 10.488, 10.521, 9.27, 10.763, 12.216, 10.673, 10.685, 11.12, 10.933, 11.236, 11.244, 11.342, 9.646, 10.96, 8.677, 10.92, 9.086], "U1": 342.0, "p": 0.11198687208268976}, "heavyTies": {"x": [5.0, 5.2, 4.8, 5.0, 4.3, 4.7, 5.3, 4.5, 5.3, 4.4, 4.6, 4.6, 5.0, 5.2, 4.6, 4.9, 5.6, 4.9, 4.7, 5.2, 4.9, 4.7, 4.3, 5.3, 4.8, 5.0, 4.6, 5.5, 5.3, 5.4], "y": [5.2, 5.4, 5.6, 5.6, 5.3, 5.2, 5.1, 4.9, 4.8, 5.3, 5.1, 4.4, 5.1, 5.6, 5.1, 4.5, 5.2, 5.5, 5.3, 5.0, 5.9, 6.0, 5.2, 5.5, 5.4, 5.5, 5.8, 5.5, 5.2, 4.9], "U1": 225.0, "p": 0.0008670298564477649}, "identical": {"x": [2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5], "y": [2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5, 2.5], "U1": 450.0, "p": 1.0}, "unequal": {"x": [0.8, 0.83, 1.89, 1.04, 1.45, 1.38, 1.91, 1.64, 0.73, 1.46], "y": [1.15, 0.88, 0.9, 0.74, 1.21], "U1": 35.0, "p": 0.24462360512698333}};

for (const [name, c] of Object.entries(FIX)) {
  test(`mannWhitneyU matches scipy: ${name}`, () => {
    const r = mannWhitneyU(c.x, c.y);
    assert.equal(r.U1, c.U1);
    assert.ok(Math.abs(r.p - c.p) < 1e-9, `p ${r.p} vs scipy ${c.p}`);
  });
}

test('mannWhitneyU: swapping the groups keeps p and mirrors U', () => {
  const a = FIX.shifted.x; const b = FIX.shifted.y;
  const r1 = mannWhitneyU(a, b); const r2 = mannWhitneyU(b, a);
  assert.equal(r1.U1, r2.U2); assert.ok(Math.abs(r1.p - r2.p) < 1e-12);
});

test('mannWhitneyU: fully separated groups give a tiny p; identical groups give p = 1', () => {
  const lo = Array.from({ length: 30 }, (_, i) => i); const hi = lo.map((v) => v + 1000);
  assert.ok(mannWhitneyU(lo, hi).p < 1e-9);
  assert.equal(mannWhitneyU([3, 3, 3], [3, 3, 3]).p, 1);
});

test('normalSf matches scipy.stats.norm.sf across the series/continued-fraction switch-over', () => {
  const ref = [[0, 0.5], [1, 0.15865525393145707], [1.96, 0.024997895148220435], [2.5, 0.006209665325776132], [3, 0.0013498980316300933], [4, 3.167124183311986e-05], [4.2426, 1.1047251836953543e-05], [4.3, 8.539905470991794e-06], [5, 2.866515718791933e-07], [6, 9.865876450376946e-10], [8, 6.22096057427174e-16], [10, 7.61985302416047e-24]];
  for (const [z, p] of ref) assert.ok(Math.abs(normalSf(z) - p) / p < 1e-9, `z=${z}: ${normalSf(z)} vs ${p}`);
  assert.ok(Math.abs(normalSf(-1) + normalSf(1) - 1) < 1e-15);
});

test('median / quantile', () => {
  assert.equal(median([3, 1, 2]), 2); assert.equal(median([4, 1, 3, 2]), 2.5);
  assert.equal(quantile([1, 2, 3, 4, 5], 0.5), 3); assert.equal(quantile([1, 2, 3, 4], 0.25), 1.75);
});

test('holm: worked example and monotonicity', () => {
  const adj = holm([0.01, 0.04, 0.03, 0.005]);
  assert.deepEqual(adj.map((v) => Math.round(v * 1e6) / 1e6), [0.03, 0.06, 0.06, 0.02]);
  assert.deepEqual(holm([0.5]), [0.5]);
  assert.deepEqual(holm([0.4, 0.9]), [0.8, 0.9]);
  assert.ok(holm([0.2, 0.3, 0.9]).every((p) => p <= 1));
});

test('bootstrapCI: deterministic for a seed, contains the estimate, recovers a known shift', () => {
  const r = rng(7);
  const a = Array.from({ length: 30 }, () => 100 + (r() - 0.5) * 10);
  const b = Array.from({ length: 30 }, () => 110 + (r() - 0.5) * 10);
  const c1 = bootstrapCI(a, b, { seed: 5 }); const c2 = bootstrapCI(a, b, { seed: 5 }); const c3 = bootstrapCI(a, b, { seed: 6 });
  assert.deepEqual(c1, c2); assert.notDeepEqual(c1, c3);
  assert.ok(c1.lo <= c1.estimate && c1.estimate <= c1.hi);
  assert.ok(c1.lo > 5 && c1.hi < 15, JSON.stringify(c1));
  const o = bootstrapCI(a, b, { kind: 'overhead', seed: 5 });
  assert.ok(o.estimate > 8 && o.estimate < 12 && o.lo < o.estimate && o.hi > o.estimate, JSON.stringify(o));
});

test('bootstrapCI: no difference -> the interval contains 0 (and contains it in ~95% of repeated samples)', () => {
  let covered = 0; const trials = 60;
  for (let t = 0; t < trials; t++) {
    const r = rng(1000 + t);
    const a = Array.from({ length: 30 }, () => r()); const b = Array.from({ length: 30 }, () => r());
    const ci = bootstrapCI(a, b, { B: 1000, seed: t + 1 });
    if (ci.lo <= 0 && 0 <= ci.hi) covered++;
  }
  assert.ok(covered / trials > 0.85, `coverage ${covered}/${trials}`); // loose: the percentile bootstrap undercovers slightly at n = 30
});
