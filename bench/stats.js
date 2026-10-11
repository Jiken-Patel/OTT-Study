'use strict';
// Statistics for the performance analysis (EXPERIMENTS.md section 12). The unit of analysis is ONE SUMMARY
// VALUE PER RUN; never feed individual request latencies into these functions.
//   - two-sided Mann-Whitney U (normal approximation with tie correction and continuity correction;
//     identical to scipy.stats.mannwhitneyu(..., use_continuity=True, method='asymptotic'))
//   - percentile bootstrap CI for a difference of medians and for the relative overhead
//   - Holm step-down correction

const sorted = (xs) => [...xs].sort((a, b) => a - b);
function median(xs) {
  const a = sorted(xs); const n = a.length;
  if (!n) return NaN;
  return n % 2 ? a[(n - 1) / 2] : (a[n / 2 - 1] + a[n / 2]) / 2;
}
const mean = (xs) => xs.reduce((s, v) => s + v, 0) / xs.length;
function quantile(xs, q) { // linear interpolation (type 7)
  const a = sorted(xs); if (!a.length) return NaN;
  const pos = (a.length - 1) * q; const lo = Math.floor(pos); const hi = Math.ceil(pos);
  return a[lo] + (a[hi] - a[lo]) * (pos - lo);
}

// ---- normal distribution tail ------------------------------------------------------------------
function erfc(x) {
  const ax = Math.abs(x);
  let r;
  if (ax < 2.5) { // Maclaurin series for erf (accurate here; erfc is not tiny yet)
    let term = ax; let sum = ax;
    for (let n = 1; n < 200; n++) { term *= -ax * ax / n; const add = term / (2 * n + 1); sum += add; if (Math.abs(add) < 1e-17 * Math.abs(sum)) break; }
    r = 1 - (2 / Math.sqrt(Math.PI)) * sum;
  } else { // continued fraction, evaluated bottom-up:
    // erfc(x) = exp(-x^2) / (sqrt(pi) * (x + (1/2)/(x + (2/2)/(x + (3/2)/(x + ...)))))
    let t = ax;
    for (let k = 200; k >= 1; k--) t = ax + (k / 2) / t;
    r = Math.exp(-ax * ax) / (Math.sqrt(Math.PI) * t);
  }
  return x >= 0 ? r : 2 - r;
}
const normalSf = (z) => 0.5 * erfc(z / Math.SQRT2); // P(Z > z)

// ---- Mann-Whitney U ----------------------------------------------------------------------------
function averageRanks(values) {
  const idx = values.map((v, i) => [v, i]).sort((a, b) => a[0] - b[0]);
  const ranks = new Array(values.length); const ties = [];
  for (let i = 0; i < idx.length;) {
    let j = i; while (j + 1 < idx.length && idx[j + 1][0] === idx[i][0]) j++;
    const r = (i + j) / 2 + 1; // 1-based average rank
    for (let k = i; k <= j; k++) ranks[idx[k][1]] = r;
    if (j > i) ties.push(j - i + 1);
    i = j + 1;
  }
  return { ranks, ties };
}

/** Two-sided Mann-Whitney U. Returns { U1, U2, z, p, n1, n2 } (U1 refers to x). */
function mannWhitneyU(x, y) {
  const n1 = x.length; const n2 = y.length; const N = n1 + n2;
  if (n1 < 1 || n2 < 1) throw new Error('both groups need at least one value');
  const { ranks, ties } = averageRanks([...x, ...y]);
  const R1 = ranks.slice(0, n1).reduce((s, v) => s + v, 0);
  const U1 = R1 - (n1 * (n1 + 1)) / 2; const U2 = n1 * n2 - U1;
  const mu = (n1 * n2) / 2;
  const tieTerm = ties.reduce((s, t) => s + (t ** 3 - t), 0) / (N * (N - 1));
  const sigma = Math.sqrt(((n1 * n2) / 12) * ((N + 1) - tieTerm));
  if (sigma === 0) return { U1, U2, z: 0, p: 1, n1, n2 };
  const z = (Math.max(U1, U2) - mu - 0.5) / sigma;
  return { U1, U2, z, p: Math.min(1, 2 * normalSf(z)), n1, n2 };
}

// ---- seeded RNG + bootstrap --------------------------------------------------------------------
function rng(seed) { // mulberry32
  let a = seed >>> 0;
  return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const resample = (xs, rand) => { const out = new Array(xs.length); for (let i = 0; i < xs.length; i++) out[i] = xs[Math.floor(rand() * xs.length)]; return out; };

/**
 * Percentile bootstrap CI. `a` = reference group (e.g. B), `b` = compared group (e.g. C).
 * kind 'diff'    : median(b) - median(a)
 * kind 'overhead': (median(b) - median(a)) / median(a) * 100
 */
function bootstrapCI(a, b, { kind = 'diff', B = 10000, alpha = 0.05, seed = 1 } = {}) {
  const rand = rng(seed);
  const stat = (xa, xb) => { const ma = median(xa); const mb = median(xb); return kind === 'overhead' ? ((mb - ma) / ma) * 100 : mb - ma; };
  const est = stat(a, b);
  const draws = new Array(B);
  for (let i = 0; i < B; i++) draws[i] = stat(resample(a, rand), resample(b, rand));
  const s = sorted(draws.filter((v) => Number.isFinite(v)));
  if (!s.length) return { estimate: est, lo: NaN, hi: NaN, B };
  return { estimate: est, lo: s[Math.floor((alpha / 2) * s.length)], hi: s[Math.min(s.length - 1, Math.ceil((1 - alpha / 2) * s.length) - 1)], B };
}

// ---- Holm ---------------------------------------------------------------------------------------
function holm(pvalues) {
  const m = pvalues.length;
  const order = pvalues.map((p, i) => [p, i]).sort((x, y) => x[0] - y[0]);
  const adj = new Array(m); let running = 0;
  order.forEach(([p, i], k) => { running = Math.max(running, Math.min(1, (m - k) * p)); adj[i] = running; });
  return adj;
}

module.exports = { median, mean, quantile, mannWhitneyU, bootstrapCI, holm, rng, normalSf, averageRanks };
