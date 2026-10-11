'use strict';
// Predicted outcomes (EXPERIMENTS.md section 9). These are HYPOTHESES to be checked by execution, not results.
// Observed outcome vocabulary used by the harness:
//   BLOCKED | SUCCEEDS | BOUNDARY | DETECTED | RATE_LIMITED | INVARIANT_HELD | STEP1_BLOCKED_FINAL_OK
// (plus INVARIANT_VIOLATED / NOT_DETECTED / ... when something unexpected is observed).
const NA = 'N/A';
const T03_B = { a: 'BOUNDARY', b: 'DETECTED', c: 'SUCCEEDS' };
const T03_CD = { a: 'BOUNDARY', b: 'DETECTED', c: 'BLOCKED' };
const row = (a, b, c, d) => ({ A: a, B: b, C: c, D: d });
const ONLY_C = (v) => row(NA, NA, v, NA);

const PREDICTED = {
  T01: row('BOUNDARY', 'BOUNDARY', 'BOUNDARY', 'BOUNDARY'),
  T02: row('SUCCEEDS', 'SUCCEEDS', 'BLOCKED', 'BLOCKED'),
  T03: row(NA, T03_B, T03_CD, T03_CD),
  T04: row(NA, 'BLOCKED', 'BLOCKED', 'BLOCKED'),
  T05: ONLY_C('BLOCKED'), T06: ONLY_C('BLOCKED'), T07: ONLY_C('BLOCKED'), T08: ONLY_C('BLOCKED'),
  T09: row(NA, NA, 'BLOCKED', 'BLOCKED'),
  T10: ONLY_C('BLOCKED'), T11: ONLY_C('BLOCKED'), T12: ONLY_C('BLOCKED'), T13: ONLY_C('BLOCKED'), T14: ONLY_C('BLOCKED'),
  T15: ONLY_C('INVARIANT_HELD'), T16: ONLY_C('INVARIANT_HELD'), T17: ONLY_C('INVARIANT_HELD'),
  T18: ONLY_C('RATE_LIMITED'), T19: ONLY_C('BLOCKED'), T20: ONLY_C('RATE_LIMITED'),
  T21: row('BLOCKED', 'BLOCKED', 'BLOCKED', 'BLOCKED'),
  T22: row('BLOCKED', 'BLOCKED', 'BLOCKED', 'BLOCKED'),
  T23: row('BLOCKED', 'BLOCKED', 'BLOCKED', 'BLOCKED'),
  T24: row('BLOCKED', 'BLOCKED', 'BLOCKED', 'BLOCKED'),
  T25: row(NA, NA, 'STEP1_BLOCKED_FINAL_OK', 'STEP1_BLOCKED_FINAL_OK'),
  T26: ONLY_C('BOUNDARY'),
  T27: ONLY_C('INVARIANT_HELD'),
  T28: row(NA, NA, NA, 'RATE_LIMITED'),
  T29: row(NA, NA, NA, 'BOUNDARY'),
};

const TEST_IDS = Object.keys(PREDICTED);
module.exports = { PREDICTED, TEST_IDS, NA };
