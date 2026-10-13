# Observed outcomes (security harness)

Generated 2026-10-12T09:15:39.766Z. Predicted outcomes (EXPERIMENTS.md section 9) are hypotheses; this table shows what was observed.

| Test | A | B | C | D |
|------|---|---|---|---|
| T01 | BOUNDARY | BOUNDARY | BOUNDARY | BOUNDARY |
| T02 | SUCCEEDS | SUCCEEDS | BLOCKED | BLOCKED |
| T03 | N/A | a: BOUNDARY, b: DETECTED, c: SUCCEEDS | a: BOUNDARY, b: DETECTED, c: BLOCKED | a: BOUNDARY, b: DETECTED, c: BLOCKED |
| T04 | N/A | BLOCKED | BLOCKED | BLOCKED |
| T05 | N/A | N/A | BLOCKED | N/A |
| T06 | N/A | N/A | BLOCKED | N/A |
| T07 | N/A | N/A | BLOCKED | N/A |
| T08 | N/A | N/A | BLOCKED | N/A |
| T09 | N/A | N/A | BLOCKED | BLOCKED |
| T10 | N/A | N/A | BLOCKED | N/A |
| T11 | N/A | N/A | BLOCKED | N/A |
| T12 | N/A | N/A | BLOCKED | N/A |
| T13 | N/A | N/A | BLOCKED | N/A |
| T14 | N/A | N/A | BLOCKED | N/A |
| T15 | N/A | N/A | INVARIANT_HELD | N/A |
| T16 | N/A | N/A | INVARIANT_HELD | N/A |
| T17 | N/A | N/A | INVARIANT_HELD | N/A |
| T18 | N/A | N/A | RATE_LIMITED | N/A |
| T19 | N/A | N/A | BLOCKED | N/A |
| T20 | N/A | N/A | RATE_LIMITED | N/A |
| T21 | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| T22 | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| T23 | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| T24 | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| T25 | N/A | N/A | STEP1_BLOCKED_FINAL_OK | STEP1_BLOCKED_FINAL_OK |
| T26 | N/A | N/A | BOUNDARY | N/A |
| T27 | N/A | N/A | INVARIANT_HELD | N/A |
| T28 | N/A | N/A | N/A | RATE_LIMITED |
| T29 | N/A | N/A | N/A | BOUNDARY |

## All executed cells match the prediction


## Attack-success counts (BOUNDARY cases excluded)

Unauthorized successes over attempts. For the concurrency tests T15-T17 only successes beyond the ONE permitted consumption count.

| Test | Config | successful / attempts |
|------|--------|-----------------------|
| T02 | A | 30 / 30 |
| T21 | A | 0 / 150 |
| T22 | A | 0 / 120 |
| T23 | A | 0 / 240 |
| T24 | A | 0 / 30 |
| T02 | B | 30 / 30 |
| T03 | B | 30 / 30 |
| T04 | B | 0 / 30 |
| T21 | B | 0 / 150 |
| T22 | B | 0 / 120 |
| T23 | B | 0 / 270 |
| T24 | B | 0 / 60 |
| T02 | C | 0 / 30 |
| T03 | C | 0 / 30 |
| T04 | C | 0 / 30 |
| T05 | C | 0 / 30 |
| T06 | C | 0 / 30 |
| T07 | C | 0 / 90 |
| T08 | C | 0 / 30 |
| T09 | C | 0 / 30 |
| T10 | C | 0 / 30 |
| T11 | C | 0 / 30 |
| T12 | C | 0 / 30 |
| T13 | C | 0 / 30 |
| T14 | C | 0 / 60 |
| T15 | C | 0 / 200 |
| T16 | C | 0 / 2000 |
| T17 | C | 0 / 5000 |
| T18 | C | 0 / 4290 |
| T19 | C | 0 / 30 |
| T20 | C | 0 / 600 |
| T21 | C | 0 / 150 |
| T22 | C | 0 / 120 |
| T23 | C | 0 / 270 |
| T24 | C | 0 / 60 |
| T27 | C | 0 / 2000 |
| T02 | D | 0 / 30 |
| T03 | D | 0 / 30 |
| T04 | D | 0 / 30 |
| T09 | D | 0 / 30 |
| T21 | D | 0 / 150 |
| T22 | D | 0 / 120 |
| T23 | D | 0 / 270 |
| T24 | D | 0 / 60 |
| T28 | D | 0 / 3000 |

## Race-condition invariants

| Test | Config | runs | violations | requests sent | successful consumptions | duplicates | db errors | 95% upper bound if 0 |
|---|---|---|---|---|---|---|---|---|
| T15 | C | 100 | 0 | 200 | 100 | 0 | 0 | 2.95% |
| T16 | C | 100 | 0 | 2000 | 100 | 0 | 0 | 2.95% |
| T17 | C | 100 | 0 | 5000 | 100 | 0 | 0 | 2.95% |
| T27 | C | 100 | 0 | 2000 | 100 | 0 | 0 | 2.95% |
