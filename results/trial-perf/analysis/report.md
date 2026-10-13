# Performance analysis

Valid runs analysed: **18** (18 attempts on disk, 0 invalid attempt(s) excluded).
Machine: 11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz x8, 16 GB, win32 10.0.26300; Node v23.5.0; MySQL 8.0.42; k6.exe v2.2.0 (commit/00a9a1b7f5, go1.26.5, windows/amd64); commit b6742eaee7bdafef6aaad90ede332dbc2a4de43b; warm-up 2 s, measurement 4 s.

> **Read before interpreting.** The load generator is closed-loop: in Config C each virtual user also performs the issuance request and the OOB sink read, so at equal VU count C sends fewer simultaneous `op` requests than B or D. Compare latencies together with the achieved throughput below, and do not describe a latency difference as pure OTT overhead. Config C's cost also includes an in-process loopback HTTP handoff to the sink (likely cheaper than a real mail or SMS call). k6, the application, MySQL and the sink share one machine.

## P2a: primary comparison, B vs C, per-run median latency (ms)

_no data_

## P2b: primary comparison, B vs C, per-run median latency (ms)

| VUs | runs B/C | median B | median C | diff (C-B) [95% CI] | overhead % [95% CI] | p (MWU) | p Holm (primary family) |
|---|---|---|---|---|---|---|---|
| 1 | 3/3 | 10.83 | 21.75 | 10.92 [7.72, 15.08] | 100.9 [64.5, 144.5] | 0.0809 | 0.1617 |
| 10 | 3/3 | 24.29 | 48.95 | 24.67 [22.53, 26.91] | 101.6 [88.4, 111.4] | 0.0809 | 0.1617 |

## Achieved throughput of the measured operation (req/s, median of per-run values)

| Bench | VUs | A | B | C | D |
|---|---|---|---|---|---|
| P2b | 1 | - | 78.8 | 15.5 | 3.8 |
| P2b | 10 | - | 363.0 | 93.0 | 17.8 |

## Latency per condition (per-run medians: median [Q1, Q3], ms)

| Bench | VUs | Config | runs | median | p95 | p99 | error rate | harness failures |
|---|---|---|---|---|---|---|---|---|
| P2b | 1 | B | 3 | 10.83 [10.64, 11.40] | 17.98 | 29.09 | 0.0000 | 0 |
| P2b | 1 | C | 3 | 21.75 [20.72, 23.64] | 54.37 | 181.57 | 0.0000 | 0 |
| P2b | 1 | D | 3 | 248.69 [243.35, 252.07] | 365.30 | 503.18 | 0.0000 | 0 |
| P2b | 10 | B | 3 | 24.29 [24.22, 24.89] | 38.63 | 62.53 | 0.0000 | 0 |
| P2b | 10 | C | 3 | 48.95 [48.49, 50.00] | 79.73 | 105.95 | 0.0000 | 0 |
| P2b | 10 | D | 3 | 549.81 [506.49, 560.33] | 632.90 | 785.28 | 0.0000 | 0 |
| P4b | 1 | B | 3 | 10.83 [10.64, 11.40] | 17.98 | 29.09 | 0.0000 | 0 |
| P4b | 1 | C | 3 | 45.35 [42.97, 48.87] | 83.13 | 214.98 | 0.0000 | 0 |
| P4b | 1 | D | 3 | 248.69 [243.35, 252.07] | 365.30 | 503.18 | 0.0000 | 0 |
| P4b | 10 | B | 3 | 24.29 [24.22, 24.89] | 38.63 | 62.53 | 0.0000 | 0 |
| P4b | 10 | C | 3 | 99.94 [99.13, 102.50] | 162.54 | 255.00 | 0.0000 | 0 |
| P4b | 10 | D | 3 | 549.81 [506.49, 560.33] | 632.90 | 785.28 | 0.0000 | 0 |

## Resource use (mean CPU % of one core / mean RSS MB, median of per-run values)

| Bench | VUs | Config | app CPU | MySQL CPU | sink CPU | load-gen CPU | app MB | MySQL MB | sink MB |
|---|---|---|---|---|---|---|---|---|---|
| P2b | 1 | B | - | - | - | - | - | - | - |
| P2b | 1 | C | - | - | - | - | - | - | - |
| P2b | 1 | D | - | - | - | - | - | - | - |
| P2b | 10 | B | - | - | - | - | - | - | - |
| P2b | 10 | C | - | - | - | - | - | - | - |
| P2b | 10 | D | - | - | - | - | - | - | - |

## Secondary comparisons on per-run median latency (Holm-adjusted across ALL secondary tests, incl. other metrics)

| Bench | VUs | ref -> cmp | median ref | median cmp | change % [95% CI] | p (MWU) | p Holm |
|---|---|---|---|---|---|---|---|
| P2b | 1 | C -> D | 21.75 | 248.69 | 1043.3 [832.5, 1197.4] | 0.0809 | 1.0000 |
| P2b | 1 | B -> D | 10.83 | 248.69 | 2196.4 [1887.9, 2346.8] | 0.0809 | 1.0000 |
| P2b | 10 | C -> D | 48.95 | 549.81 | 1023.1 [807.2, 1088.6] | 0.0809 | 1.0000 |
| P2b | 10 | B -> D | 24.29 | 549.81 | 2163.9 [1716.8, 2264.2] | 0.0809 | 1.0000 |
| P4b | 1 | B -> C | 10.83 | 45.35 | 318.8 [239.0, 401.8] | 0.0809 | 1.0000 |
| P4b | 1 | C -> D | 45.35 | 248.69 | 448.4 [354.3, 529.3] | 0.0809 | 1.0000 |
| P4b | 1 | B -> D | 10.83 | 248.69 | 2196.4 [1887.9, 2346.8] | 0.0809 | 1.0000 |
| P4b | 10 | B -> C | 24.29 | 99.94 | 311.5 [285.7, 335.1] | 0.0809 | 1.0000 |
| P4b | 10 | C -> D | 99.94 | 549.81 | 450.2 [340.8, 480.5] | 0.0809 | 1.0000 |
| P4b | 10 | B -> D | 24.29 | 549.81 | 2163.9 [1716.8, 2264.2] | 0.0809 | 1.0000 |

P4 (step-up workflow) is derived from the P2 runs (issuance + operation for C, operation for B and D); it shares runs with P2, so P2 and P4 results are two views of the same data. Full results for every metric (median, p95, p99, throughput) are in `comparisons.csv`.

## Flags

_none_
