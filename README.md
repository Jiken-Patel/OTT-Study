# ott-study — Stages 1–7(implementation, security harness, benchmarks and analysis)

Implements the database layer defined by `EXPERIMENTS.md` v1.3 (sections 3, 7, 8.2):

- `db/schema.sql` — authoritative schema (MySQL 8.0.16+, InnoDB, `DATETIME(3)`), including the
  `CHECK (used_at IS NULL OR superseded_at IS NULL)` invariant.
- `src/models/` — Sequelize models mirroring the schema (never call `sync()`).
- `src/db/ottTransactions.js` — OTT issuance (7.3) and consumption (7.4), fixed-order binding check,
  state classification, security-event logging, and the test-only negative-control flags (8.2).
- `scripts/resetDb.js` — drops and recreates all tables (used before every run).
- `src/config/index.js` — config loader. Frozen variables (TTLs, bcrypt cost 12, HS256, thread pool 16,
  password 8-72 bytes) are constants, not env-configurable. Invalid or forbidden settings throw at startup.
- `src/services/tokenService.js` — HS256-only JWT sign/verify. `jsonwebtoken` does not require
  `exp`, `iat`, `sub`, `jti` or `type`, so they are enforced explicitly.
- `src/services/revocation.js` — access-token `jti` revocation (active in every configuration).
- `src/middleware/authenticate.js` — `authenticateAccessToken`: strict Bearer parsing, uniform generic 401,
  revocation check on every request, fails closed on database errors.
- `src/app.js`, `src/server.js` — Express app factory (helmet, 10 KB body limit, no `x-powered-by`),
  `GET /api/health`, `GET /api/profile` (benchmark P1 endpoint).
- `src/services/passwords.js` — native bcrypt (cost 12), password policy (8–72 bytes), dummy comparison for unknown users.
- `src/services/authService.js` — register, login, refresh rotation with reuse detection, logout.
- `src/routes/auth.js` — `POST /api/auth/register | login | refresh | logout` (`/refresh` is not mounted in Config A).
- `src/middleware/rateLimit.js` — the five limiters from EXPERIMENTS.md 3.1 (`standard` / `relaxed` / `off`).
- `src/operations.js` — operation registry (EXPERIMENTS.md 7.1): purpose / method / registered endpoint per operation.
- `src/middleware/stepUp.js` — step-up guard chosen by `AUTH_MODE` (A/B none, D password re-entry, C fails closed until Stage 5).
- `src/routes/sensitive.js`, `src/services/sensitiveService.js` — `POST /api/auth/change-password` and the simulated routes.
- `sink/oobSink.js`, `sink/server.js` — the simulated OOB channel (test infrastructure; `npm run sink`).
- `src/services/oobDelivery.js`, `src/services/ottService.js`, `src/routes/ott.js` — Config C: delivery handoff,
  OTT issuance (`POST /api/ott/request`), the verification guard and consume-and-apply.
- `test/helpers/sinkClient.js` — harness-side inbox reader (uses the read key).
- `harness/security/` — the T01–T29 security harness (Stage 6): `matrix.js` (predicted outcomes from EXPERIMENTS.md
  section 9), `env.js` (app instances, seeded users, OOB inbox reader), `tests.js` (the 29 tests), `runner.js`, `report.js`.
- `bench/` — Stage 7: `k6/workflow.js` (P1/P2a/P2b/P3 workload), `schedule.js`, `run.js` (orchestrator), `sampler.js`, `stats.js`,
  `analyze.js`.
- `test/stage1.test.js` … `test/stage5.test.js`, `test/stats.test.js`, `test/stage7.test.js` — development tests. **These are not experiment results.**

## Setup

```bash
cp .env.example .env        # set DB_PASSWORD
mysql -uroot -e "CREATE DATABASE ott_study CHARACTER SET utf8mb4;
  CREATE USER 'ott'@'127.0.0.1' IDENTIFIED BY 'change_me';
  GRANT ALL ON ott_study.* TO 'ott'@'127.0.0.1';"
npm install
npm run db:reset
npm test                    # runs with APP_PROFILE=test
```

## Design rules enforced here

- Lock order is always `users` -> `one_time_tokens`, isolation READ COMMITTED, lock wait 5 s.
- Lock-wait (1205) / deadlock (1213) errors are never retried; they surface as `DB_LOCK_ERROR`.
- bcrypt hashing must happen **before** `consumeOtt()`; the `operation(t)` callback runs inside the
  transaction and should only do the cheap UPDATE.
- The raw OTT is returned once by `issueOtt()` for delivery to the OOB sink after commit; only its
  SHA-256 hash is stored.
- `UNSAFE_NON_ATOMIC_CONSUME` / `UNSAFE_DELAY_MS` are refused unless `APP_PROFILE=test`.

## Assumptions to confirm (not specified in EXPERIMENTS.md)

- CommonJS modules, Sequelize v6, `mysql2`.
- `users` has only `email`, `password_hash`, `password_changed_at` (no role/RBAC columns yet).
- `security_events.event_type` / `reason` are free-form strings; the vocabulary is in EXPERIMENTS.md 7.4.

## Stage 2 implementation decisions (not spelled out in EXPERIMENTS.md)

- Every authentication failure is logged as an `AUTH_FAILURE` security event, awaited before the response,
  in all configurations. Successful requests are not logged. A logging failure never changes the response.
  Reasons: `MISSING_AUTH_HEADER`, `MALFORMED_AUTH_HEADER`, `TOKEN_INVALID`, `TOKEN_EXPIRED`,
  `TOKEN_NOT_YET_VALID`, `TOKEN_WRONG_TYPE`, `TOKEN_CLAIMS_INVALID`, `TOKEN_REVOKED`.
- All failures return the same body `{"error":"Authentication failed"}` (no oracle); tokens never reach logs.
- Because failed authentication writes a row, the per-IP rate limiter (Stage 3+) must run **before**
  authentication, as EXPERIMENTS.md 3.2 already specifies; otherwise a flood of bad tokens is a write-amplification vector.
- The DB session time zone is forced to UTC (`src/config/db.js`) so all DB-time comparisons are consistent.

## Tests

`npm test` runs the implementation, statistics and benchmark-support tests (108 tests; needs a MySQL 8.0.16+ database as in Setup). Mutation checks done during
development: removing the exp/iat check, the jti check, the type check, the algorithm whitelist, the revocation
check, or making the middleware fail open each makes at least one test fail.

## Stage 3 implementation decisions (not spelled out in EXPERIMENTS.md)

- **Logout** requires `refreshToken` in Configs B/C/D (400 otherwise, and nothing is revoked). It revokes the access
  `jti` and the whole refresh family in one transaction. A refresh token belonging to another user is ignored.
  In Config A only the access `jti` is revoked.
- **Reuse policy:** presenting a revoked refresh token revokes its whole family and logs `REFRESH_REPLAY`. This also
  applies to a legitimate client that submits the same token twice concurrently (the loser triggers revocation).
- **Lock order** is `users` first in registration-free paths that touch `refresh_tokens` (rotation, logout), matching OTT code.
- **Registration** is not rate-limited (not listed in 3.1) and returns 409 for a duplicate email (email enumeration is
  accepted for this prototype).
- **Login** always performs one bcrypt comparison (dummy hash for unknown users); a password longer than 72 bytes is
  rejected as invalid credentials.
- **Audit events:** `REGISTER`, `LOGIN_SUCCESS`, `LOGIN_FAILURE` (`USER_NOT_FOUND`, `BAD_PASSWORD`, `INVALID_INPUT`),
  `REFRESH_SUCCESS`, `REFRESH_FAILURE`, `REFRESH_REPLAY`, `LOGOUT`, `RATE_LIMITED` (first blocked request per key per
  window only). Passwords and tokens are never written.
- Lock-wait/deadlock errors on refresh/logout return 500 and are not retried. They are not yet written as
  `DB_LOCK_ERROR` events (the OTT stage will add that).
- The per-user limiters (`ottIssue`, `sensitiveUser`) and `sensitiveIp` exist and are tested but are not mounted until
  the OTT and sensitive endpoints exist.

Mutation checks done for Stage 3: removing family revocation on replay, old-token revocation on rotation, family
revocation on logout, the ownership check on logout, the users lock in rotation, the dummy bcrypt comparison, the
log-once rule, or per-user limiter keying each makes at least one test fail.

## Stage 4 implementation decisions (not spelled out in EXPERIMENTS.md)

- **Chain order** on every sensitive route: per-IP limiter -> authenticate -> per-user limiter -> body validation
  (400) -> step-up guard -> handler.
- **Config D** failures (missing, non-string, over-72-byte or wrong `currentPassword`) all return the same 403 body
  and are logged as `PASSWORD_REENTRY_FAILURE` (`MISSING_PASSWORD`, `INVALID_INPUT`, `BAD_PASSWORD`).
  A malformed `newPassword` is a 400 and is checked first.
- **Config C fails closed**: until Stage 5, every sensitive route returns 501, so C can never run unprotected.
- **Simulated routes** (`confirm-email` POST/PUT, `update-security-settings`) change no state, log one
  `SENSITIVE_OPERATION_SUCCESS` event, and are mounted only with `ENABLE_SIMULATED_OPERATIONS=true`
  (a clarification of EXPERIMENTS.md 7.1; see its amendments log).
- **A password change does not revoke existing sessions** (access tokens or refresh families), in any configuration.
  The spec does not ask for it and it would add a variable; treat it as a limitation of the prototype.
- `SENSITIVE_OPERATION_SUCCESS` is written after the password UPDATE, outside any transaction, in all configurations.

Mutation checks done for Stage 4: skipping the D password comparison, making C fail open, removing authentication
from the chain, removing body validation, putting the per-IP limiter after authentication, and mounting the
simulated routes unconditionally each make at least one test fail.

## Stage 5 implementation decisions (not spelled out in EXPERIMENTS.md)

- **OOB sink:** a loopback HTTP service with two different keys. The app holds only the deliver key and has no
  code or key to read the inbox. Reading deletes. Memory is bounded (100 messages per user). Config C refuses to
  start unless `OOB_SINK_URL` is loopback and `OOB_SINK_KEY` is at least 16 characters.
- **Issuance** (`POST /api/ott/request`, Config C only): body `{purpose, operation}`, validated against the
  registry; the response is `202 {status, expiresIn}` and never contains the OTT. Delivery happens after commit and
  is not awaited. A delivery failure is logged as `OTT_DELIVERY_FAILURE` (`SINK_UNREACHABLE`, `SINK_TIMEOUT`,
  `SINK_STATUS_<code>`) and the caller is not told. The per-IP limiter also guards this route.
- **Verification order** (guard, then consume): authenticate -> per-user limiter -> body validation (400) -> `ott`
  present and plausible -> hash lookup -> binding in the frozen order -> bcrypt of the new password (outside any
  transaction) -> atomic consume + write in one transaction -> success event after commit.
- **Failed attempts:** a mismatch or state failure increments `attempt_count` on the matched row, outside the
  transaction; an unmatched token touches no row. Every failure returns the same 403 body.
- **Defence in depth:** user mismatch is also enforced by the consume statement (`user_id = :userId`), so removing
  the guard's user check alone does not open a hole; purpose, method and endpoint are enforced only by the guard.
- **Events added:** `OTT_ISSUED`, `OTT_FAILURE`, `OTT_DELIVERY_FAILURE`, `DB_LOCK_ERROR` (reason = MySQL errno).
  A lock error is a 500 and is never retried.

Mutation checks done for Stage 5: skipping the binding check, ignoring a failed consume, not superseding on
re-issue, awaiting delivery in the request, not counting failed attempts, letting the deliver key read the inbox,
not logging lock errors, and not enforcing expiry each make at least one test fail.

## Stage 6: security harness (EXPERIMENTS.md section 8)

```bash
npm run security                                  # all configs, 30 reps (100 for T15-T17 and T27), -> results/security/
npm run security -- --configs C --tests T16,T17   # a subset
npm run security -- --reps 5 --race-reps 10 --out /tmp/try   # quick trial run (NOT experiment data)
npm run security -- --negative-control            # EXPERIMENTS.md 8.2 -> results/security/negative-control/
```

- Every run starts from a reset database and OOB sink; the output directory must be empty (raw data is never
  overwritten). Running the main run first and the negative control second is fine; the main run tolerates an existing
  `negative-control/` sub-folder.
- Output: `config-<X>/<TEST>.json` (every repetition, all observations), `summary.json`, `matrix.md` (observed
  outcomes with a warning on every cell that differs from the prediction), `metadata.json` (versions, machine,
  git commit or `TBD`). The exit code is 2 when any cell differs from the prediction.
- **Predicted outcomes are hypotheses.** Only observed counts are results. A cell that differs is reported, not
  hidden (unauthorized successes in flooding tests are reported as `SUCCEEDS`).
- Rate-limit tests (T18, T20, T28) start every repetition (and, in T18, every sub-variant) from a fresh application
  with the `standard` profile; all others use `relaxed`. T06 uses `OTT_EXPIRES_IN_SECONDS=2`.
- T18 has three sub-variants: one user from one address, 31 users from one address, and one user alternating
  between three source addresses (`127.0.0.1/2/3`). The last needs loopback aliases (Linux has them; macOS and
  Windows may not and the sub-variant is then recorded as skipped).
- Setup users are inserted with one precomputed bcrypt hash and then log in through the real API.
- Race tests report violations as `x/n` plus, when `x = 0`, the exact 95% upper bound `1 - 0.05^(1/n)` (about 2.95% for n = 100).

How the harness itself was checked (smoke runs with 2-5 repetitions, not experiment data): all 26 executed cells for
A, B and D and all 27 for C matched their predictions; the negative control detected the deliberately unsafe consume
in 20/20 runs; and deliberately breaking the system (skipping the OTT binding check, skipping the revocation check,
disabling family revocation on replay, removing the Config D password comparison) made the harness report the
affected cells as differing from the prediction.

## Stage 7: benchmarks and analysis (EXPERIMENTS.md sections 10-13)

Requirements: [k6](https://k6.io) on the PATH (tested with v0.54), MySQL, **Linux** for accurate CPU sampling (`/proc`; other
systems fall back to `ps`, whose CPU figure is a cumulative average), and ideally a machine with at least 4 cores (k6, the
application, MySQL and the sink share it). The database user must be allowed to drop and create tables (the database is reset
before every run).

```bash
npm run bench -- --dry-run --runs 1            # show the schedule without running anything
npm run bench                                   # the full campaign: 45 conditions x 30 runs = 1,350 runs (about 17 h)
npm run bench -- --resume                       # continue after Ctrl-C or a crash (same --seed and --out)
npm run bench -- --benches P2b --levels 1,10 --runs 3 --warmup 2 --measure 4 --out /tmp/try   # quick trial (NOT experiment data)
npm run analyze -- --runs 30                    # -> results/performance/analysis/{report.md,comparisons.csv,conditions.csv,analysis.json}
```

- **Run order:** randomized complete blocks. Each block (one repetition) contains every condition once in a seeded random order
  (`--seed`, default 1), so configurations are interleaved. The schedule is saved to `schedule-seed<N>.json`.
- **Per run:** reset database (1,000 seeded users) and the OOB sink, start the application as its own process (rate limits `off`,
  frozen config, `APP_PROFILE=development`), mint access tokens for the first N users, run k6 (10 s warm-up + 30 s measurement),
  sample CPU/memory of app, MySQL, sink and k6 at 1 Hz, write `raw/config-<X>/<bench>_vu<N>_run<NN>_<timestamp>.json` plus a
  `.meta.json`. Files are never overwritten.
- **Iteration structure** (EXPERIMENTS.md 10.1): C issues an OTT, reads it from the sink, then calls the operation; B and D do an
  equivalent (empty) sink read, then the operation; P3 issues and drains; P1 is `GET /api/profile`. Only `ott_issue` and `op`
  requests are measured. Harness reads and idle gaps are never added to any metric.
- **Validity:** a run with more than 1% `harness_failure` iterations, a k6 failure or no iterations is marked invalid and repeated
  (up to `--max-attempts`, default 3); invalid attempts stay on disk and are listed in the report.
- **Analysis:** one summary value per run (median, p95, p99, mean, std, throughput, error rate, CPU, memory); Mann-Whitney U per
  benchmark and level; median difference and overhead % with 95% percentile-bootstrap CIs (10,000 resamples, seeded);
  primary family = B vs C median latency in P2a/P2b (unadjusted p as required, plus Holm over that family), secondary family =
  everything else, Holm-adjusted. P4 (step-up workflow latency) is derived from the P2 runs.
- **Interpretation caveat** (printed at the top of the report): the load is closed-loop, so at equal VU count Config C sends fewer
  simultaneous operation requests than B or D; read latency together with the achieved throughput table.

How this was checked (not experiment data): the statistics were validated against scipy (`mannwhitneyu`, `norm.sf`) and a Holm
worked example; the analysis was run on synthetic runs with a known 10% overhead (recovered, CI covers it), a no-effect case,
invalid attempts and retries; and the whole pipeline (orchestrator, k6, sampler, analysis) was run end to end with tiny
durations on a single-core sandbox. **Those timings are not representative of anything**: do the real campaign on a proper machine.
