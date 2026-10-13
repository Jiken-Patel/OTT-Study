# EXPERIMENTS.md

**Study:** Security and Performance Trade-Offs of Dual-JWT Authentication with One-Time Tokens for Sensitive REST API Operations

**Document version:** 1.3
**Date:** 2026-10-02
**Status:** DESIGN SIGNED OFF on 2026-10-05 (all † defaults accepted). The document becomes fully FROZEN when the implementation commit hash is recorded in Section 16.
**Rule:** No numerical result appears in this document. Every result field is `TBD` until produced by an actual run.

Items marked **†** are values or design decisions proposed in this document that need author confirmation before freezing.

---

## 1. Research Purpose

Evaluate experimentally the security and performance trade-offs of adding a purpose- and operation-context-bound, single-use one-time token (OTT), delivered out-of-band (OOB), to Dual-JWT authentication for sensitive REST API operations.

| ID | Research question |
|----|-------------------|
| RQ1 | How does adding an OOB-delivered, purpose-bound, single-use token to Dual-JWT authentication affect the success of simulated replay and unauthorized-use attacks against sensitive operations, under defined attacker capabilities? |
| RQ2 | What performance overhead does the mechanism introduce compared with Dual-JWT alone? |
| RQ3 | What security and performance trade-offs arise compared with a conventional password re-entry step-up? |

| ID | Hypothesis (not assumed true) |
|----|-------------------------------|
| H1 | Under attacker capabilities that lack the OOB-delivered OTT (AC1, AC2), sensitive-operation attempts succeed less often in C than in B. |
| H2 | OTT issuance, verification and consumption add measurable latency compared with B. |
| H3 | Atomic consumption limits successful consumption of one OTT to at most one request, including under concurrency. |
| H4 | Binding to user, purpose, method and endpoint causes context-substitution attempts to fail. |
| H5 | The mechanism adds API interactions and state-management complexity. |
| H6 (exploratory) | C and D differ in step-up latency and in the set of attacks they resist. |

**Novelty is not claimed here.** The contribution is established only after the literature review.

---

## 2. Experimental Configurations

The configuration is selected by `AUTH_MODE=A|B|C|D`. Only the authentication and step-up behaviour differs between configurations.

| Config | Name | Credentials held | Sensitive-operation request |
|--------|------|------------------|-----------------------------|
| A | Single JWT | Access JWT | `Authorization` header + `newPassword` |
| B | Dual JWT | Access JWT + Refresh JWT (rotation) | same as A |
| C | Dual JWT + OOB OTT | Access + Refresh + OOB-delivered OTT | B + `ott` |
| D | Dual JWT + password re-entry | Access + Refresh + current password | B + `currentPassword` |

Comparisons: **B vs C** is primary, **C vs D** is secondary, and **A** is a baseline.

Identical across all configurations:

- access-JWT lifetime
- `jti` revocation on logout
- logging behaviour
- database schema
- seed data
- bcrypt cost

Refresh tokens exist only in B, C and D. Under A the `/api/auth/refresh` route is not mounted.

---

## 3. Frozen Variables

| Variable | Frozen value |
|----------|--------------|
| Access JWT lifetime | 15 minutes |
| Refresh JWT lifetime | 7 days |
| OTT lifetime (normal) | 5 minutes |
| OTT lifetime (profile `ott-expiry`, T06 only) | 2 seconds |
| OTT generation | 32 bytes from `crypto.randomBytes` |
| OTT storage | SHA-256 hash only |
| JWT algorithm | HS256 (separate access and refresh secrets) |
| JWT claims | `sub`, `type`, `iat`, `exp`, `jti`, `iss`, `aud`. `iss`, `aud`, `jti` and `type` are required. `nbf` is not issued, but the verifier validates it if present. |
| Password hashing | bcrypt, cost 12 |
| New-password validation | 8 to 72 bytes (bcrypt truncates beyond 72 bytes) † |
| `UV_THREADPOOL_SIZE` | 16 |
| DB connection pool | 20 |
| Transaction isolation | READ COMMITTED |
| MySQL `innodb_lock_wait_timeout` | 5 seconds † |
| DB time source | All expiry and state comparisons use DB time (`NOW(3)`, `DATETIME(3)` columns) |
| OTT delivery | Simulated OOB sink (Section 6). The API never returns the OTT. |
| OTT delivery latency | External delivery latency (network, mail server, SMS) is excluded. The application-side handoff cost is part of C's measured cost (Section 6). |
| Security logging | Synchronous, same behaviour in all configurations, written outside the OTT transaction |
| Statistical unit | One summary value per independent run |
| Statistical tests | Mann–Whitney U + 95% bootstrap CI (10,000 resamples, percentile method) |
| Runs per condition | 30 |
| k6 password | Fixed `newPassword`; for D, `currentPassword` equals the same value |
| Placement | k6 and server on the same machine; CPU contention documented |
| HTTP statuses | 400 malformed body, 401 authentication failure, 403 step-up failure (generic body), 429 rate limited, 500 unexpected |

Generic step-up failure body: `{"error":"Invalid or unavailable one-time token"}` (C) or a matching generic message (D).

### 3.1 Rate-limit profiles †

Rate-limit values are experimental parameters, not security standards. `express-rate-limit`, fixed window, in-memory store (resets on restart), `trust proxy` disabled.

| Profile | login | refresh | OTT issuance | sensitive operations | Used for |
|---------|-------|---------|--------------|----------------------|----------|
| `standard` | 10/min per IP | 30/min per IP | 5/min per user | 10/min per user and 30/min per IP | T18, T20, T28 only |
| `relaxed` | 10,000/min | 10,000/min | 10,000/min | functional tests and all other security tests (including T15–T17, T27) |
| `off` | disabled | disabled | disabled | disabled | all performance runs |
| `ott-expiry` | as `relaxed` | as `relaxed` | as `relaxed` | as `relaxed` | T06 (`OTT_EXPIRES_IN`=2 s) |

For every rate-limited test record the threshold, window, key, first blocked attempt and HTTP response. Test both per-IP behaviour (one user from different source addresses) and per-user behaviour (different users from one address).

### 3.2 Rate-limit middleware order and test procedure †

- Per-IP limiters (login, refresh, and the per-IP sensitive-operation limit) run **before** authentication.
- Per-user limiters (OTT issuance, sensitive operations) run **after** `authenticateAccessToken`, because their key is the authenticated user ID. Requests without a valid access JWT are therefore limited only per IP.
- Order on a sensitive endpoint: per-IP limiter, then `authenticateAccessToken`, then per-user limiter, then `requireOTT` (C) or the password check (D). Invalid-OTT and wrong-password attempts therefore count toward the per-user limit (T18, T28).
- The in-memory store starts a key's fixed window at its first hit. For T18, T20 and T28, each repetition begins with an application restart (clearing the store) and a fresh user, and the whole burst completes well within one window. Record the first-hit time and the reset time reported in the rate-limit response headers.
- The `standard` limits would throttle test setup (registration and login from one address), so only T18, T20 and T28 use `standard`. All other tests use `relaxed`.

---

## 4. Test Environment

| Item | Value |
|------|-------|
| Machine (CPU, cores, RAM, disk) | TBD |
| OS and kernel | TBD |
| Node.js version | TBD |
| MySQL version | TBD |
| Sequelize / bcrypt / jsonwebtoken versions | TBD (pinned by lockfile) |
| k6 version | TBD |
| Postman / Newman version | TBD |
| OOB sink and version | TBD |
| Git commit of frozen implementation | TBD |

Requirements:

- Commit `package-lock.json` and install with `npm ci`.
- Reset the database from the same seed before every run.
- Restart the application before every run.
- Close unrelated applications and disable sleep and power-saving during runs.
- Record CPU temperature or throttling if measurable.
- Fix the number of seeded users †: 1,000. At 250 virtual users, each VU uses its own user.

---

## 5. Attacker Capability Model

Unless stated, attackers have **no access** to the legitimate user's OOB inbox.

| ID | Attacker possesses | Notes |
|----|--------------------|-------|
| AC1 | Stolen access JWT only | |
| AC2 | Stolen refresh JWT only | |
| AC3 | Stolen access JWT + captured unused OTT | Boundary of the security model |
| AC4 | Invalid, malformed or tampered credentials | |
| AC5 | No credentials | |
| AC6 | Own valid access JWT + another user's OTT | Wrong-user |
| AC7 | Valid access JWT + OTT issued for a different purpose, endpoint or method | Wrong-context |
| AC8 | Previously used, expired or superseded OTT, or a rotated refresh JWT | Replay |
| AC9 | One valid OTT submitted in parallel | Race condition |
| AC10 | Flooding (invalid OTTs or issuance requests) | Abuse |
| AC11 | Stolen access JWT + stolen current password (D) | Boundary of D |
| AC12 | Access JWT, guessing the current password (D) | |

Result classes in this document:

- **INVARIANT**: a structural property is checked rather than classifying the test as an attacker blocked/succeeded result (for example, at most one successful OTT consumption).
- **BLOCKED**: the attacker fails to complete the operation.
- **SUCCEEDS**: the attacker completes the operation and the attempt is counted in the attack-success rate.
- **BOUNDARY**: success is expected by design (for example, a stolen access JWT works on ordinary endpoints until expiry). These cases are reported separately and **not** counted in the attack-success rate.
- **RATE-LIMITED**: HTTP 429 observed after the threshold.
- **DETECTED**: the system recognizes the event (for example, refresh-token reuse) and logs it. Reported as detections `x/n`, not as an attack metric.
- **N/A**: the test does not apply to that configuration.

---

## 6. OOB Delivery Model

The OOB sink is **test infrastructure**. It is not part of the system under test and not an application data model.

Requirements (any implementation must satisfy all):

1. No API response, log line or database column contains the raw OTT.
2. No application route reads or exposes the sink.
3. Only the test harness (legitimate-user script) reads the sink, through the sink's own interface.
4. Messages are deleted after being read.
5. Delivery runs after the OTT transaction commits and asynchronously, so the HTTP response is not delayed by delivery. The sink's own processing and the harness read are excluded from measured latency.
6. A delivery failure is logged as `OTT_DELIVERY_FAILURE`.

Implementation (decided at Stage 5; see the amendments log): `sink/oobSink.js`, a small HTTP service bound to loopback. The application hands each message over with one keep-alive HTTP POST authenticated by a **deliver key**. The harness (tests, Postman, k6) reads and drains the inbox with plain HTTP using a different **read key** that the application never holds, so the application can deliver but cannot read. This replaces the earlier Mailpit candidate: it needs no SMTP dependency and every harness can read it with simple HTTP calls.

The raw OTT exists only in application memory during issuance and in the sink. The OTT table stores only hashes.

**Handoff cost †:** the application-side handoff (building and sending the message to the sink) runs inside the application process, on the same machine as k6 and the sink, and only in Config C. Excluding delivery latency from the metric does not remove its CPU and event-loop cost, so this study **does not exclude the handoff**. It is part of C's measured cost, and C's overhead must be reported as including a simulated delivery handoff. The sink process's CPU and memory are sampled separately and reported next to the server and database. B and D have no handoff. The sink is cleared before every run.

---

## 7. OTT Lifecycle and Concurrency Rules

### 7.1 Operation registry †

The issuance request body is `{ "purpose": "...", "operation": "..." }`. The server validates the pair against a registry and derives method and endpoint from it (the client never supplies them). This extends the spec's `{purpose}` body and is needed to test endpoint and method binding separately.

| operation | purpose | method | endpoint | Notes |
|-----------|---------|--------|----------|-------|
| `change_password` | `change_password` | POST | `/api/auth/change-password` | Primary sensitive operation |
| `confirm_email` | `account_security` | POST | `/api/auth/confirm-email` | Simulated, non-destructive; mounted only when `ENABLE_SIMULATED_OPERATIONS=true` |
| `update_security_settings` | `account_security` | POST | `/api/auth/update-security-settings` | Simulated, non-destructive; mounted only when `ENABLE_SIMULATED_OPERATIONS=true` |
| `confirm_email_put` | `account_security` | PUT | `/api/auth/confirm-email` | Simulated, non-destructive; mounted only when `ENABLE_SIMULATED_OPERATIONS=true` |

The endpoint used for binding is the registered route pattern, not the raw URL. Override headers (`X-HTTP-Method-Override`, `X-Original-URL`, `X-Forwarded-Prefix`) are ignored; no method-override middleware is installed.

### 7.2 States

An OTT is exactly one of: **active** (unused, not superseded, not expired), **used** (`used_at` set), **superseded** (`superseded_at` set) or **expired** (`expires_at` passed).

### 7.3 Issuance (single active OTT per user and operation)

```text
BEGIN (READ COMMITTED)
  SELECT id FROM users WHERE id = ? FOR UPDATE        -- serializes issuance per user
  UPDATE one_time_tokens SET superseded_at = NOW(3)
    WHERE user_id = ? AND purpose = ? AND method = ? AND endpoint = ?
      AND used_at IS NULL AND superseded_at IS NULL
  INSERT one_time_tokens (..., expires_at = NOW(3) + interval)
COMMIT
deliver OTT to OOB sink (after commit)
```

### 7.4 Verification and consumption order

```text
1. Authenticate access JWT                      (401 on failure)
2. Validate request body structure              (400)
3. Hash supplied OTT; cheap read-only lookup
4. Check, in this fixed order: user -> purpose -> method -> endpoint
   -> context_hash -> expiry -> unused/not superseded
5. Hash new password (bcrypt)                   -- outside any transaction
6. BEGIN
7. SELECT id FROM users WHERE id = ? FOR UPDATE   -- same lock order as issuance
8. Conditional atomic consume:
     UPDATE one_time_tokens SET used_at = NOW(3)
     WHERE id = ? AND user_id = ? AND used_at IS NULL
       AND superseded_at IS NULL AND expires_at > NOW(3)
   affected rows = 0 -> ROLLBACK, fail
9. UPDATE users SET password_hash = ?
10. COMMIT
11. Write success security event (after commit)
```

- Failure handling: failed-attempt logging and `attempt_count` increments run outside the transaction, so a rollback cannot erase attack evidence.
- `attempt_count` increments only when the supplied hash matches a stored row but a check fails. An unmatched hash cannot increment any row and is recorded only as an `OTT_FAILURE` event with reason `INVALID_TOKEN`.
- `context_hash = SHA-256(user_id|purpose|METHOD|endpoint)` is redundant with the stored columns and is kept to test context binding. The new password is never part of the context.
- External responses are generic. Internal reasons: `USER_MISMATCH`, `PURPOSE_MISMATCH`, `METHOD_MISMATCH`, `ENDPOINT_MISMATCH`, `CONTEXT_MISMATCH`, `EXPIRED`, `ALREADY_USED`, `SUPERSEDED`, `INVALID_TOKEN`, `MISSING_OTT`, `RATE_LIMITED`.
- Because checks run in a fixed order, the logged reason is the **first failing check**. Isolation of each binding dimension is verified by service-level tests at Stage 6.
- **Lock order:** every transaction that touches both tables locks `users` first, then `one_time_tokens`. Issuance and consumption use the same order, so they cannot deadlock on these two tables.
- **What guarantees single use:** consumers for one user are serialized by the user lock, so single use rests on two mechanisms: the per-user lock and the conditional UPDATE. The conditional UPDATE must be correct on its own. The negative control in 8.2 checks that the concurrency tests can detect a violation.
- **No retries:** a lock-wait timeout (1205) or deadlock (1213) is not retried. The request returns 500, the event is logged as `DB_LOCK_ERROR`, and it is counted in the results.

### 7.5 Refresh-token rotation

- Each refresh token carries a `family_id`.
- Normal use: verify the JWT, find the stored hash, confirm it is active, revoke it, issue a new one in the same family, and record `replaced_by`.
- Reuse of a revoked token: revoke the whole family and log `REFRESH_REPLAY`.

### 7.6 Logout and access-token revocation

- Table `revoked_tokens(id, jti, user_id, expires_at, revoked_at)`.
- The access-token middleware checks `jti` against it on every request in every configuration.
- Logout revokes the presented access `jti` and, in B, C and D, the refresh family.
- Records are purged after `expires_at`. The purge job runs outside measurement windows.

### 7.7 Config D step-up

`change-password` requires `currentPassword`. The server performs a bcrypt compare before the update. Failed attempts are rate-limited per user and logged as `PASSWORD_REENTRY_FAILURE`.

---

## 8. Security Test Cases

Predicted outcomes are **hypotheses to be verified**, not results. Repetitions per test:

- Deterministic tests (all except T15–T17, T27): 30 repetitions with fresh users.
- Race-condition tests (T15–T17, T27): 100 repetitions each †. Zero violations in n runs does **not** prove impossibility; the 95% upper bound on the per-run violation rate is approximately 3/n (about 3% for n = 100).

| ID | Capability | Procedure | Expected under C (internal reason) |
|----|------------|-----------|-----------------------------------|
| T01 | AC1 | `GET /api/profile` with valid stolen access JWT | 200 (boundary) |
| T02 | AC1 | `POST /api/auth/change-password` with stolen access JWT, no OTT or password | 403 (`MISSING_OTT`) |
| T03 | AC2 | Three recorded sub-results, defined in 8.1 | a: pair obtained (boundary); b: replay detected; c: sensitive operation blocked in C and D |
| T04 | AC8 | Rotate a refresh JWT, then replay the old one | 401, `REFRESH_REPLAY`, family revoked |
| T05 | AC8 | Use an OTT successfully, then resubmit it | 403 (`ALREADY_USED`) |
| T06 | AC8 | Profile `ott-expiry`; wait 3 s; submit | 403 (`EXPIRED`) |
| T07 | AC4 | Random 32 bytes, a bit-flipped valid OTT, empty value | 403 (`INVALID_TOKEN`) |
| T08 | AC5 | Valid OTT, no `Authorization` header | 401 |
| T09 | Legit JWT | Valid access JWT, `ott` field omitted | 403 (`MISSING_OTT`) |
| T10 | AC6 | JWT of user B with the OTT of user A | 403 (`USER_MISMATCH`) |
| T11 | AC7 | OTT for `confirm_email` presented at `change-password` | 403 (`PURPOSE_MISMATCH`, first failing check) |
| T12 | AC7 | OTT for `confirm_email` presented at `update-security-settings` (same purpose and method) | 403 (`ENDPOINT_MISMATCH`) |
| T13 | AC7 | OTT for `POST /confirm-email` presented as `PUT /confirm-email` (same purpose and endpoint) | 403 (`METHOD_MISMATCH`) |
| T14 | AC7 | Context-spoofing attempts: override headers; path variants (trailing slash, case). Variants resolving to the same registered route are the same operation, not a bypass. | No bypass; context derived from the actual request |
| T15 | AC9 | 1 valid OTT, 2 parallel requests, profile `relaxed` | INVARIANT: successful consumptions ≤ 1 |
| T16 | AC9 | 1 valid OTT, 20 parallel requests | INVARIANT: successful consumptions ≤ 1 |
| T17 | AC9 | 1 valid OTT, 50 parallel requests | INVARIANT: successful consumptions ≤ 1 |
| T18 | AC10 | 100 invalid-OTT attempts per user per minute under `standard`; per-IP and per-user variants | 403 until threshold, then 429 |
| T19 | AC8 | Issue OTT-1, then OTT-2 for the same user and operation; submit OTT-1, then OTT-2 | OTT-1: 403 (`SUPERSEDED`); OTT-2: 200 |
| T20 | AC10 | 20 `/api/ott/request` calls in one minute under `standard` | At most 5 requests are accepted within the fixed window; subsequent requests exceeding the limit return 429 |
| T21 | AC4 | Modify `sub`, `exp`, `type`, `jti` without re-signing; re-sign with a wrong secret | 401 |
| T22 | AC4 | `alg:none`, other HS/RS algorithms, key-confusion attempt | 401 |
| T23 | AC4 | Expired `exp`; future `nbf`; wrong `iss`; wrong `aud`; refresh JWT used as access and vice versa | 401 |
| T24 | AC1 after logout | Log out; reuse the access JWT; reuse the refresh JWT (B, C, D) | 401 on both |
| T25 | Legit | Out-of-order workflow, defined per configuration in 8.1 | Step 1: 403; final step: 200 (control) |
| T26 | AC3 | JWT + captured unused OTT submitted before the victim | 200 (boundary; documented limitation) |
| T27 | AC9 | 20 parallel `/api/ott/request` for the same user and operation, profile `relaxed`; assertions in 8.1 | INVARIANT: exactly one active OTT after all issuances finish; superseded rows distinguishable from used rows |
| T28 | AC12 (D) | 100 wrong `currentPassword` attempts under `standard` | 403 until threshold, then 429 |
| T29 | AC11 (D) | JWT + correct current password | 200 (boundary) |

For every attack test record: total attempts, successful unauthorized attempts, rejected attempts, attack-success rate (excluding BOUNDARY cases), HTTP status, rate-limit state, relevant latency, and the internal audit reason. For T15–T17 and T27 also record: concurrent requests sent, successful consumptions, duplicate successes, database errors (including lock-wait and deadlock errors, which are never retried), and the count of `SENSITIVE_OPERATION_SUCCESS` events.

**Functional controls (must pass before security tests):** registration, login, profile, refresh rotation (B/C/D), logout, and a complete legitimate sensitive operation in each configuration.

### 8.1 Detailed test definitions

**T03: stolen refresh JWT (three separately recorded sub-results)**

- **T03a:** the attacker presents the stolen refresh JWT before the legitimate holder does, and the server issues a new pair. Class: BOUNDARY. This is a property of rotation (the first valid presentation wins). It is not counted in the attack-success rate.
- **T03b:** the legitimate holder then presents the original refresh JWT. Expected: `REFRESH_REPLAY`, the whole family is revoked, and the attacker's new refresh JWT now fails. Class: DETECTED. Report detections as `x/n`.
- **T03c:** the attacker uses the access JWT obtained in T03a to attempt `change-password` with no second factor. This is counted in the attack-success rate exactly like T02 and tagged `derived-from-T03`. Expected: B SUCCEEDS; C and D BLOCKED. Family revocation does not revoke an already-issued access JWT, so record whether the access JWT still works on ordinary endpoints until expiry.
- The reverse order (the legitimate holder refreshes first, then the attacker presents the old token) is covered by T04.

**T25: out-of-order workflow (fresh user, profile `relaxed`)**

- **Config C:**
  1. Call `change-password` with a valid access JWT and `newPassword` but no `ott`. Expected: 403 (`MISSING_OTT`), and the password is unchanged.
  2. Call `/api/ott/request` for `change_password`, then read the OOB sink.
  3. Call `change-password` with the OTT. Expected: 200 and exactly one `SENSITIVE_OPERATION_SUCCESS` event.
- **Config D:**
  1. Call `change-password` with `newPassword` but no `currentPassword`. Expected: 403.
  2. Repeat with the correct `currentPassword`. Expected: 200.
- **Configs A and B:** N/A (no step-up workflow).
- **Control check (C and D):** after the final step, login with the new password returns 200 and login with the old password returns 401. The final 200 is a legitimate-path control, not an attack result.

**T27: concurrent OTT issuance (C only, profile `relaxed`, fresh user)**

1. Send 20 parallel `/api/ott/request` calls for the same user and operation.
2. Wait until all 20 HTTP responses have returned, so no issuance transaction is in flight. Then query using a fresh connection.
3. Let *k* be the number of 200 responses. Assert, using a state-classification query over rows for (user, purpose, method, endpoint):
   - active rows (unused, not superseded, not expired) = **exactly 1**
   - superseded rows (`superseded_at` set, `used_at` null) = *k* − 1
   - used rows = 0, expired rows = 0
   - total rows = *k*
   - no row has both `used_at` and `superseded_at` set (invariant: the supersede UPDATE only touches rows with `used_at IS NULL`)
4. Record every non-200 response and any lock-wait or deadlock errors.
5. Hash each OTT the harness received from the OOB sink and match it to its row. Submit all received OTTs sequentially: exactly one succeeds, and it is the active row's OTT. The rest fail with `SUPERSEDED`.

### 8.2 Negative control for the concurrency tests †

A test that cannot fail proves nothing, so the harness must show that it can detect a violation.

- A test-only flag `UNSAFE_NON_ATOMIC_CONSUME=true` makes consumption perform a plain SELECT-and-check followed by an unconditional UPDATE, without the user lock and without the conditional guard. `UNSAFE_DELAY_MS` (default 0) inserts a delay between the check and the update.
- The flags are rejected outside the test profile, are part of the frozen commit, are disabled by default, and are never enabled in performance runs.
- Procedure: with the flag enabled, run T16 and T17 with the same repetition count as the real tests (100 each), storing results in `results/security/negative-control/`.
- Expected: at least one repetition shows more than one successful consumption. If none does, the harness lacks power. Raise `UNSAFE_DELAY_MS` or the parallelism until a violation is observed, record the settings used, and only then interpret the T15–T17 results of the real implementation.
- These results are not part of any attack-success rate.

---

## 9. Configuration Applicability Matrix (predicted outcomes)

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
| T15 | N/A | N/A | INVARIANT (≤1 successful consumption) | N/A |
| T16 | N/A | N/A | INVARIANT (≤1 successful consumption) | N/A |
| T17 | N/A | N/A | INVARIANT (≤1 successful consumption) | N/A |
| T18 | N/A | N/A | RATE-LIMITED | N/A |
| T19 | N/A | N/A | BLOCKED | N/A |
| T20 | N/A | N/A | RATE-LIMITED | N/A |
| T21 | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| T22 | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| T23 | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| T24 | BLOCKED | BLOCKED | BLOCKED | BLOCKED |
| T25 | N/A | N/A | step 1 BLOCKED; final step OK (control) | step 1 BLOCKED; final step OK (control) |
| T26 | N/A | N/A | BOUNDARY | N/A |
| T27 | N/A | N/A | INVARIANT (exactly 1 active) | N/A |
| T28 | N/A | N/A | N/A | RATE-LIMITED |
| T29 | N/A | N/A | N/A | BOUNDARY |

Notes:

- `N/A` means the test depends on a mechanism that does not exist in that configuration.
- A password is reusable by design, so replay and single-use tests (T05, T15–T17, T19) have no D equivalent.
- The honest C vs D security difference is narrow: C adds single-use, replay and context binding, while D adds no extra channel or state. Report it as measured.
- T24 under A covers the access JWT only.

---

## 10. Performance Benchmarks

| ID | Endpoint(s) | Configurations | Purpose |
|----|-------------|----------------|---------|
| P1 | `GET /api/profile` | A, B | Normal authenticated API. C and D add nothing here. |
| P2a | `POST /api/auth/change-password` | B, C, D | Actual sensitive operation (bcrypt hash identical in all). |
| P2b | `POST /api/auth/confirm-email` (simulated, bcrypt-free †) | B, C, D | Isolates the OTT layer from bcrypt cost. |
| P3 | `POST /api/ott/request` | C | OTT issuance alone. |
| P4 | Derived from P2a/P2b tags | B, C, D | Step-up workflow: C = issuance + operation; D = operation (includes the password compare); B = operation. |

Do not include external email or SMS latency.

### 10.1 Measurement definition (P2a, P2b, P3, P4)

Every k6 request is tagged with `bench`, `config` and `step` (`ott_issue`, `harness` or `op`).

Iteration structure (same VU loop in all configurations †):

- **C:** (1) `POST /api/ott/request`, tagged `ott_issue`; (2) read the OTT from the OOB sink (separate host and port), tagged `harness`; (3) the operation, tagged `op`.
- **B and D:** (1) skipped; (2) an equivalent sink read that returns empty, tagged `harness`; (3) the operation, tagged `op` (for D including `currentPassword`).

Rules:

- Only `ott_issue` and `op` requests are server measurements. `harness` requests are excluded from latency, throughput and error rate. Harness duration and the idle gap between requests are never added to any metric.
- **P2 metrics** come from `op` requests only. Per run: median, P95, P99 of `http_req_duration`; throughput = completed `op` requests per second of the measurement window; error rate = `op` requests with an unexpected status ÷ all `op` requests.
- **P3 metrics** come from `ott_issue` requests only, computed the same way. In P3 each iteration is an `ott_issue` request followed by a `harness` read that drains and deletes the message (no `op` request), so the sink does not accumulate messages during the run.
- The harness polls the sink every 20 ms for up to 2 s †. If no OTT arrives, the iteration is a `harness_failure`: the `op` request is skipped and is not counted as an operation error. Record the count. A run with more than 1% `harness_failure` iterations is marked invalid and repeated; both runs are kept in the raw data, and the invalid one is flagged.
- The 5-minute OTT lifetime is far longer than any iteration, so expiry cannot occur during performance runs.
- **Closed-loop caveat:** in C, each VU spends time on issuance and the sink read, so at equal VU count C sends fewer simultaneous `op` requests than B or D. The equivalent sink handling in B and D is included only to keep the VU workflow structurally similar; it does not make request concurrency identical. Record achieved `op` throughput for every run and interpret latency differences alongside it. Do not describe a latency difference as pure OTT overhead without acknowledging the closed-loop request-mix difference.

### 10.2 P4 derivation (step-up workflow)

- An iteration is **complete** if every measured request in it returned the expected status (C: `ott_issue` and `op`; B and D: `op`).
- Workflow latency of iteration *i*: C: `w_i = d_issue_i + d_op_i`; B and D: `w_i = d_op_i` (D's password compare is inside `d_op`). Harness time and idle gaps are excluded.
- Per-run summaries (median, P95, P99) are computed over the `w_i` of complete iterations **within that run**. Never add the per-run percentiles of `ott_issue` and `op`, because percentiles are not additive.
- Workflow throughput = complete iterations per second. Workflow error rate = incomplete iterations (excluding `harness_failure`) ÷ all attempted iterations.
- The 30 per-run values per configuration are then compared exactly as in Section 12.
- P4 shares runs with P2 for the same configuration, so the P2 and P4 test results are correlated. Report them as two views of the same runs, and treat P4 as a secondary comparison under the Holm correction.

---

## 11. Load Levels

1, 10, 50, 100 and 250 concurrent virtual users.

If 250 cannot be sustained meaningfully (defined here as server CPU saturated for the whole measurement window or error rate above 1% in the warm-up), reduce the top level and document the actual configuration and the reason.

Conditions: P1 = 2 configs × 5 levels = 10; P2a = 15; P2b = 15; P3 = 5. Total = 45 conditions × 30 runs = **1,350 runs**. At 10 s warm-up + 30 s measurement + ~5 s reset per run, that is about **17 hours** of pure run time †.

---

## 12. Run Structure and Statistical Analysis

Per run:

1. Reset the database from the seed and clear the OOB sink.
2. Start the application with the frozen configuration and rate-limit profile `off`.
3. Warm up (10 s †, excluded).
4. Measure (30 s †).
5. Save raw output and metadata. Never overwrite.

Condition order is randomized in blocks so that configurations are interleaved and time-based drift (thermal, cache, background load) is not confounded with configuration.

Per-run summaries (the unit of analysis): mean, median, P95, P99 and standard deviation of latency, throughput (requests/s), error rate, and CPU and memory of the server process, MySQL and the OOB sink process (sampled at 1 Hz; record mean and peak).

Analysis per benchmark and load level:

- Compare the 30 per-run summaries between configurations with a two-sided Mann–Whitney U test (α = 0.05).
- Report the median difference with a 95% bootstrap CI.
- Compute overhead as `(C − B) / B × 100` on per-run medians, with a bootstrap CI.
- B vs C is the primary hypothesis test. All other comparisons are secondary; apply Holm correction across them.
- Do **not** run tests on individual requests.

Security results are reported as counts (`x/n`), not as percentages alone.

---

## 13. Metrics

- **Latency:** mean, median, P95, P99, standard deviation.
- **Throughput and error rate:** per run.
- **Resources:** CPU and memory (server process, database and OOB sink).
- **Overhead:** relative to B (percentage).
- **Security:** attempts, successes, rejections, attack-success rate (excluding BOUNDARY), status codes, rate-limit state, successful consumptions and duplicates, database errors, and internal reasons.
- **Complexity (H5):** extra requests per sensitive operation, additional tables and state, lines of code in the step-up path, and number of per-request database queries.

---

## 14. Data Collection

```text
results/
├── raw/
│   ├── config-A/
│   ├── config-B/
│   ├── config-C/
│   └── config-D/
├── processed/
├── security/
└── figures/
```

- Raw k6 output is stored as JSON or CSV, one file per run, and is never overwritten.
- File name pattern: `<benchmark>_vu<N>_run<NN>_<timestamp>.json`.
- Each run has a `metadata.json` with: date, time, configuration, test ID, rate-limit profile, concurrency, duration, warm-up, Node.js version, DB version, k6 version, machine specification, git commit, experiment version.
- Screenshots are not data.

---

## 15. Reproducibility Requirements

1. Implement and commit the system.
2. Run functional and security tests (T01–T29).
3. Tag the commit `experiment-v1` and record the hash in Section 16.
4. Run performance tests.
5. No change to authentication or database logic after the freeze. Any such change creates experiment version 2, and v1 and v2 results are never mixed.
6. Provide `.env.example`, seed scripts, schema migrations, `README.md` and the documents listed in the project spec.
7. The test-only `UNSAFE_NON_ATOMIC_CONSUME` and `UNSAFE_DELAY_MS` flags (8.2) are part of the frozen commit, disabled by default, rejected outside the test profile, and never enabled in performance runs.

---

## 16. Freeze Record

| Field | Value |
|-------|-------|
| Author sign-off | Jiken, 2026-10-05 (design v1.3, all † defaults accepted) |
| Freeze date | Design: 2026-10-05. Implementation: TBD |
| Frozen commit hash | TBD |
| Experiment version | v1 |

### Items to complete before sign-off

Environment records (necessarily `TBD` until setup; they are not research variables):

- machine specification, OS and kernel
- Node.js, MySQL, Sequelize, bcrypt, jsonwebtoken, k6 and Postman/Newman versions
- OOB sink implementation and version (decided at Stage 5, recorded in the amendments log)
- frozen commit hash

Design decisions marked **†** (all accepted by the author on 2026-10-05):

- rate-limit profile values (3.1)
- new-password length rule, seeded user count (3.x, 4)
- operation registry and the extended issuance body `{purpose, operation}` (7.1)
- Mailpit as the candidate OOB sink (6)
- 100 repetitions for race-condition tests (8)
- 10 s warm-up, 30 s measurement, and the resulting ~17 h estimate (11, 12)
- bcrypt-free simulated route for P2b (10)
- identical VU loop with an equivalent sink read in B and D, and the 20 ms / 2 s sink polling rule (10.1)
- consumption taking the `users` lock first, the 5 s lock-wait timeout, and no retries on 1205/1213 (3, 7.4)
- the negative-control flags and procedure (8.2)
- counting the OOB delivery handoff as part of C's cost (6)
- restricting profile `standard` to T18, T20 and T28, with an app restart and a fresh user per repetition (3.1, 3.2)

### Amendments log

| Date | Version | Change | Reason |
|------|---------|--------|--------|
| 2026-10-02 | 1.0-draft | Initial draft: configurations A–D, OOB delivery, issuance row-lock, per-run statistics, applicability matrix | Resolve review findings before Stage 1 |
| 2026-10-03 | 1.1-draft | Defined P2/P3 measurement and exclusion of the OOB harness (10.1); defined P4 per-run construction (10.2); split T03 into sub-results a/b/c and added DETECTED class; specified T25 per configuration; specified T27 assertions (8.1); added freeze checklist | Review items 1–6 |
| 2026-10-03 | 1.2-draft | Reclassified T15–T17 and T27 as INVARIANT checks; changed T20 from an exact ordering prediction to a fixed-window upper-bound expectation; clarified the closed-loop performance interpretation | Prevent predicted labels from being mistaken for attack outcomes or timing guarantees |
| 2026-10-03 | 1.3-draft | Consumption now locks `users` first (same order as issuance) with no retries on lock errors (7.4); added negative control for concurrency tests (8.2); OOB handoff cost counted in C and sink resources sampled (6, 12, 13); P3 drains the sink (10.1); rate-limit middleware order and per-repetition restart procedure (3.2); `standard` profile limited to T18, T20, T28 | Review findings 1–3 on v1.2 |
| 2026-10-05 | 1.3 | Author accepted all † defaults; design signed off. No change to research variables. | Sign-off before Stage 1 |
| 2026-10-08 | 1.3 (clarification) | Simulated routes (7.1) are enabled by the explicit flag `ENABLE_SIMULATED_OPERATIONS=true` instead of `APP_PROFILE=test`. No change to research variables, routes or behaviour. | Benchmark P2b must run outside the test profile (which skips the thread-pool check and allows the UNSAFE flags), so tying the routes to that profile would have made P2b impossible |
| 2026-10-08 | 1.3 (clarification) | OOB sink implementation chosen: custom loopback HTTP sink with separate deliver and read keys, instead of the Mailpit candidate (Section 6). Issuance route `/api/ott/request` is also protected by the per-IP sensitive limiter before authentication (3.2). No change to research variables. | Section 6 left the choice to Stage 5; the custom sink avoids an SMTP dependency and is readable by tests, Postman and k6 with plain HTTP. The per-IP limiter on issuance prevents unauthenticated floods from writing audit rows |
| 2026-10-09 | 1.3 (clarification) | Stage 7 implementation of Sections 10-12: (1) run order is a randomized complete block design: one block per repetition containing every condition once in a seeded random order; (2) the application is restarted and the database re-seeded (1,000 users) before every run, access tokens for the first N users are minted by the token service instead of via login (login is not benchmarked); (3) an iteration belongs to the phase it started in (warm-up or measurement); (4) a Holm-adjusted p over the primary family is reported in addition to the unadjusted primary p required by Section 12; (5) CPU/memory of the load generator is sampled alongside app, MySQL and sink. No change to research variables. | Section 12 left these mechanics open |
| 2026-10-12 | 1.3 (clarification) | After the first full security run (commit 5dff733, 53 cells, 0 errors, all matching predictions): (1) the aggregation of attack-success counts for the concurrency tests T15-T17 counted the single permitted consumption as a success, so the report said 100/200 instead of 0/200; the aggregation was corrected and the report rebuilt from the unchanged raw data (`harness/security/rebuild.js`), and T27 now records its permitted consumptions; (2) the benchmark orchestrator passes the environment variables Windows needs to child processes, and the resource sampler reports `unsupported` on Windows instead of producing no data silently. No change to research variables, to raw data or to the system under test. | Reporting correction; Windows support for the orchestrator |

---

## 17. Threats to Validity

- **Internal:** same-machine load generator and server contend for CPU; order and thermal effects; database cache warmth; garbage-collection pauses; background processes. Mitigated by randomized interleaving, reset-per-run and documented contention.
- **Internal (load definition):** the performance loop is closed-loop with a fixed VU count, and C's iteration includes an extra issuance request and a sink read. At equal VU count the server therefore sees a different request mix and `op` concurrency in C than in B and D (Section 10.1). Mitigated by the equivalent sink read in B and D and by reporting achieved throughput per run. C also performs the delivery handoff inside the application process, and the sink process consumes CPU on the same machine (Section 6). That cost is counted in C, and the sink's CPU and memory are reported separately.
- **Construct:** attack success depends on the defined attacker capabilities. The OOB sink is a simulation and does not model real delivery channels, phishing, device compromise or real mailbox security. The handoff is a loopback HTTP POST, which is likely cheaper than a real mail or SMS gateway call, so C's measured handoff cost is a lower bound. Attacks are implemented by the same author who built the defence.
- **External:** one prototype, one machine, local network (no WAN latency), one Node.js/MySQL stack, synthetic dataset, and one sensitive operation family. Results do not generalize to production systems.
- **Statistical:** 30 runs per condition detect only reasonably large effects; heavy-tailed latency distributions are handled with rank-based tests; race conditions cannot be proven absent by sampling (Section 8).
- **Conclusion:** the study evaluates a defined mechanism under defined conditions, not general superiority.

---

## 18. Expected Limitations

- A stolen access token still works on ordinary endpoints until expiry or revocation (T01).
- An attacker who holds both the access JWT and the OOB-delivered OTT can complete the operation (T26). In D, an attacker holding the JWT and the password can (T29).
- The OTT layer does not replace HTTPS, key management, authorization, secure password storage, rate limiting, secure client storage, sender-constrained tokens or general API security controls.
- Logout and revocation of JWTs require server-side state; the design is not state-free.
- The five-minute OTT lifetime, 15-minute access lifetime, 7-day refresh lifetime, rate-limit values, thread-pool size and pool size are experimental parameters, not recommendations.
