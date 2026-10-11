'use strict';
// T01-T29 (EXPERIMENTS.md section 8 / 8.1). Each test returns { outcome, observed, counted?, latencyMs? }.
// `counted: { attempts, successes }` feeds the attack-success rate; BOUNDARY cases are NOT counted.
// "Success" always means: the attacker completed the operation (HTTP 200 AND the password actually changed
// where the operation changes it).
const crypto = require('crypto');
const { OPERATIONS } = require('../../src/operations');
const { NEW_PW } = require('./env');

const b64u = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const hmac = (secret, data, algo = 'sha256') => crypto.createHmac(algo, secret).update(data).digest('base64url');
const nowS = () => Math.floor(Date.now() / 1000);
const randomOtt = () => crypto.randomBytes(32).toString('base64url');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const SECOND_PW = 'harness-second-password-2';

const res = (outcome, observed = {}, counted = null, latencyMs = null) => ({ outcome, observed, counted, latencyMs });
const claims = (userId, over = {}) => ({ type: 'access', sub: String(userId), jti: crypto.randomUUID(), iss: 'ott-study-auth',
  aud: 'ott-study-api', iat: nowS(), exp: nowS() + 900, ...over });
const sign = (payload, secret, header = { alg: 'HS256', typ: 'JWT' }) => {
  const h = b64u(header); const p = b64u(payload);
  return `${h}.${p}.${hmac(secret, `${h}.${p}`)}`;
};
const statusSummary = (statuses) => statuses.reduce((m, s) => { m[s] = (m[s] || 0) + 1; return m; }, {});
const changed = async (ctx, userId, before) => (await ctx.hash(userId)) !== before;

/** Attacker attempts `attempt()` (returns a response); success = 200 and (optionally) password changed. */
async function attack(ctx, user, attempt, { expectsPasswordChange = true } = {}) {
  const before = await ctx.hash(user.id);
  const r = await attempt();
  const ok = r.status === 200 && (!expectsPasswordChange || await changed(ctx, user.id, before));
  return { r, ok };
}
const blockedOrSucceeds = (ok) => (ok ? 'SUCCEEDS' : 'BLOCKED');

const T = {};

// ---------------------------------------------------------------- T01-T04
T.T01 = { name: 'Stolen access JWT on an ordinary endpoint', cap: 'AC1', run: async (ctx) => {
  const u = await ctx.user();
  const r = await ctx.req('GET', '/api/profile', { token: u.access });
  return res(r.status === 200 ? 'BOUNDARY' : 'BLOCKED', { status: r.status }, null, r.ms);
} };

T.T02 = { name: 'Stolen access JWT on the sensitive endpoint, no second factor', cap: 'AC1', run: async (ctx) => {
  const u = await ctx.user();
  const { r, ok } = await attack(ctx, u, () => ctx.cp(u.access));
  const reasons = {};
  if (ctx.mode === 'C') reasons.otpFailureMissing = await ctx.count('OTT_FAILURE', 'MISSING_OTT', u.id);
  if (ctx.mode === 'D') reasons.reentryMissing = await ctx.count('PASSWORD_REENTRY_FAILURE', 'MISSING_PASSWORD', u.id);
  return res(blockedOrSucceeds(ok), { status: r.status, ...reasons }, { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T03 = { name: 'Stolen refresh JWT (a: attacker rotates, b: replay detected, c: sensitive op)', cap: 'AC2', run: async (ctx) => {
  const victim = await ctx.user();
  const replaysBefore = await ctx.count('REFRESH_REPLAY', null, victim.id);
  const a = await ctx.req('POST', '/api/auth/refresh', { body: { refreshToken: victim.refresh } });
  const attacker = a.status === 200 ? a.json() : null;
  const b1 = await ctx.req('POST', '/api/auth/refresh', { body: { refreshToken: victim.refresh } });
  const replaysAfter = await ctx.count('REFRESH_REPLAY', null, victim.id);
  let attackerRefreshDead = true;
  if (attacker) attackerRefreshDead = (await ctx.req('POST', '/api/auth/refresh', { body: { refreshToken: attacker.refreshToken } })).status === 401;
  const detected = b1.status === 401 && replaysAfter === replaysBefore + 1 && attackerRefreshDead;
  let c = 'N/A'; let accessStillWorks = null; let counted = null;
  if (attacker) {
    const { ok } = await attack(ctx, victim, () => ctx.cp(attacker.accessToken));
    c = blockedOrSucceeds(ok);
    counted = { attempts: 1, successes: ok ? 1 : 0 };
    accessStillWorks = (await ctx.req('GET', '/api/profile', { token: attacker.accessToken })).status === 200;
  }
  return res({ a: a.status === 200 ? 'BOUNDARY' : 'BLOCKED', b: detected ? 'DETECTED' : 'NOT_DETECTED', c },
    { statusA: a.status, statusB: b1.status, replayEventsDelta: replaysAfter - replaysBefore, attackerRefreshDead, accessStillWorks }, counted, a.ms);
} };

T.T04 = { name: 'Replay of a rotated refresh JWT', cap: 'AC8', run: async (ctx) => {
  const u = await ctx.user();
  const rot = await ctx.req('POST', '/api/auth/refresh', { body: { refreshToken: u.refresh } });
  if (rot.status !== 200) return res('PRECONDITION_FAILED', { rotateStatus: rot.status });
  const before = await ctx.count('REFRESH_REPLAY', null, u.id);
  const replay = await ctx.req('POST', '/api/auth/refresh', { body: { refreshToken: u.refresh } });
  const familyDead = (await ctx.req('POST', '/api/auth/refresh', { body: { refreshToken: rot.json().refreshToken } })).status === 401;
  const ok = replay.status === 200;
  return res(ok || !familyDead ? 'SUCCEEDS' : 'BLOCKED',
    { replayStatus: replay.status, familyDead, replayEvents: (await ctx.count('REFRESH_REPLAY', null, u.id)) - before },
    { attempts: 1, successes: ok ? 1 : 0 }, replay.ms);
} };

// ---------------------------------------------------------------- T05-T14 (Config C: OTT)
T.T05 = { name: 'Replay of a used OTT', cap: 'AC8', run: async (ctx) => {
  const u = await ctx.user();
  const ott = await ctx.ott(u, 'change_password');
  const first = await ctx.cp(u.access, { ott });
  if (first.status !== 200) return res('PRECONDITION_FAILED', { firstStatus: first.status });
  const { r, ok } = await attack(ctx, u, () => ctx.cp(u.access, { ott, newPassword: SECOND_PW }));
  const row = (await ctx.sequelize.query('SELECT attempt_count FROM one_time_tokens WHERE user_id = :id', { replacements: { id: u.id }, type: 'SELECT' }))[0];
  return res(blockedOrSucceeds(ok), { status: r.status, alreadyUsedEvents: await ctx.count('OTT_FAILURE', 'ALREADY_USED', u.id), attemptCount: Number(row.attempt_count) },
    { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T06 = { name: 'Expired OTT (2 s lifetime, submitted after 3 s)', cap: 'AC8', variant: 'ott-expiry', parallel: true, run: async (ctx) => {
  const u = await ctx.user();
  const ott = await ctx.ott(u, 'change_password');
  await sleep(3000);
  const { r, ok } = await attack(ctx, u, () => ctx.cp(u.access, { ott }));
  return res(blockedOrSucceeds(ok), { status: r.status, expiredEvents: await ctx.count('OTT_FAILURE', 'EXPIRED', u.id) },
    { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T07 = { name: 'Random, bit-flipped and empty OTTs', cap: 'AC4', run: async (ctx) => {
  const u = await ctx.user();
  const real = await ctx.ott(u, 'change_password');
  const flipped = real.slice(0, -1) + (real.endsWith('A') ? 'B' : 'A');
  const statuses = []; let successes = 0; let ms = null;
  for (const ott of [randomOtt(), flipped, '']) {
    const { r, ok } = await attack(ctx, u, () => ctx.cp(u.access, { ott }));
    statuses.push(r.status); if (ok) successes += 1; if (ms === null) ms = r.ms;
  }
  return res(successes ? 'SUCCEEDS' : 'BLOCKED', { statuses, invalidEvents: await ctx.count('OTT_FAILURE', 'INVALID_TOKEN', u.id) },
    { attempts: 3, successes }, ms);
} };

T.T08 = { name: 'Valid OTT without an access JWT', cap: 'AC5', run: async (ctx) => {
  const u = await ctx.user();
  const ott = await ctx.ott(u, 'change_password');
  const { r, ok } = await attack(ctx, u, () => ctx.req('POST', '/api/auth/change-password', { body: { newPassword: NEW_PW, ott } }));
  const stillUsable = (await ctx.cp(u.access, { ott })).status === 200;
  return res(blockedOrSucceeds(ok), { status: r.status, ottStillUsable: stillUsable }, { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T09 = { name: 'Valid access JWT, second factor omitted', cap: 'Legit JWT', run: async (ctx) => {
  const u = await ctx.user();
  const { r, ok } = await attack(ctx, u, () => ctx.cp(u.access)); // no `ott` (C) / no `currentPassword` (D)
  return res(blockedOrSucceeds(ok), { status: r.status }, { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T10 = { name: "User B's JWT with user A's OTT", cap: 'AC6', run: async (ctx) => {
  const a = await ctx.user(); const b = await ctx.user();
  const ottA = await ctx.ott(a, 'change_password');
  const { r, ok } = await attack(ctx, b, () => ctx.cp(b.access, { ott: ottA }));
  return res(blockedOrSucceeds(ok), { status: r.status, userMismatchEvents: await ctx.count('OTT_FAILURE', 'USER_MISMATCH', b.id) },
    { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T11 = { name: 'OTT for confirm_email presented at change-password (purpose)', cap: 'AC7', run: async (ctx) => {
  const u = await ctx.user();
  const ott = await ctx.ott(u, 'confirm_email');
  const { r, ok } = await attack(ctx, u, () => ctx.cp(u.access, { ott }));
  return res(blockedOrSucceeds(ok), { status: r.status, purposeEvents: await ctx.count('OTT_FAILURE', 'PURPOSE_MISMATCH', u.id) },
    { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T12 = { name: 'OTT for confirm_email presented at update-security-settings (endpoint)', cap: 'AC7', run: async (ctx) => {
  const u = await ctx.user();
  const ott = await ctx.ott(u, 'confirm_email');
  const r = await ctx.req('POST', '/api/auth/update-security-settings', { body: { ott }, token: u.access });
  const ok = r.status === 200;
  return res(blockedOrSucceeds(ok), { status: r.status, endpointEvents: await ctx.count('OTT_FAILURE', 'ENDPOINT_MISMATCH', u.id) },
    { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T13 = { name: 'OTT for POST confirm-email presented as PUT (method)', cap: 'AC7', run: async (ctx) => {
  const u = await ctx.user();
  const ott = await ctx.ott(u, 'confirm_email');
  const r = await ctx.req('PUT', '/api/auth/confirm-email', { body: { ott }, token: u.access });
  const ok = r.status === 200;
  return res(blockedOrSucceeds(ok), { status: r.status, methodEvents: await ctx.count('OTT_FAILURE', 'METHOD_MISMATCH', u.id) },
    { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T14 = { name: 'Context-spoofing headers; path variants of the same route', cap: 'AC7', run: async (ctx) => {
  const u = await ctx.user();
  const ott = await ctx.ott(u, 'confirm_email');
  const spoof = { 'X-HTTP-Method-Override': 'POST', 'X-Method-Override': 'POST', 'X-Original-URL': '/api/auth/confirm-email',
    'X-Rewrite-URL': '/api/auth/confirm-email', 'X-Forwarded-Prefix': '/api/auth', 'X-Forwarded-Path': '/api/auth/confirm-email' };
  const i = await ctx.req('PUT', '/api/auth/confirm-email', { body: { ott }, token: u.access, headers: spoof });
  const ii = await ctx.req('POST', '/api/auth/update-security-settings', { body: { ott }, token: u.access, headers: spoof });
  const successes = [i, ii].filter((r) => r.status === 200).length;
  // Not an attack: the same registered route reached through a trailing slash / different case is the SAME operation.
  const variant = await ctx.req('POST', '/api/auth/confirm-email/', { body: { ott }, token: u.access });
  return res(successes ? 'SUCCEEDS' : 'BLOCKED', { methodOverrideStatus: i.status, endpointOverrideStatus: ii.status, sameRouteVariantStatus: variant.status },
    { attempts: 2, successes }, i.ms);
} };

// ---------------------------------------------------------------- T15-T17 (races on consumption)
function raceConsume(n) {
  return async (ctx) => {
    const u = await ctx.user();
    const ott = await ctx.ott(u, 'confirm_email');
    const t0 = process.hrtime.bigint();
    const rs = await Promise.all(Array.from({ length: n }, () => ctx.req('POST', '/api/auth/confirm-email', { body: { ott }, token: u.access })));
    const statuses = rs.map((r) => r.status);
    const successes = statuses.filter((s) => s === 200).length;
    const serverErrors = statuses.filter((s) => s >= 500).length;
    const lockEvents = await ctx.count('DB_LOCK_ERROR', null, u.id);
    const successEvents = await ctx.count('SENSITIVE_OPERATION_SUCCESS', null, u.id);
    return res(successes <= 1 && successEvents <= 1 ? 'INVARIANT_HELD' : 'INVARIANT_VIOLATED',
      { concurrentSent: n, successes, duplicates: Math.max(0, successes - 1), zeroSuccess: successes === 0, statuses: statusSummary(statuses),
        dbErrors: serverErrors + lockEvents, sensitiveSuccessEvents: successEvents },
      { attempts: n, successes }, Number(process.hrtime.bigint() - t0) / 1e6);
  };
}
T.T15 = { name: '2 parallel uses of one OTT', cap: 'AC9', race: true, run: raceConsume(2) };
T.T16 = { name: '20 parallel uses of one OTT', cap: 'AC9', race: true, run: raceConsume(20) };
T.T17 = { name: '50 parallel uses of one OTT', cap: 'AC9', race: true, run: raceConsume(50) };

// ---------------------------------------------------------------- T18-T20, T28 (rate limits; fresh app per variant)
function shapeOk(statuses, allowed, limit, total) { // first `limit` are `allowed`, the rest are 429
  return statuses.length === total && statuses.slice(0, limit).every((s) => s === allowed) && statuses.slice(limit).every((s) => s === 429);
}

T.T18 = { name: 'Invalid-OTT flooding (per-user, per-IP, per-user across IPs)', cap: 'AC10', variant: 'standard', run: async (ctx) => {
  const sub = {};
  // (1) one user, 100 attempts from one address
  { const u = await ctx.user(); const statuses = []; let ms = null;
    for (let i = 0; i < 100; i++) { const r = await ctx.cp(u.access, { ott: randomOtt() }); statuses.push(r.status); if (ms === null) ms = r.ms; }
    sub.user = { ok: shapeOk(statuses, 403, 10, 100) && (await ctx.count('RATE_LIMITED', 'sensitiveUser', u.id)) === 1,
      firstBlocked: statuses.indexOf(429) + 1, statuses: statusSummary(statuses), successes: statuses.filter((s) => s === 200).length, ms }; }
  // (2) 31 different users from one address
  { const c = await ctx.restart('standard'); const before = await c.count('RATE_LIMITED', 'sensitiveIp', null);
    const statuses = [];
    for (let i = 0; i < 31; i++) { const u = await c.userNoLogin(); statuses.push((await c.cp(u.access, { ott: randomOtt() })).status); }
    sub.ip = { ok: shapeOk(statuses, 403, 30, 31) && (await c.count('RATE_LIMITED', 'sensitiveIp', null)) - before === 1,
      firstBlocked: statuses.indexOf(429) + 1, statuses: statusSummary(statuses), successes: statuses.filter((s) => s === 200).length }; }
  // (3) one user, attempts alternating over three source addresses (the per-user limit must still apply)
  { const c = await ctx.restart('standard'); const u = await c.user(); const statuses = [];
    try {
      const addrs = [undefined, '127.0.0.2', '127.0.0.3'];
      for (let i = 0; i < 12; i++) statuses.push((await c.cp(u.access, { ott: randomOtt() }, { from: addrs[i % 3] })).status);
      sub.userAcrossIps = { ok: shapeOk(statuses, 403, 10, 12) && (await c.count('RATE_LIMITED', 'sensitiveUser', u.id)) === 1,
        firstBlocked: statuses.indexOf(429) + 1, statuses: statusSummary(statuses), successes: statuses.filter((s) => s === 200).length };
    } catch (e) { sub.userAcrossIps = { skipped: `source address aliases unavailable (${e.code || e.message})`, ok: true, successes: 0 }; } }
  const allOk = Object.values(sub).every((s) => s.ok);
  const attempts = 100 + 31 + (sub.userAcrossIps.skipped ? 0 : 12);
  const successes = Object.values(sub).reduce((n, s) => n + (s.successes || 0), 0);
  const outcome = successes > 0 ? 'SUCCEEDS' : (allOk ? 'RATE_LIMITED' : 'NOT_RATE_LIMITED_AS_EXPECTED');
  return res(outcome, sub, { attempts, successes }, sub.user.ms);
} };

T.T19 = { name: 'Superseded OTT', cap: 'AC8', run: async (ctx) => {
  const u = await ctx.user();
  const first = await ctx.ott(u, 'change_password');
  const second = await ctx.ott(u, 'change_password');
  const { r, ok } = await attack(ctx, u, () => ctx.cp(u.access, { ott: first }));
  const control = await ctx.cp(u.access, { ott: second });
  return res(blockedOrSucceeds(ok) === 'BLOCKED' && control.status === 200 ? 'BLOCKED' : (ok ? 'SUCCEEDS' : 'CONTROL_FAILED'),
    { status: r.status, supersededEvents: await ctx.count('OTT_FAILURE', 'SUPERSEDED', u.id), controlStatus: control.status },
    { attempts: 1, successes: ok ? 1 : 0 }, r.ms);
} };

T.T20 = { name: 'OTT-issuance flooding', cap: 'AC10', variant: 'standard', run: async (ctx) => {
  const u = await ctx.user();
  const statuses = []; let ms = null;
  for (let i = 0; i < 20; i++) { const r = await ctx.issue(u, 'change_password'); statuses.push(r.status); if (ms === null) ms = r.ms; }
  const delivered = (await ctx.inbox.readAll(u.id)).length;
  const ok = statuses.slice(0, 5).every((s) => s === 202) && statuses.slice(5).every((s) => s === 429)
    && (await ctx.count('RATE_LIMITED', 'ottIssue', u.id)) === 1 && delivered === 5;
  return res(ok ? 'RATE_LIMITED' : 'NOT_RATE_LIMITED_AS_EXPECTED',
    { statuses: statusSummary(statuses), firstBlocked: statuses.indexOf(429) + 1, otpsDelivered: delivered },
    { attempts: 20, successes: statuses.filter((s) => s === 200).length }, ms);
} };

// ---------------------------------------------------------------- T21-T24 (all configurations)
async function profileAttempts(ctx, tokens) {
  const statuses = []; let ms = null;
  for (const t of tokens) { const r = await ctx.req('GET', '/api/profile', { token: t }); statuses.push(r.status); if (ms === null) ms = r.ms; }
  const successes = statuses.filter((s) => s === 200).length;
  return { statuses, successes, ms };
}

T.T21 = { name: 'Tampered claims / wrong secret', cap: 'AC4', run: async (ctx) => {
  const u = await ctx.user();
  const secret = ctx.appConfig.jwt.accessSecret;
  const base = claims(u.id);
  const [h, , s] = sign(base, secret).split('.');
  const swap = (over) => `${h}.${b64u({ ...base, ...over })}.${s}`;
  const tokens = [swap({ sub: '1' }), swap({ exp: nowS() + 999999 }), swap({ type: 'refresh' }), swap({ jti: crypto.randomUUID() }),
    sign(claims(u.id), 'x'.repeat(40))];
  const { statuses, successes, ms } = await profileAttempts(ctx, tokens);
  return res(successes ? 'SUCCEEDS' : 'BLOCKED', { statuses }, { attempts: tokens.length, successes }, ms);
} };

T.T22 = { name: 'Algorithm manipulation (none, HS384, RS256 key confusion)', cap: 'AC4', run: async (ctx) => {
  const u = await ctx.user();
  const secret = ctx.appConfig.jwt.accessSecret;
  const c = claims(u.id); const p = b64u(c);
  const none = (sig) => `${b64u({ alg: 'none', typ: 'JWT' })}.${p}.${sig}`;
  const h384 = b64u({ alg: 'HS384', typ: 'JWT' }); const rs = b64u({ alg: 'RS256', typ: 'JWT' });
  const tokens = [none(''), none('AAAA'), `${h384}.${p}.${hmac(secret, `${h384}.${p}`, 'sha384')}`, `${rs}.${p}.${hmac(secret, `${rs}.${p}`)}`];
  const { statuses, successes, ms } = await profileAttempts(ctx, tokens);
  return res(successes ? 'SUCCEEDS' : 'BLOCKED', { statuses }, { attempts: tokens.length, successes }, ms);
} };

T.T23 = { name: 'Claim validation (exp, nbf, iss, aud, type, missing claims)', cap: 'AC4', run: async (ctx) => {
  const u = await ctx.user();
  const secret = ctx.appConfig.jwt.accessSecret;
  const mk = (over) => sign(claims(u.id, over), secret);
  const tokens = [mk({ iat: nowS() - 2000, exp: nowS() - 1000 }), mk({ nbf: nowS() + 3600 }), mk({ iss: 'someone-else' }), mk({ aud: 'another-api' }),
    mk({ type: 'refresh' }), mk({ exp: undefined }), mk({ jti: undefined }), ctx.tokenService.signRefresh(u.id).token];
  const { statuses, successes, ms } = await profileAttempts(ctx, tokens);
  let attempts = tokens.length; let extra = null; let total = successes;
  if (ctx.mode !== 'A') { // an access token presented as a refresh token
    const r = await ctx.req('POST', '/api/auth/refresh', { body: { refreshToken: u.access } });
    attempts += 1; extra = r.status; if (r.status === 200) total += 1;
  }
  return res(total ? 'SUCCEEDS' : 'BLOCKED', { statuses, accessAsRefreshStatus: extra }, { attempts, successes: total }, ms);
} };

T.T24 = { name: 'Reuse of access and refresh JWTs after logout', cap: 'AC1 after logout', run: async (ctx) => {
  const u = await ctx.user();
  const lo = await ctx.req('POST', '/api/auth/logout', { body: ctx.mode === 'A' ? {} : { refreshToken: u.refresh }, token: u.access });
  const access = await ctx.req('GET', '/api/profile', { token: u.access });
  const refresh = ctx.mode === 'A' ? null : await ctx.req('POST', '/api/auth/refresh', { body: { refreshToken: u.refresh } });
  const successes = (access.status === 200 ? 1 : 0) + (refresh && refresh.status === 200 ? 1 : 0);
  return res(lo.status === 204 && successes === 0 ? 'BLOCKED' : 'SUCCEEDS',
    { logoutStatus: lo.status, accessStatus: access.status, refreshStatus: refresh ? refresh.status : 'n/a' },
    { attempts: refresh ? 2 : 1, successes }, access.ms);
} };

// ---------------------------------------------------------------- T25-T29
T.T25 = { name: 'Out-of-order workflow (control)', cap: 'Legit', run: async (ctx) => {
  const u = await ctx.user();
  const h0 = await ctx.hash(u.id);
  const step1 = await ctx.cp(u.access); // no second factor
  const step1Blocked = step1.status === 403 && (await ctx.hash(u.id)) === h0;
  let finalRes;
  if (ctx.mode === 'C') finalRes = await ctx.cp(u.access, { ott: await ctx.ott(u, 'change_password') });
  else finalRes = await ctx.cp(u.access, { currentPassword: ctx.PW });
  const newLogin = (await u.login(NEW_PW)).status;
  const oldLogin = (await u.login(ctx.PW)).status;
  const events = await ctx.count('SENSITIVE_OPERATION_SUCCESS', null, u.id);
  const ok = step1Blocked && finalRes.status === 200 && newLogin === 200 && oldLogin === 401 && events === 1;
  return res(ok ? 'STEP1_BLOCKED_FINAL_OK' : 'WORKFLOW_MISMATCH', { step1: step1.status, final: finalRes.status, newLogin, oldLogin, successEvents: events }, null, finalRes.ms);
} };

T.T26 = { name: 'Access JWT + captured unused OTT', cap: 'AC3', run: async (ctx) => {
  const victim = await ctx.user();
  const captured = await ctx.ott(victim, 'change_password'); // the attacker captured it from the victim's OOB inbox
  const { r, ok } = await attack(ctx, victim, () => ctx.cp(victim.access, { ott: captured }));
  return res(ok ? 'BOUNDARY' : 'BLOCKED', { status: r.status }, null, r.ms);
} };

T.T27 = { name: '20 parallel OTT issuance requests', cap: 'AC9', race: true, run: async (ctx) => {
  const u = await ctx.user();
  const rs = await Promise.all(Array.from({ length: 20 }, () => ctx.issue(u, 'change_password')));
  const statuses = rs.map((r) => r.status);
  const k = statuses.filter((s) => s === 202).length;
  const msgs = await ctx.inbox.waitFor(u.id, k, 5000).catch(() => []);
  const op = OPERATIONS.change_password;
  const s = await ctx.ottDb.countStates(ctx.sequelize, { userId: u.id, purpose: op.purpose, method: op.method, endpoint: op.endpoint });
  const stateOk = s.active === 1 && s.superseded === k - 1 && s.used === 0 && s.expired === 0 && s.total === k && s.bothFlags === 0;
  const results = [];
  for (const m of msgs) results.push((await ctx.cp(u.access, { ott: m.token })).status);
  const consumeOk = results.filter((x) => x === 200).length === 1;
  const lockEvents = await ctx.count('DB_LOCK_ERROR', null, u.id);
  return res(stateOk && consumeOk ? 'INVARIANT_HELD' : 'INVARIANT_VIOLATED',
    { concurrentSent: 20, accepted: k, statuses: statusSummary(statuses), states: s, delivered: msgs.length, consumeStatuses: statusSummary(results),
      dbErrors: statuses.filter((x) => x >= 500).length + lockEvents }, { attempts: 20, successes: 0 }, null);
} };

T.T28 = { name: 'Password guessing against re-entry (Config D)', cap: 'AC12', variant: 'standard', run: async (ctx) => {
  const u = await ctx.user();
  const statuses = []; let ms = null;
  for (let i = 0; i < 100; i++) { const r = await ctx.cp(u.access, { currentPassword: `wrong-guess-${i}-xx` }); statuses.push(r.status); if (ms === null) ms = r.ms; }
  const ok = shapeOk(statuses, 403, 10, 100) && (await ctx.count('RATE_LIMITED', 'sensitiveUser', u.id)) === 1;
  const successes = statuses.filter((s) => s === 200).length; // a wrong password that is accepted is an attack success
  return res(successes > 0 ? 'SUCCEEDS' : (ok ? 'RATE_LIMITED' : 'NOT_RATE_LIMITED_AS_EXPECTED'),
    { firstBlocked: statuses.indexOf(429) + 1, statuses: statusSummary(statuses) },
    { attempts: 100, successes }, ms);
} };

T.T29 = { name: 'Stolen access JWT + stolen current password (Config D)', cap: 'AC11', run: async (ctx) => {
  const u = await ctx.user();
  const { r, ok } = await attack(ctx, u, () => ctx.cp(u.access, { currentPassword: ctx.PW }));
  return res(ok ? 'BOUNDARY' : 'BLOCKED', { status: r.status }, null, r.ms);
} };

module.exports = { T, raceConsume };
