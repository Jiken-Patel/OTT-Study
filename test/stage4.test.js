'use strict';
// Stage 4 development tests: change-password under Configs A/B/D, Config C fails closed (501),
// simulated sensitive routes, middleware order and limiter mechanics (T02, T25, T28, T29). NOT experiment results.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { QueryTypes } = require('sequelize');
const { resetDb } = require('../scripts/resetDb');
const sequelize = require('../src/config/db');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');

const ENV = { APP_PROFILE: 'test', AUTH_MODE: 'B', RATE_LIMIT_PROFILE: 'relaxed', ENABLE_SIMULATED_OPERATIONS: 'true',
  JWT_ACCESS_SECRET: 'test-access-secret-0123456789-abcdefghij', JWT_REFRESH_SECRET: 'test-refresh-secret-9876543210-jihgfedcba' };
const PW = 'correct horse battery';
const NEW_PW = 'brand new passphrase';

const servers = [];
async function startApp(over = {}) {
  const config = loadConfig({ ...ENV, ...over });
  const app = createApp({ sequelize, config });
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  server.sockets = new Set();
  server.on('connection', (c) => { server.sockets.add(c); c.on('close', () => server.sockets.delete(c)); });
  servers.push(server);
  return { app, config, base: `http://127.0.0.1:${server.address().port}` };
}
const q = (sql, r = {}) => sequelize.query(sql, { replacements: r, type: QueryTypes.SELECT });
const send = (base, method, path, body, token) => fetch(base + path, {
  method, headers: { 'content-type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  body: body === undefined ? undefined : JSON.stringify(body),
});
const post = (base, path, body, token) => send(base, 'POST', path, body, token);
const evCount = async (type, reason, userId) => Number((await q(
  `SELECT COUNT(*) AS n FROM security_events WHERE event_type = :type
     AND (:reason IS NULL OR reason = :reason) AND (:userId IS NULL OR user_id = :userId)`,
  { type, reason: reason ?? null, userId: userId ?? null }))[0].n);
let seq = 0;
async function makeUser(base) {
  const email = `s4user${Date.now()}_${seq++}@example.test`;
  const r = await post(base, '/api/auth/register', { email, password: PW });
  assert.equal(r.status, 201);
  const id = (await r.json()).id;
  const login = async (pw = PW) => post(base, '/api/auth/login', { email, password: pw });
  const t = await (await login()).json();
  return { email, id, token: t.accessToken, login };
}
const hashOf = async (id) => (await q('SELECT password_hash FROM users WHERE id = :id', { id }))[0].password_hash;

let A, Bapp, D;
before(async () => {
  await resetDb();
  A = await startApp({ AUTH_MODE: 'A' });
  Bapp = await startApp({ AUTH_MODE: 'B' });
  D = await startApp({ AUTH_MODE: 'D' });
});
after(async () => {
  for (const s of servers) { s.sockets.forEach((c) => c.destroy()); await new Promise((r) => s.close(r)); }
  await sequelize.close();
});

// ---------- config ----------
test('config: ENABLE_SIMULATED_OPERATIONS is an explicit opt-in, independent of APP_PROFILE', () => {
  assert.equal(loadConfig({ ...ENV, ENABLE_SIMULATED_OPERATIONS: undefined }).enableSimulatedOperations, false);
  assert.equal(loadConfig({ ...ENV, ENABLE_SIMULATED_OPERATIONS: 'false' }).enableSimulatedOperations, false);
  assert.equal(loadConfig({ ...ENV, ENABLE_SIMULATED_OPERATIONS: 'true' }).enableSimulatedOperations, true);
  assert.equal(loadConfig({ ...ENV, APP_PROFILE: 'development', UV_THREADPOOL_SIZE: '16',
    ENABLE_SIMULATED_OPERATIONS: 'true' }).enableSimulatedOperations, true);
});

// ---------- change-password: Configs A and B (no step-up) ----------
for (const [name, getApp] of [['A', () => A], ['B', () => Bapp]]) {
  test(`T02 (Config ${name}): a stolen access JWT alone changes the password — SUCCEEDS by design`, async () => {
    const { base } = getApp();
    const u = await makeUser(base);
    const r = await post(base, '/api/auth/change-password', { newPassword: NEW_PW }, u.token);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { status: 'password_changed' });
    assert.ok((await hashOf(u.id)).startsWith('$2b$12$'));
    assert.equal((await u.login(NEW_PW)).status, 200);
    assert.equal((await u.login(PW)).status, 401);
    const [row] = await q('SELECT password_changed_at FROM users WHERE id = :id', { id: u.id });
    assert.ok(row.password_changed_at);
    assert.ok(await evCount('SENSITIVE_OPERATION_SUCCESS', null, u.id) >= 1);
    assert.ok(!JSON.stringify(await q('SELECT * FROM security_events')).includes(NEW_PW), 'new password reached the audit log');
  });
}

test('change-password: auth is required; invalid newPassword is 400 and changes nothing; wrong methods are 404', async () => {
  const { base } = Bapp;
  const u = await makeUser(base);
  const before = await hashOf(u.id);
  assert.equal((await post(base, '/api/auth/change-password', { newPassword: NEW_PW })).status, 401);
  for (const bad of [{}, { newPassword: 'short' }, { newPassword: 'a'.repeat(73) }, { newPassword: 12345678 }, { newPassword: ['x'.repeat(10)] }]) {
    assert.equal((await post(base, '/api/auth/change-password', bad, u.token)).status, 400, JSON.stringify(bad));
  }
  assert.equal(await hashOf(u.id), before);
  assert.equal((await send(base, 'GET', '/api/auth/change-password', undefined, u.token)).status, 404);
  assert.equal((await send(base, 'PUT', '/api/auth/change-password', { newPassword: NEW_PW }, u.token)).status, 404);
});

test('change-password: a revoked access token is rejected before anything else', async () => {
  const { base } = Bapp;
  const u = await makeUser(base);
  const t = await (await u.login()).json();
  assert.equal((await post(base, '/api/auth/logout', { refreshToken: t.refreshToken }, t.accessToken)).status, 204);
  const before = await hashOf(u.id);
  assert.equal((await post(base, '/api/auth/change-password', { newPassword: NEW_PW }, t.accessToken)).status, 401);
  assert.equal(await hashOf(u.id), before);
});

// ---------- Config D: password re-entry ----------
test('T02/T09 (Config D): stolen JWT without or with a wrong current password is BLOCKED; password unchanged', async () => {
  const { base } = D;
  const u = await makeUser(base);
  const before = await hashOf(u.id);
  const bodies = new Set();
  const cases = [{ newPassword: NEW_PW }, { newPassword: NEW_PW, currentPassword: 'wrong password!!' },
    { newPassword: NEW_PW, currentPassword: 12345678 }, { newPassword: NEW_PW, currentPassword: 'x'.repeat(100) }];
  for (const c of cases) {
    const r = await post(base, '/api/auth/change-password', c, u.token);
    assert.equal(r.status, 403, JSON.stringify(c));
    bodies.add(await r.text());
  }
  assert.equal(bodies.size, 1, 'all step-up failures must look identical');
  assert.equal(await hashOf(u.id), before);
  for (const reason of ['MISSING_PASSWORD', 'BAD_PASSWORD', 'INVALID_INPUT']) {
    assert.ok(await evCount('PASSWORD_REENTRY_FAILURE', reason, u.id) >= 1, reason);
  }
});

test('T25/T29 (Config D): omit -> 403, then correct current password -> 200; new password works, old does not', async () => {
  const { base } = D;
  const u = await makeUser(base);
  assert.equal((await post(base, '/api/auth/change-password', { newPassword: NEW_PW }, u.token)).status, 403);
  const ok = await post(base, '/api/auth/change-password', { newPassword: NEW_PW, currentPassword: PW }, u.token);
  assert.equal(ok.status, 200);
  assert.equal((await u.login(NEW_PW)).status, 200);
  assert.equal((await u.login(PW)).status, 401);
});

test('Config D: invalid newPassword is a 400 even with the correct current password (validation first)', async () => {
  const { base } = D;
  const u = await makeUser(base);
  const before = await hashOf(u.id);
  assert.equal((await post(base, '/api/auth/change-password', { newPassword: 'short', currentPassword: PW }, u.token)).status, 400);
  assert.equal((await post(base, '/api/auth/change-password', { newPassword: 'short', currentPassword: 'wrong' }, u.token)).status, 400);
  assert.equal(await hashOf(u.id), before);
});

test('Config D: the current password of ANOTHER user does not work', async () => {
  const { base } = D;
  const a = await makeUser(base);
  const b = await makeUser(base);
  await post(base, '/api/auth/change-password', { newPassword: 'bobs own new password', currentPassword: PW }, b.token);
  const r = await post(base, '/api/auth/change-password', { newPassword: NEW_PW, currentPassword: 'bobs own new password' }, a.token);
  assert.equal(r.status, 403);
});

// ---------- Config C step-up fails closed if the OTT service is missing ----------
// (Config C's real behaviour is covered in stage5.test.js; here we only check the guard cannot fail open.)
test('Config C step-up fails closed (501) when no OTT service is wired in', async () => {
  const { createStepUp } = require('../src/middleware/stepUp');
  const config = loadConfig({ ...ENV, AUTH_MODE: 'C', OOB_SINK_URL: 'http://127.0.0.1:4010', OOB_SINK_KEY: 'k'.repeat(20) });
  const guard = createStepUp({ sequelize, config, passwords: {}, ottService: null })('change_password');
  let status; let nextCalled = false;
  const res = { status(s) { status = s; return this; }, json() { return this; } };
  guard({}, res, () => { nextCalled = true; });
  assert.equal(status, 501);
  assert.equal(nextCalled, false);
});

// ---------- simulated operations ----------
test('simulated routes are NOT mounted unless explicitly enabled', async () => {
  const off = await startApp({ ENABLE_SIMULATED_OPERATIONS: 'false' });
  const u = await makeUser(off.base);
  for (const [m, p] of [['POST', '/api/auth/confirm-email'], ['PUT', '/api/auth/confirm-email'], ['POST', '/api/auth/update-security-settings']]) {
    assert.equal((await send(off.base, m, p, {}, u.token)).status, 404, `${m} ${p}`);
  }
});

test('simulated routes (A/B): JWT is enough, no state changes, success event logged; auth required', async () => {
  for (const app of [A, Bapp]) {
    const u = await makeUser(app.base);
    const before = await hashOf(u.id);
    for (const [m, p, op] of [['POST', '/api/auth/confirm-email', 'confirm_email'], ['PUT', '/api/auth/confirm-email', 'confirm_email_put'],
      ['POST', '/api/auth/update-security-settings', 'update_security_settings']]) {
      const r = await send(app.base, m, p, {}, u.token);
      assert.equal(r.status, 200, `${m} ${p}`);
      assert.deepEqual(await r.json(), { status: 'ok', operation: op });
      assert.equal((await send(app.base, m, p, {})).status, 401);
    }
    assert.equal(await hashOf(u.id), before);
    assert.ok(await evCount('SENSITIVE_OPERATION_SUCCESS', null, u.id) >= 3);
  }
});

test('simulated routes (D): require the current password', async () => {
  const u = await makeUser(D.base);
  assert.equal((await post(D.base, '/api/auth/confirm-email', {}, u.token)).status, 403);
  assert.equal((await post(D.base, '/api/auth/confirm-email', { currentPassword: 'nope nope nope' }, u.token)).status, 403);
  assert.equal((await post(D.base, '/api/auth/confirm-email', { currentPassword: PW }, u.token)).status, 200);
  assert.equal((await send(D.base, 'PUT', '/api/auth/confirm-email', { currentPassword: PW }, u.token)).status, 200);
});

// ---------- middleware order + limiters (T28 mechanics) ----------
test('T28 mechanics (Config D, standard): wrong-password attempts are 403 until 10/min per user, then 429, logged once', async () => {
  const RL = await startApp({ AUTH_MODE: 'D', RATE_LIMIT_PROFILE: 'standard' });
  const u = await makeUser(RL.base);
  const before = await evCount('RATE_LIMITED', 'sensitiveUser', u.id);
  const statuses = [];
  for (let i = 0; i < 13; i++) statuses.push((await post(RL.base, '/api/auth/change-password', { newPassword: NEW_PW, currentPassword: 'wrong guess ' + i }, u.token)).status);
  assert.deepEqual(statuses, [...Array(10).fill(403), 429, 429, 429]);
  assert.equal(await evCount('RATE_LIMITED', 'sensitiveUser', u.id), before + 1);
  // the legitimate password is also blocked while the window is exhausted
  assert.equal((await post(RL.base, '/api/auth/change-password', { newPassword: NEW_PW, currentPassword: PW }, u.token)).status, 429);
});

test('middleware order: the per-IP limiter runs BEFORE authentication (unauthenticated floods are limited per IP)', async () => {
  const RL = await startApp({ AUTH_MODE: 'B', RATE_LIMIT_PROFILE: 'standard' });
  const statuses = [];
  for (let i = 0; i < 32; i++) statuses.push((await post(RL.base, '/api/auth/change-password', { newPassword: NEW_PW })).status);
  assert.deepEqual(statuses, [...Array(30).fill(401), 429, 429]);
  assert.ok(await evCount('RATE_LIMITED', 'sensitiveIp') >= 1);
});
