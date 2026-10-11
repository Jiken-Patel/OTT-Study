'use strict';
// Stage 3 development tests: registration, login, refresh rotation + reuse detection (T03/T04),
// logout (T24), per-IP/per-user rate limiters (T18/T20 mechanics). NOT experiment results.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const express = require('express');
const { QueryTypes } = require('sequelize');
const { resetDb } = require('../scripts/resetDb');
const sequelize = require('../src/config/db');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');
const { createRateLimiters } = require('../src/middleware/rateLimit');

const ACCESS_SECRET = 'test-access-secret-0123456789-abcdefghij';
const REFRESH_SECRET = 'test-refresh-secret-9876543210-jihgfedcba';
const ENV = { APP_PROFILE: 'test', AUTH_MODE: 'B', RATE_LIMIT_PROFILE: 'relaxed',
  JWT_ACCESS_SECRET: ACCESS_SECRET, JWT_REFRESH_SECRET: REFRESH_SECRET };
const PW = 'correct horse battery';

const servers = [];
async function startApp(over = {}) {
  const config = loadConfig({ ...ENV, ...over });
  const app = createApp({ sequelize, config });
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  server.sockets = new Set();
  server.on('connection', (c) => { server.sockets.add(c); c.on('close', () => server.sockets.delete(c)); });
  servers.push(server);
  return { app, config, server, base: `http://127.0.0.1:${server.address().port}` };
}
const q = (sql, r = {}) => sequelize.query(sql, { replacements: r, type: QueryTypes.SELECT });
const post = (base, path, body, headers = {}) => fetch(base + path, {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers },
  body: body === undefined ? undefined : JSON.stringify(body),
});
const getProfile = (base, token) => fetch(`${base}/api/profile`, { headers: { Authorization: `Bearer ${token}` } });
const evCount = async (type, reason) => Number((await q(
  'SELECT COUNT(*) AS n FROM security_events WHERE event_type = :type AND (:reason IS NULL OR reason = :reason)',
  { type, reason: reason ?? null }))[0].n);
let seq = 0;
async function makeUser(base, pw = PW) {
  const email = `user${Date.now()}_${seq++}@example.test`;
  const r = await post(base, '/api/auth/register', { email, password: pw });
  assert.equal(r.status, 201);
  return { email, id: (await r.json()).id };
}
async function loginAs(base, email, pw = PW) {
  const r = await post(base, '/api/auth/login', { email, password: pw });
  assert.equal(r.status, 200);
  return r.json();
}

let B, A; // Config B and Config A servers
before(async () => {
  await resetDb();
  B = await startApp();
  A = await startApp({ AUTH_MODE: 'A' });
});
after(async () => {
  for (const s of servers) { s.sockets.forEach((c) => c.destroy()); await new Promise((r) => s.close(r)); }
  await sequelize.close();
});

// ---------------- registration ----------------
test('register: normalises email, stores only a bcrypt cost-12 hash, rejects duplicates', async () => {
  const email = `Reg${Date.now()}@Example.test`;
  const r = await post(B.base, '/api/auth/register', { email: `  ${email} `, password: PW });
  assert.equal(r.status, 201);
  const body = await r.json();
  assert.equal(body.email, email.toLowerCase());
  assert.ok(!('password' in body) && !('password_hash' in body));
  const [u] = await q('SELECT password_hash FROM users WHERE id = :id', { id: body.id });
  assert.ok(u.password_hash.startsWith('$2b$12$'), 'bcrypt cost 12 expected');
  assert.ok(!JSON.stringify(await q('SELECT * FROM users')).includes(PW));
  assert.equal((await post(B.base, '/api/auth/register', { email: email.toUpperCase(), password: PW })).status, 409);
});

test('register: invalid email/password input is rejected with 400', async () => {
  const bad = [
    { email: 'nope', password: PW }, { email: 123, password: PW }, { email: 'x@y.test', password: 'short' },
    { email: 'x@y.test', password: 'a'.repeat(73) }, { email: 'x@y.test', password: '😀'.repeat(19) }, // 76 bytes
    { email: 'x@y.test', password: 12345678 }, { email: 'x@y.test', password: ['a'.repeat(10)] }, {},
  ];
  for (const b of bad) assert.equal((await post(B.base, '/api/auth/register', b)).status, 400, JSON.stringify(b));
  assert.equal((await post(B.base, '/api/auth/register', { email: 'ok1@y.test', password: 'a'.repeat(72) })).status, 201);
  assert.equal((await post(B.base, '/api/auth/register', { email: 'ok2@y.test', password: 'a'.repeat(8) })).status, 201);
});

// ---------------- login ----------------
test('login: success returns access + refresh (B); only hashes are stored', async () => {
  const u = await makeUser(B.base);
  const t = await loginAs(B.base, u.email);
  assert.ok(t.accessToken && t.refreshToken);
  assert.equal(t.tokenType, 'Bearer'); assert.equal(t.expiresIn, 900); assert.equal(t.refreshExpiresIn, 604800);
  assert.equal((await getProfile(B.base, t.accessToken)).status, 200);
  const stored = JSON.stringify(await q('SELECT * FROM refresh_tokens'));
  assert.ok(!stored.includes(t.refreshToken), 'raw refresh token stored');
  assert.ok(!JSON.stringify(await q('SELECT * FROM security_events')).includes(PW), 'password reached the audit log');
});

test('login: wrong password and unknown user are indistinguishable to the client but logged internally', async () => {
  const u = await makeUser(B.base);
  const r1 = await post(B.base, '/api/auth/login', { email: u.email, password: 'wrong password!!' });
  const r2 = await post(B.base, '/api/auth/login', { email: 'nobody@example.test', password: PW });
  const r3 = await post(B.base, '/api/auth/login', { email: u.email, password: 'x'.repeat(200) });
  const r4 = await post(B.base, '/api/auth/login', {});
  for (const r of [r1, r2, r3, r4]) assert.equal(r.status, 401);
  const bodies = new Set([await r1.text(), await r2.text(), await r3.text(), await r4.text()]);
  assert.equal(bodies.size, 1);
  assert.ok(await evCount('LOGIN_FAILURE', 'BAD_PASSWORD') >= 1);
  assert.ok(await evCount('LOGIN_FAILURE', 'USER_NOT_FOUND') >= 1);
  assert.ok(await evCount('LOGIN_FAILURE', 'INVALID_INPUT') >= 1);
});

test('login: an unknown user still pays a bcrypt comparison (no cheap timing oracle)', async () => {
  await post(B.base, '/api/auth/login', { email: 'warmup@example.test', password: PW }); // memoise dummy hash
  const t0 = process.hrtime.bigint();
  const r = await post(B.base, '/api/auth/login', { email: 'nobody2@example.test', password: PW });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.equal(r.status, 401);
  assert.ok(ms >= 60, `unknown-user login took only ${ms.toFixed(0)} ms`);
});

// ---------------- refresh rotation (T03, T04) ----------------
test('refresh: rotates, chains rows in one family, and the old token is dead', async () => {
  const u = await makeUser(B.base);
  const t1 = await loginAs(B.base, u.email);
  const r = await post(B.base, '/api/auth/refresh', { refreshToken: t1.refreshToken });
  assert.equal(r.status, 200);
  const t2 = await r.json();
  assert.notEqual(t2.refreshToken, t1.refreshToken);
  assert.equal((await getProfile(B.base, t2.accessToken)).status, 200);
  const rowsU = await q('SELECT id, family_id, revoked_at, replaced_by FROM refresh_tokens WHERE user_id = :id ORDER BY id', { id: u.id });
  assert.equal(rowsU.length, 2);
  assert.equal(rowsU[0].family_id, rowsU[1].family_id);
  assert.ok(rowsU[0].revoked_at); assert.equal(rowsU[1].revoked_at, null);
  assert.equal(String(rowsU[0].replaced_by), String(rowsU[1].id));
});

test('T04: replaying a rotated refresh token is detected and revokes the whole family', async () => {
  const u = await makeUser(B.base);
  const t1 = await loginAs(B.base, u.email);
  const t2 = await (await post(B.base, '/api/auth/refresh', { refreshToken: t1.refreshToken })).json();
  const before = await evCount('REFRESH_REPLAY');
  assert.equal((await post(B.base, '/api/auth/refresh', { refreshToken: t1.refreshToken })).status, 401); // replay
  assert.equal(await evCount('REFRESH_REPLAY'), before + 1);
  assert.equal((await post(B.base, '/api/auth/refresh', { refreshToken: t2.refreshToken })).status, 401); // family dead
  const [active] = await q('SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = :id AND revoked_at IS NULL', { id: u.id });
  assert.equal(Number(active.n), 0);
});

test('T03: stolen refresh token — attacker rotates first (boundary), legitimate reuse is detected, family dies', async () => {
  const u = await makeUser(B.base);
  const victim = await loginAs(B.base, u.email);
  const a = await post(B.base, '/api/auth/refresh', { refreshToken: victim.refreshToken });          // T03a
  assert.equal(a.status, 200);
  const attacker = await a.json();
  const before = await evCount('REFRESH_REPLAY');
  assert.equal((await post(B.base, '/api/auth/refresh', { refreshToken: victim.refreshToken })).status, 401); // T03b
  assert.equal(await evCount('REFRESH_REPLAY'), before + 1);
  assert.equal((await post(B.base, '/api/auth/refresh', { refreshToken: attacker.refreshToken })).status, 401);
  // Family revocation does not revoke an already-issued access JWT (documented boundary).
  assert.equal((await getProfile(B.base, attacker.accessToken)).status, 200);
});

test('refresh: invalid inputs are all a generic 401 and are logged', async () => {
  const u = await makeUser(B.base);
  const t = await loginAs(B.base, u.email);
  const ts = B.app.locals.tokenService;
  const unstored = ts.signRefresh(u.id).token;                       // valid signature, never stored
  const [h, p, s] = t.refreshToken.split('.');
  const tampered = `${h}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url')), sub: '1' })).toString('base64url')}.${s}`;
  const cases = [undefined, '', 'garbage', t.accessToken, tampered, unstored];
  for (const c of cases) {
    const r = await post(B.base, '/api/auth/refresh', { refreshToken: c });
    assert.equal(r.status, 401, String(c));
    assert.deepEqual(await r.json(), { error: 'Authentication failed' });
  }
  assert.equal((await post(B.base, '/api/auth/refresh', {})).status, 401);
  assert.ok(await evCount('REFRESH_FAILURE', 'REFRESH_UNKNOWN') >= 1);
  assert.ok(await evCount('REFRESH_FAILURE', 'TOKEN_INVALID') >= 1);
});

test('refresh: 20 parallel uses of one token -> exactly one success, family ends fully revoked, no 5xx', async () => {
  for (let rep = 0; rep < 5; rep++) {
    const u = await makeUser(B.base);
    const t = await loginAs(B.base, u.email);
    const res = await Promise.all(Array.from({ length: 20 }, () => post(B.base, '/api/auth/refresh', { refreshToken: t.refreshToken })));
    const statuses = res.map((r) => r.status);
    assert.equal(statuses.filter((s) => s === 200).length, 1, statuses.join(','));
    assert.ok(statuses.every((s) => s === 200 || s === 401), `unexpected status: ${statuses.join(',')}`);
    const [active] = await q('SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = :id AND revoked_at IS NULL', { id: u.id });
    assert.equal(Number(active.n), 0);
  }
});

// ---------------- logout (T24) ----------------
test('T24: logout revokes the access jti and the refresh family', async () => {
  const u = await makeUser(B.base);
  const t = await loginAs(B.base, u.email);
  assert.equal((await getProfile(B.base, t.accessToken)).status, 200);
  const r = await post(B.base, '/api/auth/logout', { refreshToken: t.refreshToken }, { Authorization: `Bearer ${t.accessToken}` });
  assert.equal(r.status, 204);
  assert.equal((await getProfile(B.base, t.accessToken)).status, 401);
  assert.equal((await post(B.base, '/api/auth/refresh', { refreshToken: t.refreshToken })).status, 401);
});

test('logout: requires authentication and (B/C/D) a refresh token; a rejected logout revokes nothing', async () => {
  const u = await makeUser(B.base);
  const t = await loginAs(B.base, u.email);
  assert.equal((await post(B.base, '/api/auth/logout', { refreshToken: t.refreshToken })).status, 401);
  assert.equal((await post(B.base, '/api/auth/logout', {}, { Authorization: `Bearer ${t.accessToken}` })).status, 400);
  assert.equal((await getProfile(B.base, t.accessToken)).status, 200);
  assert.equal((await post(B.base, '/api/auth/refresh', { refreshToken: t.refreshToken })).status, 200);
});

test('logout: presenting someone else\'s refresh token revokes only your own access token', async () => {
  const alice = await makeUser(B.base); const bob = await makeUser(B.base);
  const ta = await loginAs(B.base, alice.email); const tb = await loginAs(B.base, bob.email);
  const r = await post(B.base, '/api/auth/logout', { refreshToken: tb.refreshToken }, { Authorization: `Bearer ${ta.accessToken}` });
  assert.equal(r.status, 204);
  assert.equal((await getProfile(B.base, ta.accessToken)).status, 401);
  assert.equal((await post(B.base, '/api/auth/refresh', { refreshToken: tb.refreshToken })).status, 200);
});

// ---------------- Config A ----------------
test('Config A: login returns only an access token, /refresh does not exist, logout revokes the access jti', async () => {
  const u = await makeUser(A.base);
  const t = await loginAs(A.base, u.email);
  assert.ok(t.accessToken); assert.equal(t.refreshToken, undefined); assert.equal(t.refreshExpiresIn, undefined);
  assert.equal((await post(A.base, '/api/auth/refresh', { refreshToken: 'x' })).status, 404);
  assert.equal((await post(A.base, '/api/auth/logout', {}, { Authorization: `Bearer ${t.accessToken}` })).status, 204);
  assert.equal((await getProfile(A.base, t.accessToken)).status, 401);
  assert.equal(Number((await q('SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = :id', { id: u.id }))[0].n), 0);
});

// ---------------- rate limiting (T18/T20 mechanics) ----------------
test('rate limit (standard): per-IP login limit 10/min, 11th is 429 with headers, logged once', async () => {
  const RL = await startApp({ RATE_LIMIT_PROFILE: 'standard' });
  const before = await evCount('RATE_LIMITED', 'login');
  const statuses = [];
  let last;
  for (let i = 0; i < 15; i++) { last = await post(RL.base, '/api/auth/login', {}); statuses.push(last.status); }
  assert.deepEqual(statuses, [...Array(10).fill(401), ...Array(5).fill(429)]);
  assert.equal(last.headers.get('ratelimit-limit'), '10');
  assert.ok(Number(last.headers.get('ratelimit-reset')) > 0);
  assert.deepEqual(await last.json(), { error: 'Too many requests' });
  assert.equal(await evCount('RATE_LIMITED', 'login'), before + 1, 'first blocked request must be logged exactly once');
});

test('rate limit (standard): per-IP refresh limit 30/min', async () => {
  const RL = await startApp({ RATE_LIMIT_PROFILE: 'standard' });
  const statuses = [];
  for (let i = 0; i < 32; i++) statuses.push((await post(RL.base, '/api/auth/refresh', { refreshToken: 'garbage' })).status);
  assert.equal(statuses.filter((s) => s === 401).length, 30);
  assert.deepEqual(statuses.slice(30), [429, 429]);
});

test('rate limit (off): no limiting at all', async () => {
  const OFF = await startApp({ RATE_LIMIT_PROFILE: 'off' });
  for (let i = 0; i < 15; i++) assert.equal((await post(OFF.base, '/api/auth/login', {})).status, 401);
});

test('rate limit: per-user limiters key on the authenticated user, per-IP limiter on the address', async () => {
  const cfg = loadConfig({ ...ENV, RATE_LIMIT_PROFILE: 'standard' });
  const lim = createRateLimiters({ sequelize, config: cfg });
  const mini = express();
  mini.use((req, res, next) => { req.auth = { userId: req.headers['x-user'] }; next(); });
  mini.post('/issue', lim.ottIssue, (req, res) => res.json({ ok: 1 }));
  mini.post('/op-user', lim.sensitiveUser, (req, res) => res.json({ ok: 1 }));
  mini.post('/op-ip', lim.sensitiveIp, (req, res) => res.json({ ok: 1 }));
  const s = await new Promise((resolve) => { const x = mini.listen(0, '127.0.0.1', () => resolve(x)); });
  s.sockets = new Set(); s.on('connection', (c) => s.sockets.add(c)); servers.push(s);
  const base = `http://127.0.0.1:${s.address().port}`;
  const u1 = (await q('SELECT id FROM users ORDER BY id LIMIT 1'))[0].id;
  const u2 = (await q('SELECT id FROM users ORDER BY id LIMIT 1 OFFSET 1'))[0].id;
  const hit = async (path, user) => (await post(base, path, {}, { 'x-user': String(user) })).status;

  const issue = []; for (let i = 0; i < 6; i++) issue.push(await hit('/issue', u1));
  assert.deepEqual(issue, [200, 200, 200, 200, 200, 429]);          // 5/min per user
  assert.equal(await hit('/issue', u2), 200);                        // another user is unaffected

  const op = []; for (let i = 0; i < 11; i++) op.push(await hit('/op-user', u1));
  assert.deepEqual(op, [...Array(10).fill(200), 429]);               // 10/min per user

  const ip = []; for (let i = 0; i < 31; i++) ip.push(await hit('/op-ip', i % 2 ? u1 : u2)); // different users, same IP
  assert.deepEqual(ip, [...Array(30).fill(200), 429]);               // 30/min per IP
  assert.ok(await evCount('RATE_LIMITED', 'ottIssue') >= 1);
});
