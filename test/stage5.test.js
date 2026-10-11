'use strict';
// Stage 5 development tests: OOB sink, OTT issuance, requireOTT guard, atomic consume (Config C).
// T02, T05-T20, T25-T27 at HTTP level. NOT experiment results.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { QueryTypes } = require('sequelize');
const { resetDb } = require('../scripts/resetDb');
const sequelize = require('../src/config/db');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');
const { createSink } = require('../sink/oobSink');
const { createSinkClient } = require('./helpers/sinkClient');
const { OPERATIONS } = require('../src/operations');
const ottMod = require('../src/db/ottTransactions');

const DELIVER_KEY = 'deliver-key-0123456789abcd';
const READ_KEY = 'read-key-9876543210zyxwvu';
const ENV = { APP_PROFILE: 'test', AUTH_MODE: 'C', RATE_LIMIT_PROFILE: 'relaxed', ENABLE_SIMULATED_OPERATIONS: 'true',
  JWT_ACCESS_SECRET: 'test-access-secret-0123456789-abcdefghij', JWT_REFRESH_SECRET: 'test-refresh-secret-9876543210-jihgfedcba' };
const PW = 'correct horse battery';
const NEW_PW = 'brand new passphrase';
const FAIL_BODY = { error: 'Invalid or unavailable one-time token' };

let sink, sinkBase, inbox, C;
const servers = [];
async function startApp(over = {}) {
  const config = loadConfig({ ...ENV, OOB_SINK_URL: sinkBase, OOB_SINK_KEY: DELIVER_KEY, ...over });
  const app = createApp({ sequelize, config });
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  server.sockets = new Set();
  server.on('connection', (c) => { server.sockets.add(c); c.on('close', () => server.sockets.delete(c)); });
  servers.push(server);
  return { app, config, base: `http://127.0.0.1:${server.address().port}` };
}
const q = (sql, r = {}) => sequelize.query(sql, { replacements: r, type: QueryTypes.SELECT });
const send = (base, method, path, body, token, headers = {}) => fetch(base + path, {
  method, headers: { 'content-type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
  body: body === undefined ? undefined : JSON.stringify(body),
});
const post = (base, path, body, token, headers) => send(base, 'POST', path, body, token, headers);
const evCount = async (type, reason, userId) => Number((await q(
  `SELECT COUNT(*) AS n FROM security_events WHERE event_type = :type
     AND (:reason IS NULL OR reason = :reason) AND (:userId IS NULL OR user_id = :userId)`,
  { type, reason: reason ?? null, userId: userId ?? null }))[0].n);
const hashOf = async (id) => (await q('SELECT password_hash FROM users WHERE id = :id', { id }))[0].password_hash;
let seq = 0;
async function makeUser(base = C.base) {
  const email = `s5user${Date.now()}_${seq++}@example.test`;
  const r = await post(base, '/api/auth/register', { email, password: PW });
  assert.equal(r.status, 201);
  const id = (await r.json()).id;
  const login = (pw = PW) => post(base, '/api/auth/login', { email, password: pw });
  const t = await (await login()).json();
  return { email, id, token: t.accessToken, login };
}
const issueReq = (base, token, operation, purpose) =>
  post(base, '/api/ott/request', { purpose: purpose ?? OPERATIONS[operation].purpose, operation }, token);
/** Issue an OTT for `operation` and read it from the harness inbox. */
async function getOtt(user, operation, base = C.base) {
  const r = await issueReq(base, user.token, operation);
  assert.equal(r.status, 202, `issuance failed: ${r.status}`);
  return inbox.readOtt(user.id);
}
const cp = (user, body, base = C.base) => post(base, '/api/auth/change-password', { newPassword: NEW_PW, ...body }, user.token);
const confirm = (user, ott, base = C.base) => post(base, '/api/auth/confirm-email', { ott }, user.token);

before(async () => {
  await resetDb();
  sink = createSink({ deliverKey: DELIVER_KEY, readKey: READ_KEY });
  sinkBase = `http://127.0.0.1:${await sink.listen(0)}`;
  inbox = createSinkClient({ baseUrl: sinkBase, readKey: READ_KEY });
  C = await startApp();
});
after(async () => {
  for (const s of servers) { s.sockets.forEach((c) => c.destroy()); await new Promise((r) => s.close(r)); }
  await sink.close();
  await sequelize.close();
});

// ---------------- config ----------------
test('config: Config C requires a loopback OOB sink URL and a deliver key; other modes do not', () => {
  const base = { ...ENV };
  const bad = (over, re) => assert.throws(() => loadConfig({ ...base, ...over }), re);
  bad({ OOB_SINK_URL: undefined, OOB_SINK_KEY: DELIVER_KEY }, /OOB_SINK_URL/);
  bad({ OOB_SINK_URL: 'http://example.com:4010', OOB_SINK_KEY: DELIVER_KEY }, /loopback/);
  bad({ OOB_SINK_URL: 'https://127.0.0.1:4010', OOB_SINK_KEY: DELIVER_KEY }, /OOB_SINK_URL/);
  bad({ OOB_SINK_URL: 'http://127.0.0.1:4010', OOB_SINK_KEY: 'short' }, /OOB_SINK_KEY/);
  assert.equal(loadConfig({ ...base, OOB_SINK_URL: 'http://localhost:4010', OOB_SINK_KEY: DELIVER_KEY }).oobSink.url, 'http://localhost:4010');
  assert.equal(loadConfig({ ...base, AUTH_MODE: 'B' }).oobSink, null);
});

// ---------------- sink contract ----------------
test('sink: deliver and read keys are separate; read deletes; reset clears; memory is bounded', async () => {
  const s = createSink({ deliverKey: DELIVER_KEY, readKey: READ_KEY, maxPerUser: 3 });
  const base = `http://127.0.0.1:${await s.listen(0)}`;
  try {
    assert.throws(() => createSink({ deliverKey: 'same-key-same-key-1', readKey: 'same-key-same-key-1' }), /two different keys/);
    const deliver = (key, token = 't') => fetch(`${base}/deliver`, { method: 'POST',
      headers: { 'content-type': 'application/json', ...(key ? { 'x-sink-key': key } : {}) },
      body: JSON.stringify({ userId: '7', operation: 'confirm_email', purpose: 'account_security', token }) });
    assert.equal((await deliver(undefined)).status, 401);
    assert.equal((await deliver(READ_KEY)).status, 401);          // the read key cannot deliver
    assert.equal((await deliver(DELIVER_KEY)).status, 202);
    const get = (key) => fetch(`${base}/inbox/7`, { headers: key ? { 'x-sink-key': key } : {} });
    assert.equal((await get(undefined)).status, 401);
    assert.equal((await get(DELIVER_KEY)).status, 401);           // the app's key cannot read the inbox
    const first = await (await get(READ_KEY)).json();
    assert.equal(first.length, 1);
    assert.deepEqual(await (await get(READ_KEY)).json(), []);     // delete-on-read
    for (let i = 0; i < 5; i++) await deliver(DELIVER_KEY, `m${i}`);
    assert.deepEqual((await (await get(READ_KEY)).json()).map((m) => m.token), ['m2', 'm3', 'm4']); // bounded, oldest dropped
    await deliver(DELIVER_KEY);
    assert.equal((await fetch(`${base}/reset`, { method: 'POST', headers: { 'x-sink-key': DELIVER_KEY } })).status, 401);
    assert.equal((await fetch(`${base}/reset`, { method: 'POST', headers: { 'x-sink-key': READ_KEY } })).status, 204);
    assert.equal(s.size(), 0);
  } finally { await s.close(); }
});

// ---------------- issuance ----------------
test('issuance: 202, the response never contains the OTT, it arrives only in the OOB inbox; only hashes are stored', async () => {
  const u = await makeUser();
  const r = await issueReq(C.base, u.token, 'change_password');
  const text = await r.text();
  assert.equal(r.status, 202);
  assert.deepEqual(JSON.parse(text), { status: 'ott_issued', expiresIn: 300 });
  const [msg] = await inbox.waitFor(u.id, 1);
  assert.equal(msg.operation, 'change_password'); assert.equal(msg.purpose, 'change_password');
  assert.equal(msg.token.length, 43);
  assert.ok(!text.includes(msg.token));
  assert.equal(Number((await q('SELECT COUNT(*) AS n FROM one_time_tokens WHERE token_hash = :t', { t: msg.token }))[0].n), 0);
  assert.equal(Number((await q('SELECT COUNT(*) AS n FROM one_time_tokens WHERE token_hash = :t', { t: ottMod.sha256(msg.token) }))[0].n), 1);
  assert.ok(await evCount('OTT_ISSUED', null, u.id) >= 1);
});

test('issuance: requires authentication; invalid purpose/operation combinations are a generic 400; the route is Config C only', async () => {
  const u = await makeUser();
  assert.equal((await post(C.base, '/api/ott/request', { purpose: 'change_password', operation: 'change_password' })).status, 401);
  for (const body of [{}, { operation: 'change_password' }, { purpose: 'change_password' }, { purpose: 'change_password', operation: 'nope' },
    { purpose: 'account_security', operation: 'change_password' }, { purpose: 'change_password', operation: 'confirm_email' },
    { purpose: 5, operation: 'change_password' }, { purpose: 'change_password', operation: ['change_password'] },
    { purpose: 'change_password', operation: '__proto__' }, { purpose: 'change_password', operation: 'constructor' }]) {
    const r = await post(C.base, '/api/ott/request', body, u.token);
    assert.equal(r.status, 400, JSON.stringify(body));
    assert.deepEqual(await r.json(), { error: 'Invalid request' });
  }
  const noSim = await startApp({ ENABLE_SIMULATED_OPERATIONS: 'false' });
  const u2 = await makeUser(noSim.base);
  assert.equal((await issueReq(noSim.base, u2.token, 'confirm_email')).status, 400); // simulated op, flag off
  const B = await startApp({ AUTH_MODE: 'B' });
  assert.equal((await post(B.base, '/api/ott/request', { purpose: 'change_password', operation: 'change_password' }, u.token)).status, 404);
  assert.equal((await send(C.base, 'GET', `/api/ott/inbox/${u.id}`, undefined, u.token)).status, 404); // the app has no inbox route
  assert.equal((await send(C.base, 'GET', '/api/ott/request', undefined, u.token)).status, 404);
});

test('issuance: the OTT is only delivered, the call does not wait for delivery, and delivery failures are logged', async () => {
  const poll = async (reason, userId, tries = 150) => {
    let n = 0;
    for (let i = 0; i < tries && !n; i++) { n = await evCount('OTT_DELIVERY_FAILURE', reason, userId); if (!n) await new Promise((x) => setTimeout(x, 30)); }
    return n;
  };
  // A sink that accepts connections but never answers: an awaited delivery would block for the full 2 s timeout.
  const net = require('net');
  const conns = new Set();
  const hang = net.createServer((c) => { conns.add(c); });
  await new Promise((r) => hang.listen(0, '127.0.0.1', r));
  try {
    const slow = await startApp({ OOB_SINK_URL: `http://127.0.0.1:${hang.address().port}` });
    const us = await makeUser(slow.base);
    const t0 = Date.now();
    const rs = await issueReq(slow.base, us.token, 'change_password');
    assert.equal(rs.status, 202);
    assert.ok(Date.now() - t0 < 1000, `issuance waited for delivery (${Date.now() - t0} ms)`);
    assert.equal(await poll('SINK_TIMEOUT', us.id, 200), 1);
  } finally { conns.forEach((c) => c.destroy()); hang.close(); }
  const dead = await startApp({ OOB_SINK_URL: 'http://127.0.0.1:1' });
  const u = await makeUser(dead.base);
  assert.equal((await issueReq(dead.base, u.token, 'change_password')).status, 202);
  assert.equal(await poll('SINK_UNREACHABLE', u.id), 1);
  let n = 0;
  const wrongKey = await startApp({ OOB_SINK_KEY: 'another-deliver-key-1234' });
  const u2 = await makeUser(wrongKey.base);
  assert.equal((await issueReq(wrongKey.base, u2.token, 'change_password')).status, 202);
  n = 0;
  for (let i = 0; i < 100 && !n; i++) { n = await evCount('OTT_DELIVERY_FAILURE', 'SINK_STATUS_401', u2.id); if (!n) await new Promise((x) => setTimeout(x, 30)); }
  assert.equal(n, 1);
  assert.ok(!JSON.stringify(await q('SELECT * FROM security_events')).includes(DELIVER_KEY), 'sink key reached the audit log');
});

// ---------------- T25 / T02 / T09 ----------------
test('T25 (Config C): without OTT 403 -> issue -> change-password with OTT 200; new password works; OTT is used', async () => {
  const u = await makeUser();
  const before = await hashOf(u.id);
  const r0 = await cp(u, {});
  assert.equal(r0.status, 403); assert.deepEqual(await r0.json(), FAIL_BODY);
  assert.equal(await hashOf(u.id), before);
  const ott = await getOtt(u, 'change_password');
  const ok = await cp(u, { ott });
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), { status: 'password_changed' });
  assert.equal((await u.login(NEW_PW)).status, 200);
  assert.equal((await u.login(PW)).status, 401);
  assert.equal(await evCount('SENSITIVE_OPERATION_SUCCESS', null, u.id), 1);
  const [row] = await q('SELECT used_at, superseded_at FROM one_time_tokens WHERE user_id = :id', { id: u.id });
  assert.ok(row.used_at); assert.equal(row.superseded_at, null);
});

test('T02/T09 (Config C): a stolen access JWT cannot change the password and cannot read the OTT', async () => {
  const u = await makeUser();
  const before = await hashOf(u.id);
  const r = await cp(u, {});
  assert.equal(r.status, 403);
  assert.ok(await evCount('OTT_FAILURE', 'MISSING_OTT', u.id) >= 1);
  assert.equal(await hashOf(u.id), before);
  // the attacker holds the app's deliver key at most — which cannot read the inbox
  assert.equal((await fetch(`${sinkBase}/inbox/${u.id}`, { headers: { 'x-sink-key': DELIVER_KEY } })).status, 401);
  assert.equal((await fetch(`${sinkBase}/inbox/${u.id}`)).status, 401);
});

test('invalid newPassword is a 400 before any OTT check and the OTT is not burned', async () => {
  const u = await makeUser();
  const ott = await getOtt(u, 'change_password');
  assert.equal((await cp(u, { ott, newPassword: 'short' })).status, 400);
  assert.equal((await cp(u, { ott })).status, 200);
});

// ---------------- T05-T08, T10 ----------------
test('T05: a used OTT cannot be replayed (ALREADY_USED); attempt_count is incremented', async () => {
  const u = await makeUser();
  const ott = await getOtt(u, 'confirm_email');
  assert.equal((await confirm(u, ott)).status, 200);
  const r = await confirm(u, ott);
  assert.equal(r.status, 403); assert.deepEqual(await r.json(), FAIL_BODY);
  assert.equal(await evCount('OTT_FAILURE', 'ALREADY_USED', u.id), 1);
  const [row] = await q('SELECT attempt_count FROM one_time_tokens WHERE user_id = :id', { id: u.id });
  assert.equal(Number(row.attempt_count), 1);
});

test('T06: an expired OTT is rejected (EXPIRED), judged by DB time', async () => {
  const short = await startApp({ OTT_EXPIRES_IN_SECONDS: '2' });
  const u = await makeUser(short.base);
  const ott = await getOtt(u, 'confirm_email', short.base);
  await new Promise((r) => setTimeout(r, 3000));
  const r = await confirm(u, ott, short.base);
  assert.equal(r.status, 403);
  assert.equal(await evCount('OTT_FAILURE', 'EXPIRED', u.id), 1);
});

test('T07: random, bit-flipped, empty, mistyped and oversized OTTs are all the same 403; nothing is consumed', async () => {
  const u = await makeUser();
  const real = await getOtt(u, 'change_password');
  const flipped = real.slice(0, -1) + (real.endsWith('A') ? 'B' : 'A');
  const cases = [crypto.randomBytes(32).toString('base64url'), flipped, 12345, { a: 1 }, ['x'], 'x'.repeat(300), true];
  const bodies = new Set();
  const before = await hashOf(u.id);
  for (const c of cases) {
    const r = await cp(u, { ott: c });
    assert.equal(r.status, 403, JSON.stringify(c));
    bodies.add(await r.text());
  }
  assert.equal((await cp(u, { ott: '' })).status, 403);
  assert.equal((await cp(u, { ott: null })).status, 403);
  assert.deepEqual([...bodies], [JSON.stringify(FAIL_BODY)]);
  assert.equal(await hashOf(u.id), before);
  assert.ok(await evCount('OTT_FAILURE', 'INVALID_TOKEN', u.id) >= 5);
  assert.ok(await evCount('OTT_FAILURE', 'MISSING_OTT', u.id) >= 2);
  const [row] = await q('SELECT attempt_count, used_at FROM one_time_tokens WHERE user_id = :id', { id: u.id });
  assert.equal(Number(row.attempt_count), 0, 'unmatched tokens must not touch any row');
  assert.equal(row.used_at, null);
  assert.equal((await cp(u, { ott: real })).status, 200); // the genuine OTT still works
});

test('T08: a valid OTT without an access JWT is a 401 and the OTT stays usable', async () => {
  const u = await makeUser();
  const ott = await getOtt(u, 'change_password');
  assert.equal((await post(C.base, '/api/auth/change-password', { newPassword: NEW_PW, ott })).status, 401);
  assert.equal((await cp(u, { ott })).status, 200);
});

test('T10: user B cannot use user A\'s OTT (USER_MISMATCH); A can still use it', async () => {
  const a = await makeUser(); const b = await makeUser();
  const ott = await getOtt(a, 'confirm_email');
  assert.equal((await confirm(b, ott)).status, 403);
  assert.equal(await evCount('OTT_FAILURE', 'USER_MISMATCH', b.id), 1);
  const [row] = await q('SELECT attempt_count FROM one_time_tokens WHERE user_id = :id', { id: a.id });
  assert.equal(Number(row.attempt_count), 1);
  assert.equal((await confirm(a, ott)).status, 200);
});

// ---------------- T11-T14: binding ----------------
test('T11-T13: purpose, endpoint and method mismatches are rejected without consuming the OTT', async () => {
  const u = await makeUser();
  const ott = await getOtt(u, 'confirm_email'); // POST /api/auth/confirm-email, purpose account_security
  assert.equal((await cp(u, { ott })).status, 403);                                                          // T11
  assert.equal(await evCount('OTT_FAILURE', 'PURPOSE_MISMATCH', u.id), 1);
  assert.equal((await post(C.base, '/api/auth/update-security-settings', { ott }, u.token)).status, 403);    // T12
  assert.equal(await evCount('OTT_FAILURE', 'ENDPOINT_MISMATCH', u.id), 1);
  assert.equal((await send(C.base, 'PUT', '/api/auth/confirm-email', { ott }, u.token)).status, 403);        // T13
  assert.equal(await evCount('OTT_FAILURE', 'METHOD_MISMATCH', u.id), 1);
  const [row] = await q('SELECT attempt_count, used_at FROM one_time_tokens WHERE user_id = :id', { id: u.id });
  assert.equal(Number(row.attempt_count), 3); assert.equal(row.used_at, null);
  assert.equal((await confirm(u, ott)).status, 200);                                                         // still valid for its own context
});

test('T14: override headers cannot change the bound context; path variants of the SAME route are the same operation', async () => {
  const u = await makeUser();
  const ott = await getOtt(u, 'confirm_email');
  const spoof = { 'X-HTTP-Method-Override': 'POST', 'X-Method-Override': 'POST', 'X-Original-URL': '/api/auth/confirm-email',
    'X-Rewrite-URL': '/api/auth/confirm-email', 'X-Forwarded-Prefix': '/api/auth', 'X-Forwarded-Path': '/api/auth/confirm-email' };
  assert.equal((await send(C.base, 'PUT', '/api/auth/confirm-email', { ott }, u.token, spoof)).status, 403);
  assert.equal(await evCount('OTT_FAILURE', 'METHOD_MISMATCH', u.id), 1);
  assert.equal((await post(C.base, '/api/auth/update-security-settings', { ott }, u.token, spoof)).status, 403);
  assert.equal(await evCount('OTT_FAILURE', 'ENDPOINT_MISMATCH', u.id), 1);
  // Trailing slash and case resolve to the same registered route: same operation, NOT a bypass (it needs the right OTT once).
  assert.equal((await post(C.base, '/api/auth/confirm-email/', { ott }, u.token)).status, 200);
  assert.equal((await post(C.base, '/api/auth/confirm-email/', { ott }, u.token)).status, 403);
  const ott2 = await getOtt(u, 'confirm_email');
  assert.equal((await post(C.base, '/API/AUTH/CONFIRM-EMAIL', { ott: ott2 }, u.token)).status, 200);
});

// ---------------- T19: superseded ----------------
test('T19: re-issuing supersedes the earlier OTT (SUPERSEDED); the newer one works', async () => {
  const u = await makeUser();
  const first = await getOtt(u, 'change_password');
  const second = await getOtt(u, 'change_password');
  assert.notEqual(first, second);
  assert.equal((await cp(u, { ott: first })).status, 403);
  assert.equal(await evCount('OTT_FAILURE', 'SUPERSEDED', u.id), 1);
  assert.equal((await cp(u, { ott: second })).status, 200);
});

// ---------------- T15-T17: concurrent consumption ----------------
for (const n of [2, 20, 50]) {
  test(`T15-T17: ${n} parallel uses of one OTT -> exactly one 200, no 5xx (5 reps, confirm-email)`, async () => {
    for (let rep = 0; rep < 5; rep++) {
      const u = await makeUser();
      const ott = await getOtt(u, 'confirm_email');
      const res = await Promise.all(Array.from({ length: n }, () => confirm(u, ott)));
      const statuses = res.map((r) => r.status);
      assert.equal(statuses.filter((s) => s === 200).length, 1, statuses.join(','));
      assert.ok(statuses.every((s) => s === 200 || s === 403), `unexpected: ${statuses.join(',')}`);
      assert.equal(await evCount('SENSITIVE_OPERATION_SUCCESS', null, u.id), 1);
      const states = await ottMod.countStates(sequelize, { userId: u.id, ...(({ purpose, method, endpoint }) => ({ purpose, method, endpoint }))(OPERATIONS.confirm_email) });
      assert.equal(states.used, 1);
    }
  });
}

test('T16 with the real password write: 20 parallel change-password with one OTT -> one 200, password changed once', async () => {
  for (let rep = 0; rep < 3; rep++) {
    const u = await makeUser();
    const ott = await getOtt(u, 'change_password');
    const res = await Promise.all(Array.from({ length: 20 }, () => cp(u, { ott })));
    const statuses = res.map((r) => r.status);
    assert.equal(statuses.filter((s) => s === 200).length, 1, statuses.join(','));
    assert.ok(statuses.every((s) => s === 200 || s === 403), statuses.join(','));
    assert.equal(await evCount('SENSITIVE_OPERATION_SUCCESS', null, u.id), 1);
    assert.equal((await u.login(NEW_PW)).status, 200);
  }
});

// ---------------- T27: concurrent issuance ----------------
test('T27: 20 parallel issuance requests -> exactly one active OTT, 19 superseded, only the active one is usable', async () => {
  const u = await makeUser();
  const res = await Promise.all(Array.from({ length: 20 }, () => issueReq(C.base, u.token, 'change_password')));
  assert.ok(res.every((r) => r.status === 202), res.map((r) => r.status).join(','));
  const msgs = await inbox.waitFor(u.id, 20, 5000);
  const op = OPERATIONS.change_password;
  const s = await ottMod.countStates(sequelize, { userId: u.id, purpose: op.purpose, method: op.method, endpoint: op.endpoint });
  assert.deepEqual(s, { total: 20, used: 0, superseded: 19, expired: 0, active: 1, bothFlags: 0 });
  const statuses = [];
  for (const m of msgs) statuses.push((await cp(u, { ott: m.token })).status);
  assert.equal(statuses.filter((x) => x === 200).length, 1, statuses.join(','));
  assert.equal(await evCount('OTT_FAILURE', 'SUPERSEDED', u.id), 19);
});

// ---------------- rate limits (T18, T20) ----------------
test('T20 (standard): 20 issuance calls in a minute -> first 5 are 202, then 429; only 5 OTTs exist; logged once', async () => {
  const RL = await startApp({ RATE_LIMIT_PROFILE: 'standard' });
  const u = await makeUser(RL.base);
  const statuses = [];
  for (let i = 0; i < 20; i++) statuses.push((await issueReq(RL.base, u.token, 'change_password')).status);
  assert.deepEqual(statuses, [...Array(5).fill(202), ...Array(15).fill(429)]);
  assert.equal(await evCount('RATE_LIMITED', 'ottIssue', u.id), 1);
  assert.equal(Number((await q('SELECT COUNT(*) AS n FROM one_time_tokens WHERE user_id = :id', { id: u.id }))[0].n), 5);
  await inbox.readAll(u.id);
});

test('T18 (standard): 100 invalid-OTT attempts -> 403 until the per-user limit (10/min), then 429; logged once', async () => {
  const RL = await startApp({ RATE_LIMIT_PROFILE: 'standard' });
  const u = await makeUser(RL.base);
  const statuses = [];
  for (let i = 0; i < 100; i++) statuses.push((await cp(u, { ott: crypto.randomBytes(32).toString('base64url') }, RL.base)).status);
  assert.deepEqual(statuses, [...Array(10).fill(403), ...Array(90).fill(429)]);
  assert.equal(await evCount('RATE_LIMITED', 'sensitiveUser', u.id), 1);
  assert.equal(await evCount('OTT_FAILURE', 'INVALID_TOKEN', u.id), 10);
});

// ---------------- DB_LOCK_ERROR ----------------
test('a lock/deadlock error during consumption is a 500, is NOT retried, and is logged as DB_LOCK_ERROR', async () => {
  const u = await makeUser();
  const ott = await getOtt(u, 'confirm_email');
  const orig = ottMod.consumeOtt;
  let calls = 0;
  ottMod.consumeOtt = async () => { calls += 1; const e = new Error('x'); e.code = 'DB_LOCK_ERROR'; e.errno = 1213; throw e; };
  try {
    const r = await confirm(u, ott);
    assert.equal(r.status, 500);
    assert.deepEqual(await r.json(), { error: 'Internal server error' });
  } finally { ottMod.consumeOtt = orig; }
  assert.equal(calls, 1, 'must not retry');
  assert.equal(await evCount('DB_LOCK_ERROR', '1213', u.id), 1);
  assert.equal((await confirm(u, ott)).status, 200); // OTT untouched by the failed attempt
});

// ---------------- no raw OTT anywhere ----------------
test('no raw OTT or key material exists in any stored table or audit event', async () => {
  assert.ok(inbox.seen.size > 30, 'expected the harness to have read many OTTs');
  const dump = JSON.stringify({
    events: await q('SELECT * FROM security_events'), users: await q('SELECT * FROM users'),
    refresh: await q('SELECT * FROM refresh_tokens'), revoked: await q('SELECT * FROM revoked_tokens'),
    otts: await q('SELECT * FROM one_time_tokens'),
  });
  for (const t of inbox.seen) assert.ok(!dump.includes(t), 'a raw OTT was found in the database');
  assert.ok(!dump.includes(DELIVER_KEY) && !dump.includes(READ_KEY));
});
