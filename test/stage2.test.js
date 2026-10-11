'use strict';
// Stage 2 development tests: config loader, JWT service, revocation, authenticateAccessToken.
// NOT experiment results. They check the middleware behaves as EXPERIMENTS.md v1.3 requires
// (T01, T21-T24 at middleware level) before Stage 3 builds on it.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { QueryTypes } = require('sequelize');
const { resetDb } = require('../scripts/resetDb');
const sequelize = require('../src/config/db');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');
const { createTokenService, TokenError } = require('../src/services/tokenService');
const { revokeAccessToken, purgeExpiredRevocations } = require('../src/services/revocation');

const ACCESS_SECRET = 'test-access-secret-0123456789-abcdefghij';
const REFRESH_SECRET = 'test-refresh-secret-9876543210-jihgfedcba';
const ENV = { APP_PROFILE: 'test', AUTH_MODE: 'B', RATE_LIMIT_PROFILE: 'off',
  JWT_ACCESS_SECRET: ACCESS_SECRET, JWT_REFRESH_SECRET: REFRESH_SECRET };

const b64u = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const hmac = (secret, data, algo = 'sha256') => crypto.createHmac(algo, secret).update(data).digest('base64url');
const nowS = () => Math.floor(Date.now() / 1000);

let config, app, server, base, userId, otherUserId;

const q = (sql, replacements = {}) => sequelize.query(sql, { replacements, type: QueryTypes.SELECT });
async function createUser(email) {
  const r = await sequelize.query("INSERT INTO users (email, password_hash) VALUES (:email, 'x')",
    { replacements: { email }, type: QueryTypes.INSERT });
  return r[0];
}
const claims = (over = {}) => ({
  type: 'access', sub: String(userId), jti: crypto.randomUUID(),
  iss: 'ott-study-auth', aud: 'ott-study-api', iat: nowS(), exp: nowS() + 900, ...over,
});
function signHs256(payload, secret = ACCESS_SECRET, header = { alg: 'HS256', typ: 'JWT' }) {
  const h = b64u(header); const p = b64u(payload);
  return `${h}.${p}.${hmac(secret, `${h}.${p}`)}`;
}
const listen = (a) => new Promise((resolve) => {
  const s = a.listen(0, '127.0.0.1', () => resolve(s));
  s.sockets = new Set();
  s.on('connection', (c) => { s.sockets.add(c); c.on('close', () => s.sockets.delete(c)); });
});
const get = (path, authValue, baseUrl = base) =>
  fetch(baseUrl + path, { headers: authValue === undefined ? {} : { Authorization: authValue } });
const bearer = (t) => `Bearer ${t}`;
const eventCount = async (reason) =>
  Number((await q("SELECT COUNT(*) AS n FROM security_events WHERE event_type = 'AUTH_FAILURE' AND reason = :reason", { reason }))[0].n);

before(async () => {
  await resetDb();
  config = loadConfig(ENV);
  app = createApp({ sequelize, config });
  server = await listen(app);
  base = `http://127.0.0.1:${server.address().port}`;
  userId = await createUser('a@example.test');
  otherUserId = await createUser('b@example.test');
});
after(async () => {
  server.sockets.forEach((c) => c.destroy());
  await new Promise((r) => server.close(r));
  await sequelize.close();
});

// ---------- configuration ----------
test('config: valid environment loads and frozen values are fixed', () => {
  const c = loadConfig(ENV);
  assert.equal(c.jwt.algorithm, 'HS256');
  assert.equal(c.jwt.accessTtlSeconds, 900);
  assert.equal(c.jwt.refreshTtlSeconds, 604800);
  assert.equal(c.ottTtlSeconds, 300);
  assert.equal(c.bcryptCost, 12);
  assert.throws(() => { c.bcryptCost = 4; }, TypeError); // frozen object
});

test('config: invalid or forbidden settings are rejected', () => {
  const bad = (over, re) => assert.throws(() => loadConfig({ ...ENV, ...over }), re);
  bad({ AUTH_MODE: 'Z' }, /AUTH_MODE/);
  bad({ AUTH_MODE: undefined }, /AUTH_MODE/);
  bad({ RATE_LIMIT_PROFILE: 'wild' }, /RATE_LIMIT_PROFILE/);
  bad({ JWT_ACCESS_SECRET: 'short' }, /JWT_ACCESS_SECRET/);
  bad({ JWT_REFRESH_SECRET: ACCESS_SECRET }, /must differ/);
  bad({ OTT_EXPIRES_IN_SECONDS: '0' }, /positive integer/);
  bad({ APP_PROFILE: 'development', UV_THREADPOOL_SIZE: '16', OTT_EXPIRES_IN_SECONDS: '2' }, /APP_PROFILE=test/);
  bad({ APP_PROFILE: 'development', UV_THREADPOOL_SIZE: '16', UNSAFE_NON_ATOMIC_CONSUME: 'true' }, /UNSAFE/);
  bad({ APP_PROFILE: 'development', UV_THREADPOOL_SIZE: '4' }, /UV_THREADPOOL_SIZE/);
  assert.equal(loadConfig({ ...ENV, OTT_EXPIRES_IN_SECONDS: '2' }).ottTtlSeconds, 2); // allowed in test profile
});

test('config: error messages never contain secret values', () => {
  try { loadConfig({ ...ENV, JWT_ACCESS_SECRET: 'short-secret-value' }); assert.fail('should throw'); }
  catch (e) { assert.ok(!e.message.includes('short-secret-value')); }
});

// ---------- token service ----------
test('tokenService: round-trip and strict type separation', () => {
  const ts = createTokenService(config);
  const a = ts.signAccess(userId); const r = ts.signRefresh(userId);
  const ac = ts.verifyAccess(a.token);
  assert.equal(ac.userId, String(userId)); assert.equal(ac.jti, a.jti);
  assert.equal(ts.verifyRefresh(r.token).jti, r.jti);
  assert.throws(() => ts.verifyAccess(r.token), (e) => e instanceof TokenError && e.reason === 'TOKEN_INVALID');
  assert.throws(() => ts.verifyRefresh(a.token), (e) => e instanceof TokenError && e.reason === 'TOKEN_INVALID');
});

// ---------- middleware: T01 boundary + header parsing ----------
test('T01: a valid access JWT reaches an ordinary protected endpoint; no secrets in the body', async () => {
  const { token } = app.locals.tokenService.signAccess(userId);
  const res = await get('/api/profile', bearer(token));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.email, 'a@example.test');
  assert.ok(!('password_hash' in body) && !('passwordHash' in body));
});

test('security headers present; x-powered-by absent; unknown route 404; bad JSON 400', async () => {
  const res = await get('/api/health');
  assert.equal(res.headers.get('x-powered-by'), null);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal((await get('/api/nope')).status, 404);
  const bad = await fetch(`${base}/api/health`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{oops' });
  assert.equal(bad.status, 400);
  assert.deepEqual(await bad.json(), { error: 'Malformed request body' });
});

test('header parsing: scheme is case-insensitive; malformed headers are rejected', async () => {
  const { token } = app.locals.tokenService.signAccess(userId);
  assert.equal((await get('/api/profile', `bearer ${token}`)).status, 200);
  for (const v of [undefined, '', 'Bearer', 'Bearer ', `Basic ${token}`, `Bearer  ${token}`, `Bearer ${token} extra`, token, 'Bearer a.b']) {
    const res = await get('/api/profile', v);
    assert.equal(res.status, 401, `header ${JSON.stringify(v)}`);
  }
});

// ---------- T21: tampering ----------
test('T21: modified claims without re-signing, and a wrong secret, are rejected', async () => {
  const base0 = claims();
  const good = signHs256(base0);
  const [h, p, s] = good.split('.');
  const swap = (over) => `${h}.${b64u({ ...base0, ...over })}.${s}`;
  for (const over of [{ sub: String(otherUserId) }, { exp: nowS() + 999999 }, { type: 'refresh' }, { jti: crypto.randomUUID() }]) {
    assert.equal((await get('/api/profile', bearer(swap(over)))).status, 401, JSON.stringify(over));
  }
  assert.equal((await get('/api/profile', bearer(signHs256(claims(), 'x'.repeat(40))))).status, 401);
  assert.equal((await get('/api/profile', bearer(`${h}.${p}.${s.slice(0, -2)}AA`))).status, 401);
});

// ---------- T22: algorithm manipulation ----------
test('T22: alg none, other HS algorithms and RS256 key confusion are rejected', async () => {
  const c = claims();
  const none = (sig) => `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u(c)}.${sig}`;
  assert.equal((await get('/api/profile', bearer(none('')))).status, 401);
  assert.equal((await get('/api/profile', bearer(none('AAAA')))).status, 401);
  const h384 = b64u({ alg: 'HS384', typ: 'JWT' }); const p = b64u(c);
  assert.equal((await get('/api/profile', bearer(`${h384}.${p}.${hmac(ACCESS_SECRET, `${h384}.${p}`, 'sha384')}`))).status, 401);
  const rs = b64u({ alg: 'RS256', typ: 'JWT' });
  assert.equal((await get('/api/profile', bearer(`${rs}.${p}.${hmac(ACCESS_SECRET, `${rs}.${p}`)}`))).status, 401);
});

// ---------- T23: claim validation ----------
test('T23: expired, not-yet-valid, wrong iss/aud/type and missing/odd claims are rejected', async () => {
  const cases = {
    expired: claims({ iat: nowS() - 2000, exp: nowS() - 1000 }),
    futureNbf: claims({ nbf: nowS() + 3600 }),
    wrongIss: claims({ iss: 'someone-else' }),
    wrongAud: claims({ aud: 'another-api' }),
    wrongType: claims({ type: 'refresh' }),
    missingExp: claims({ exp: undefined }),
    missingIat: claims({ iat: undefined }),
    missingJti: claims({ jti: undefined }),
    badJti: claims({ jti: 'not-a-uuid' }),
    missingSub: claims({ sub: undefined }),
    nonNumericSub: claims({ sub: 'admin' }),
    missingType: claims({ type: undefined }),
  };
  for (const [name, c] of Object.entries(cases)) {
    const res = await get('/api/profile', bearer(signHs256(c)));
    assert.equal(res.status, 401, name);
  }
  // A refresh token (signed with the refresh secret) must not work as an access token.
  const { token: refresh } = app.locals.tokenService.signRefresh(userId);
  assert.equal((await get('/api/profile', bearer(refresh))).status, 401);
});

// ---------- T24 (middleware part): revocation ----------
test('T24: a revoked jti is rejected immediately; the same token worked before', async () => {
  const { token, jti, exp } = app.locals.tokenService.signAccess(userId);
  assert.equal((await get('/api/profile', bearer(token))).status, 200);
  await revokeAccessToken(sequelize, { jti, userId, exp });
  await revokeAccessToken(sequelize, { jti, userId, exp }); // idempotent
  assert.equal((await get('/api/profile', bearer(token))).status, 401);
  assert.equal(await eventCount('TOKEN_REVOKED') >= 1, true);
});

test('revocation: purge removes only rows whose token has already expired', async () => {
  const live = app.locals.tokenService.signAccess(userId);
  await revokeAccessToken(sequelize, { jti: live.jti, userId, exp: live.exp });
  const deadJti = crypto.randomUUID();
  await revokeAccessToken(sequelize, { jti: deadJti, userId, exp: nowS() - 10 });
  const purged = await purgeExpiredRevocations(sequelize);
  assert.ok(purged >= 1);
  assert.equal((await q('SELECT COUNT(*) AS n FROM revoked_tokens WHERE jti = :j', { j: deadJti }))[0].n, 0);
  assert.equal(Number((await q('SELECT COUNT(*) AS n FROM revoked_tokens WHERE jti = :j', { j: live.jti }))[0].n), 1);
});

// ---------- uniform 401 + logging ----------
test('every authentication failure returns the same generic 401 body', async () => {
  const bodies = new Set();
  const tokens = [undefined, 'Bearer a.b.c', bearer(signHs256(claims({ exp: nowS() - 5, iat: nowS() - 50 }))),
    bearer(signHs256(claims(), 'y'.repeat(40))), bearer(signHs256(claims({ type: 'refresh' })))];
  for (const t of tokens) {
    const res = await get('/api/profile', t);
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('www-authenticate'), 'Bearer');
    bodies.add(JSON.stringify(await res.json()));
  }
  assert.deepEqual([...bodies], ['{"error":"Authentication failed"}']);
});

test('failures are logged with internal reasons, and tokens never reach the log', async () => {
  const marker = signHs256(claims(), 'z'.repeat(40)); // invalid signature
  await get('/api/profile', bearer(marker));
  await get('/api/profile');
  await get('/api/profile', 'Bearer a.b');
  await get('/api/profile', bearer(signHs256(claims({ exp: nowS() - 5, iat: nowS() - 50 }))));
  await get('/api/profile', bearer(signHs256(claims({ nbf: nowS() + 3600 }))));
  await get('/api/profile', bearer(signHs256(claims({ type: 'refresh' }))));
  await get('/api/profile', bearer(signHs256(claims({ jti: undefined }))));
  for (const r of ['TOKEN_INVALID', 'MISSING_AUTH_HEADER', 'MALFORMED_AUTH_HEADER', 'TOKEN_EXPIRED',
    'TOKEN_NOT_YET_VALID', 'TOKEN_WRONG_TYPE', 'TOKEN_CLAIMS_INVALID']) {
    assert.ok(await eventCount(r) >= 1, `no AUTH_FAILURE event for ${r}`);
  }
  const frag = marker.split('.')[1].slice(5, 40);
  const rows = await q('SELECT event_type, reason, endpoint, ip, details FROM security_events');
  assert.ok(rows.length > 0);
  assert.ok(!JSON.stringify(rows).includes(frag), 'token material found in security_events');
});

// ---------- fail closed ----------
test('fails closed: if the revocation lookup fails the request is a 500, not authenticated', async () => {
  // Only the revocation lookup fails; the profile query would succeed. A middleware that fails
  // OPEN would therefore return 200 here, so this test can tell the two behaviours apart.
  const stub = { query: async (sql) => {
    if (/revoked_tokens/.test(sql)) throw new Error('db down');
    return [{ id: userId, email: 'a@example.test', created_at: new Date() }];
  } };
  const a2 = createApp({ sequelize: stub, config });
  const s2 = await listen(a2);
  try {
    const { token } = a2.locals.tokenService.signAccess(userId);
    const res = await get('/api/profile', bearer(token), `http://127.0.0.1:${s2.address().port}`);
    assert.equal(res.status, 500);
    assert.deepEqual(await res.json(), { error: 'Internal server error' });
  } finally {
    await new Promise((r) => { s2.close(r); s2.sockets.forEach((c) => c.destroy()); });
  }
});

test('a validly signed token for a user that does not exist is rejected', async () => {
  const ghost = signHs256(claims({ sub: '999999' }));
  assert.equal((await get('/api/profile', bearer(ghost))).status, 401);
});
