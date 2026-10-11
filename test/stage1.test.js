'use strict';
// Stage 1 development tests (database layer). These are NOT experiment results: they check that the
// schema, transactions and test harness behave as EXPERIMENTS.md v1.3 specifies before Stage 2.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { QueryTypes } = require('sequelize');
const { resetDb } = require('../scripts/resetDb');
const sequelize = require('../src/config/db');
const ott = require('../src/db/ottTransactions');

const OP = { purpose: 'account_security', method: 'POST', endpoint: '/api/auth/confirm-email' };
let seq = 0;

async function createUser() {
  const email = `u${Date.now()}_${seq++}@example.test`;
  const res = await sequelize.query(
    "INSERT INTO users (email, password_hash) VALUES (:email, 'x')",
    { replacements: { email }, type: QueryTypes.INSERT }
  );
  return res[0];
}
const q = (sql, replacements = {}) => sequelize.query(sql, { replacements, type: QueryTypes.SELECT });
const markApplied = (userId) => (t) => ott.logEvent(sequelize, { userId, eventType: 'TEST_OP_APPLIED' }, t);
const appliedCount = async (userId) =>
  Number((await q("SELECT COUNT(*) AS n FROM security_events WHERE user_id = :userId AND event_type = 'TEST_OP_APPLIED'", { userId }))[0].n);

before(async () => { await resetDb(); });
after(async () => { await sequelize.close(); });

test('schema: CHECK rejects a row that is both used and superseded', async () => {
  const userId = await createUser();
  await assert.rejects(
    sequelize.query(
      `INSERT INTO one_time_tokens (user_id, token_hash, purpose, method, endpoint, context_hash, expires_at, used_at, superseded_at)
       VALUES (:userId, :h, 'p', 'POST', '/e', :h, NOW(3), NOW(3), NOW(3))`,
      { replacements: { userId, h: 'a'.repeat(64) }, type: QueryTypes.INSERT }
    ),
    (e) => /chk_ott_not_used_and_superseded|check constraint/i.test(String(e.message + (e.original ? e.original.message : '')))
  );
});

test('issueOtt: stores only the hash; re-issue supersedes the previous OTT', async () => {
  const userId = await createUser();
  const a = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
  const b = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
  assert.equal(a.supersededCount, 0);
  assert.equal(b.supersededCount, 1);
  const raw = await q("SELECT COUNT(*) AS n FROM one_time_tokens WHERE token_hash = :r", { r: a.rawToken });
  assert.equal(Number(raw[0].n), 0, 'raw OTT must not be stored');
  const hashed = await q("SELECT COUNT(*) AS n FROM one_time_tokens WHERE token_hash = :h", { h: ott.sha256(a.rawToken) });
  assert.equal(Number(hashed[0].n), 1);
  const states = await ott.countStates(sequelize, { userId, ...OP });
  assert.deepEqual(states, { total: 2, used: 0, superseded: 1, expired: 0, active: 1, bothFlags: 0 });
});

test('checkBinding: reasons come back in the frozen order', async () => {
  const userId = await createUser();
  const { rawToken } = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
  const row = await ott.lookupOtt(sequelize, rawToken);
  const ctx = { userId, ...OP };
  assert.equal(ott.checkBinding(row, ctx), null);
  assert.equal(ott.checkBinding(row, { ...ctx, userId: userId + 999 }), 'USER_MISMATCH');
  assert.equal(ott.checkBinding(row, { ...ctx, purpose: 'change_password', endpoint: '/other' }), 'PURPOSE_MISMATCH');
  assert.equal(ott.checkBinding(row, { ...ctx, method: 'PUT' }), 'METHOD_MISMATCH');
  assert.equal(ott.checkBinding(row, { ...ctx, endpoint: '/api/auth/update-security-settings' }), 'ENDPOINT_MISMATCH');
  assert.equal(ott.checkBinding({ ...row, context_hash: 'f'.repeat(64) }, ctx), 'CONTEXT_MISMATCH');
  assert.equal(ott.checkBinding({ ...row, is_expired: 1, used_at: new Date() }, ctx), 'EXPIRED');
  assert.equal(ott.checkBinding({ ...row, used_at: new Date() }, ctx), 'ALREADY_USED');
  assert.equal(ott.checkBinding({ ...row, superseded_at: new Date() }, ctx), 'SUPERSEDED');
});

test('expiry uses DB time; an expired OTT is not consumable', async () => {
  const userId = await createUser();
  const { id, rawToken } = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 1 });
  await new Promise((r) => setTimeout(r, 1300));
  const row = await ott.lookupOtt(sequelize, rawToken);
  assert.equal(ott.checkBinding(row, { userId, ...OP }), 'EXPIRED');
  const res = await ott.consumeOtt(sequelize, { ottId: id, userId, operation: markApplied(userId) });
  assert.equal(res.consumed, false);
  assert.equal(await appliedCount(userId), 0);
});

test('consume: succeeds once, operation applied once, second attempt rejected', async () => {
  const userId = await createUser();
  const { id } = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
  const first = await ott.consumeOtt(sequelize, { ottId: id, userId, operation: markApplied(userId) });
  const second = await ott.consumeOtt(sequelize, { ottId: id, userId, operation: markApplied(userId) });
  assert.equal(first.consumed, true);
  assert.equal(second.consumed, false);
  assert.equal(await appliedCount(userId), 1);
  const states = await ott.countStates(sequelize, { userId, ...OP });
  assert.equal(states.used, 1);
});

test('consume: a failing operation rolls back and does NOT burn the OTT', async () => {
  const userId = await createUser();
  const { id } = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
  await assert.rejects(
    ott.consumeOtt(sequelize, { ottId: id, userId, operation: async () => { throw new Error('boom'); } }),
    /boom/
  );
  const states = await ott.countStates(sequelize, { userId, ...OP });
  assert.equal(states.used, 0);
  assert.equal(states.active, 1);
  const retry = await ott.consumeOtt(sequelize, { ottId: id, userId, operation: markApplied(userId) });
  assert.equal(retry.consumed, true);
});

test('consume: a superseded OTT cannot be consumed; the newer one can', async () => {
  const userId = await createUser();
  const a = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
  const b = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
  assert.equal((await ott.consumeOtt(sequelize, { ottId: a.id, userId, operation: markApplied(userId) })).consumed, false);
  assert.equal((await ott.consumeOtt(sequelize, { ottId: b.id, userId, operation: markApplied(userId) })).consumed, true);
});

test('recordFailedAttempt increments attempt_count outside any transaction', async () => {
  const userId = await createUser();
  const { id } = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
  await ott.recordFailedAttempt(sequelize, id);
  await ott.recordFailedAttempt(sequelize, id);
  const [r] = await q('SELECT attempt_count FROM one_time_tokens WHERE id = :id', { id });
  assert.equal(Number(r.attempt_count), 2);
});

test('T27-style: 20 parallel issuances leave exactly one active OTT (k-1 superseded)', async () => {
  for (let rep = 0; rep < 10; rep++) {
    const userId = await createUser();
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, () => ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 }))
    );
    const ok = results.filter((r) => r.status === 'fulfilled');
    const failed = results.filter((r) => r.status === 'rejected');
    assert.equal(failed.length, 0, `unexpected failures: ${failed.map((f) => f.reason.message).join('; ')}`);
    const s = await ott.countStates(sequelize, { userId, ...OP });
    assert.equal(s.active, 1);
    assert.equal(s.superseded, ok.length - 1);
    assert.equal(s.used, 0);
    assert.equal(s.expired, 0);
    assert.equal(s.total, ok.length);
    assert.equal(s.bothFlags, 0);
  }
});

for (const n of [2, 20, 50]) {
  test(`T15-T17-style: ${n} parallel consumptions of one OTT -> exactly one success (30 reps)`, async () => {
    for (let rep = 0; rep < 30; rep++) {
      const userId = await createUser();
      const { id } = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
      const results = await Promise.allSettled(
        Array.from({ length: n }, () => ott.consumeOtt(sequelize, { ottId: id, userId, operation: markApplied(userId) }))
      );
      const errors = results.filter((r) => r.status === 'rejected');
      assert.equal(errors.length, 0, `errors: ${errors.map((e) => e.reason.code || e.reason.message).join('; ')}`);
      const successes = results.filter((r) => r.value.consumed).length;
      assert.equal(successes, 1);
      assert.equal(await appliedCount(userId), 1);
    }
  });
}

// The real operation updates the users row (password change), which is what makes lock order matter.
const updateUserAndMark = (userId) => async (t) => {
  await sequelize.query('UPDATE users SET password_hash = :h, password_changed_at = NOW(3) WHERE id = :userId',
    { replacements: { h: 'y', userId }, type: QueryTypes.UPDATE, transaction: t });
  await ott.logEvent(sequelize, { userId, eventType: 'TEST_OP_APPLIED' }, t);
};

test('lock order: concurrent issue + consume on one user never deadlock (100 reps)', async () => {
  let lockErrors = 0;
  for (let rep = 0; rep < 100; rep++) {
    const userId = await createUser();
    const { id } = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
    const results = await Promise.allSettled([
      ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 }),
      ott.consumeOtt(sequelize, { ottId: id, userId, operation: updateUserAndMark(userId) }),
      ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 }),
      ott.consumeOtt(sequelize, { ottId: id, userId, operation: updateUserAndMark(userId) }),
    ]);
    lockErrors += results.filter((r) => r.status === 'rejected' && r.reason.code === 'DB_LOCK_ERROR').length;
    const s = await ott.countStates(sequelize, { userId, ...OP });
    assert.equal(s.active <= 1, true);
    assert.equal(s.bothFlags, 0);
  }
  assert.equal(lockErrors, 0, 'DB_LOCK_ERROR observed');
});

test('negative control: the unsafe non-atomic consume IS detected by the concurrency harness', async () => {
  process.env.UNSAFE_NON_ATOMIC_CONSUME = 'true';
  process.env.UNSAFE_DELAY_MS = '20';
  try {
    let violations = 0;
    for (let rep = 0; rep < 20; rep++) {
      const userId = await createUser();
      const { id } = await ott.issueOtt(sequelize, { userId, ...OP, ttlSeconds: 300 });
      const results = await Promise.all(
        Array.from({ length: 20 }, () => ott.consumeOtt(sequelize, { ottId: id, userId, operation: markApplied(userId) }))
      );
      if (results.filter((r) => r.consumed).length > 1) violations++;
    }
    assert.ok(violations > 0, 'harness could not detect the deliberately unsafe variant: it lacks power');
  } finally {
    delete process.env.UNSAFE_NON_ATOMIC_CONSUME;
    delete process.env.UNSAFE_DELAY_MS;
  }
});

test('UNSAFE flag is refused outside APP_PROFILE=test', async () => {
  const saved = process.env.APP_PROFILE;
  process.env.APP_PROFILE = 'development';
  process.env.UNSAFE_NON_ATOMIC_CONSUME = 'true';
  try {
    await assert.rejects(ott.consumeOtt(sequelize, { ottId: 1, userId: 1, operation: async () => {} }), /APP_PROFILE=test/);
  } finally {
    process.env.APP_PROFILE = saved;
    delete process.env.UNSAFE_NON_ATOMIC_CONSUME;
  }
});
