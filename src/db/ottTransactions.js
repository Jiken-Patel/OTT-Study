'use strict';
// OTT issuance and consumption (EXPERIMENTS.md 7.3 / 7.4). Raw SQL on purpose: the exact
// statements, lock order and isolation level are research variables.
//
// Lock order everywhere: users -> one_time_tokens. Isolation: READ COMMITTED.
// Lock-wait (1205) and deadlock (1213) errors are NOT retried; they surface as DB_LOCK_ERROR.

const crypto = require('crypto');
const { Transaction, QueryTypes } = require('sequelize');

const RC = Transaction.ISOLATION_LEVELS.READ_COMMITTED;
const sha256 = (v) => crypto.createHash('sha256').update(v).digest('hex');

const contextHash = ({ userId, purpose, method, endpoint }) =>
  sha256(`${userId}|${purpose}|${String(method).toUpperCase()}|${endpoint}`);

class ConsumeRejected extends Error {}

function wrapLockError(e) {
  const errno = e && ((e.original && e.original.errno) || (e.parent && e.parent.errno));
  if (errno === 1205 || errno === 1213) {
    const err = new Error(`database lock error (${errno})`);
    err.code = 'DB_LOCK_ERROR';
    err.errno = errno;
    return err;
  }
  return e;
}

// Sequelize returns different shapes for UPDATE depending on query type; normalise here.
const affectedRows = (res) => (Array.isArray(res) ? res[1] : res);

async function lockUserRow(sequelize, userId, t) {
  const rows = await sequelize.query('SELECT id FROM users WHERE id = :userId FOR UPDATE', {
    replacements: { userId },
    type: QueryTypes.SELECT,
    transaction: t,
  });
  return rows.length === 1;
}

/**
 * Issue an OTT (7.3). Serialised per user by the users-row lock; supersedes any earlier
 * active OTT for the same (user, purpose, method, endpoint) in the same transaction.
 * Returns the RAW token once; the caller hands it to the OOB sink after commit. Only its
 * SHA-256 hash is stored.
 */
async function issueOtt(sequelize, { userId, purpose, method, endpoint, ttlSeconds }) {
  const rawToken = crypto.randomBytes(32).toString('base64url');
  const m = String(method).toUpperCase();
  const replacements = {
    userId, purpose, method: m, endpoint, ttl: ttlSeconds,
    tokenHash: sha256(rawToken),
    ctx: contextHash({ userId, purpose, method: m, endpoint }),
  };
  try {
    const out = await sequelize.transaction({ isolationLevel: RC }, async (t) => {
      if (!(await lockUserRow(sequelize, userId, t))) {
        const err = new Error('user not found');
        err.code = 'USER_NOT_FOUND';
        throw err;
      }
      const upd = await sequelize.query(
        `UPDATE one_time_tokens SET superseded_at = NOW(3)
          WHERE user_id = :userId AND purpose = :purpose AND method = :method AND endpoint = :endpoint
            AND used_at IS NULL AND superseded_at IS NULL`,
        { replacements, type: QueryTypes.UPDATE, transaction: t }
      );
      const ins = await sequelize.query(
        `INSERT INTO one_time_tokens
           (user_id, token_hash, purpose, method, endpoint, context_hash, expires_at)
         VALUES (:userId, :tokenHash, :purpose, :method, :endpoint, :ctx,
                 DATE_ADD(NOW(3), INTERVAL :ttl SECOND))`,
        { replacements, type: QueryTypes.INSERT, transaction: t }
      );
      return { id: Array.isArray(ins) ? ins[0] : ins, supersededCount: affectedRows(upd) };
    });
    return { id: out.id, rawToken, supersededCount: out.supersededCount };
  } catch (e) {
    throw wrapLockError(e);
  }
}

/** Cheap read-only lookup by the hash of the submitted OTT (7.4 step 3). Returns null if unknown. */
async function lookupOtt(sequelize, rawToken) {
  const rows = await sequelize.query(
    `SELECT id, user_id, purpose, method, endpoint, context_hash, used_at, superseded_at,
            expires_at, attempt_count, (expires_at <= NOW(3)) AS is_expired
       FROM one_time_tokens WHERE token_hash = :h`,
    { replacements: { h: sha256(String(rawToken)) }, type: QueryTypes.SELECT }
  );
  return rows[0] || null;
}

/**
 * Pure check in the frozen order (7.4): user -> purpose -> method -> endpoint -> context_hash
 * -> expiry -> used -> superseded. Returns the first failing internal reason, or null.
 * `ctx` is derived by the server from the actual request, never from client input.
 */
function checkBinding(row, ctx) {
  if (String(row.user_id) !== String(ctx.userId)) return 'USER_MISMATCH';
  if (row.purpose !== ctx.purpose) return 'PURPOSE_MISMATCH';
  if (row.method !== String(ctx.method).toUpperCase()) return 'METHOD_MISMATCH';
  if (row.endpoint !== ctx.endpoint) return 'ENDPOINT_MISMATCH';
  if (row.context_hash !== contextHash(ctx)) return 'CONTEXT_MISMATCH';
  if (Number(row.is_expired) === 1) return 'EXPIRED';
  if (row.used_at) return 'ALREADY_USED';
  if (row.superseded_at) return 'SUPERSEDED';
  return null;
}

/** Failed-attempt bookkeeping. Runs OUTSIDE any consume transaction so a rollback cannot erase it. */
async function recordFailedAttempt(sequelize, ottId) {
  await sequelize.query('UPDATE one_time_tokens SET attempt_count = attempt_count + 1 WHERE id = :ottId', {
    replacements: { ottId },
    type: QueryTypes.UPDATE,
  });
}

/**
 * Atomically consume an OTT and apply the sensitive operation in ONE transaction (7.4 steps 6-11).
 * `operation(t)` runs inside the transaction (e.g. UPDATE users SET password_hash ...).
 * bcrypt hashing must be done BEFORE calling this (never inside the transaction).
 * Returns { consumed: true } or { consumed: false } (OTT not consumable: nothing was changed).
 */
async function consumeOtt(sequelize, { ottId, userId, operation }) {
  if (process.env.UNSAFE_NON_ATOMIC_CONSUME === 'true') {
    return unsafeNonAtomicConsume(sequelize, { ottId, operation });
  }
  try {
    return await sequelize.transaction({ isolationLevel: RC }, async (t) => {
      if (!(await lockUserRow(sequelize, userId, t))) throw new ConsumeRejected();
      const upd = await sequelize.query(
        `UPDATE one_time_tokens SET used_at = NOW(3)
          WHERE id = :ottId AND user_id = :userId
            AND used_at IS NULL AND superseded_at IS NULL AND expires_at > NOW(3)`,
        { replacements: { ottId, userId }, type: QueryTypes.UPDATE, transaction: t }
      );
      if (affectedRows(upd) !== 1) throw new ConsumeRejected(); // rolls back
      await operation(t);
      return { consumed: true };
    });
  } catch (e) {
    if (e instanceof ConsumeRejected) return { consumed: false };
    throw wrapLockError(e);
  }
}

/**
 * TEST-ONLY negative control (EXPERIMENTS.md 8.2): plain SELECT-then-UPDATE with no user lock and
 * no conditional guard. Exists only to prove the concurrency tests can detect a violation.
 * Refused unless APP_PROFILE=test.
 */
async function unsafeNonAtomicConsume(sequelize, { ottId, operation }) {
  if (process.env.APP_PROFILE !== 'test') {
    throw new Error('UNSAFE_NON_ATOMIC_CONSUME is only allowed when APP_PROFILE=test');
  }
  const rows = await sequelize.query('SELECT used_at FROM one_time_tokens WHERE id = :ottId', {
    replacements: { ottId }, type: QueryTypes.SELECT,
  });
  if (!rows[0] || rows[0].used_at) return { consumed: false };
  const delay = Number(process.env.UNSAFE_DELAY_MS || 0);
  if (delay > 0) await new Promise((r) => setTimeout(r, delay));
  await sequelize.query('UPDATE one_time_tokens SET used_at = NOW(3) WHERE id = :ottId', {
    replacements: { ottId }, type: QueryTypes.UPDATE,
  });
  await sequelize.transaction({ isolationLevel: RC }, (t) => operation(t));
  return { consumed: true };
}

/** State classification for tests/analysis. Precedence: used > superseded > expired > active. */
async function countStates(sequelize, { userId, purpose, method, endpoint }) {
  const [r] = await sequelize.query(
    `SELECT COUNT(*) AS total,
            SUM(used_at IS NOT NULL) AS used,
            SUM(used_at IS NULL AND superseded_at IS NOT NULL) AS superseded,
            SUM(used_at IS NULL AND superseded_at IS NULL AND expires_at <= NOW(3)) AS expired,
            SUM(used_at IS NULL AND superseded_at IS NULL AND expires_at > NOW(3)) AS active,
            SUM(used_at IS NOT NULL AND superseded_at IS NOT NULL) AS both_flags
       FROM one_time_tokens
      WHERE user_id = :userId AND purpose = :purpose AND method = :method AND endpoint = :endpoint`,
    { replacements: { userId, purpose, method: String(method).toUpperCase(), endpoint }, type: QueryTypes.SELECT }
  );
  const n = (v) => Number(v || 0);
  return { total: n(r.total), used: n(r.used), superseded: n(r.superseded), expired: n(r.expired),
           active: n(r.active), bothFlags: n(r.both_flags) };
}

/** Security audit event. Never pass raw tokens or passwords in `details`. */
async function logEvent(sequelize, ev, t) {
  await sequelize.query(
    `INSERT INTO security_events (user_id, event_type, reason, auth_mode, http_method, endpoint, ip, details)
     VALUES (:userId, :eventType, :reason, :authMode, :httpMethod, :endpoint, :ip, :details)`,
    {
      replacements: {
        userId: ev.userId ?? null, eventType: ev.eventType, reason: ev.reason ?? null,
        authMode: ev.authMode ?? null, httpMethod: ev.httpMethod ?? null, endpoint: ev.endpoint ?? null,
        ip: ev.ip ?? null, details: ev.details ? JSON.stringify(ev.details) : null,
      },
      type: QueryTypes.INSERT,
      transaction: t,
    }
  );
}

module.exports = {
  issueOtt, lookupOtt, checkBinding, recordFailedAttempt, consumeOtt, countStates, logEvent,
  contextHash, sha256, wrapLockError,
};
