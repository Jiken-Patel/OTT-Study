'use strict';
// Registration, login, refresh rotation with reuse detection, logout (EXPERIMENTS.md 7.5 / 7.6).
// Lock order everywhere: users -> refresh_tokens / one_time_tokens. Isolation: READ COMMITTED.
// bcrypt work happens OUTSIDE transactions.
const crypto = require('crypto');
const { QueryTypes, Transaction } = require('sequelize');
const { TokenError } = require('./tokenService');
const { revokeAccessToken } = require('./revocation');
const { logEvent, sha256, wrapLockError } = require('../db/ottTransactions');

const RC = Transaction.ISOLATION_LEVELS.READ_COMMITTED;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const rows = (r) => (Array.isArray(r) ? r[1] : r);

function createAuthService({ sequelize, config, tokenService, passwords }) {
  const refreshEnabled = config.authMode !== 'A'; // Config A has no refresh tokens
  const base = { authMode: config.authMode };

  async function safeLog(ev) {
    try { await logEvent(sequelize, { ...base, ...ev }); }
    catch (e) { console.error('security event logging failed:', e.code || e.name); }
  }
  const ctxOf = (req) => ({
    httpMethod: req.method,
    endpoint: String(req.originalUrl || '').split('?')[0].slice(0, 128),
    ip: req.ip,
  });

  const lockUser = async (userId, t) => (await sequelize.query(
    'SELECT id FROM users WHERE id = :userId FOR UPDATE',
    { replacements: { userId }, type: QueryTypes.SELECT, transaction: t })).length === 1;

  const insertRefresh = (t, { userId, familyId, refresh }) => sequelize.query(
    `INSERT INTO refresh_tokens (user_id, family_id, jti, token_hash, expires_at)
     VALUES (:userId, :familyId, :jti, :hash, DATE_ADD('1970-01-01 00:00:00', INTERVAL :exp SECOND))`,
    { replacements: { userId, familyId, jti: refresh.jti, hash: sha256(refresh.token), exp: refresh.exp },
      type: QueryTypes.INSERT, transaction: t });

  const revokeFamily = (t, familyId) => sequelize.query(
    'UPDATE refresh_tokens SET revoked_at = NOW(3) WHERE family_id = :familyId AND revoked_at IS NULL',
    { replacements: { familyId }, type: QueryTypes.UPDATE, transaction: t });

  function tokenResponse(access, refresh) {
    const out = { accessToken: access.token, tokenType: 'Bearer', expiresIn: config.jwt.accessTtlSeconds };
    if (refresh) { out.refreshToken = refresh.token; out.refreshExpiresIn = config.jwt.refreshTtlSeconds; }
    return out;
  }

  async function register(req, { email, password }) {
    if (typeof email !== 'string') return { ok: false, status: 400, error: 'Invalid email' };
    const norm = email.trim().toLowerCase();
    if (norm.length > 255 || !EMAIL_RE.test(norm)) return { ok: false, status: 400, error: 'Invalid email' };
    const problem = passwords.validateNew(password);
    if (problem) return { ok: false, status: 400, error: 'Invalid password' };
    const hash = await passwords.hash(password);
    try {
      const r = await sequelize.query('INSERT INTO users (email, password_hash) VALUES (:email, :hash)',
        { replacements: { email: norm, hash }, type: QueryTypes.INSERT });
      const user = { id: r[0], email: norm };
      await safeLog({ userId: user.id, eventType: 'REGISTER', ...ctxOf(req) });
      return { ok: true, user };
    } catch (e) {
      if (e.original && e.original.errno === 1062) return { ok: false, status: 409, error: 'Email already registered' };
      throw e;
    }
  }

  async function login(req, { email, password }) {
    const fail = async (reason, userId = null) => {
      await safeLog({ userId, eventType: 'LOGIN_FAILURE', reason, ...ctxOf(req) });
      return { ok: false };
    };
    if (typeof email !== 'string' || !passwords.isPlausible(password)) return fail('INVALID_INPUT');
    const found = await sequelize.query('SELECT id, password_hash FROM users WHERE email = :email',
      { replacements: { email: email.trim().toLowerCase() }, type: QueryTypes.SELECT });
    const user = found[0];
    // Always pay one bcrypt comparison so unknown users are not distinguishable by timing.
    const match = user ? await passwords.verify(password, user.password_hash) : await passwords.verifyAgainstDummy(password);
    if (!user) return fail('USER_NOT_FOUND');
    if (!match) return fail('BAD_PASSWORD', user.id);

    const access = tokenService.signAccess(user.id);
    let refresh = null;
    if (refreshEnabled) {
      refresh = tokenService.signRefresh(user.id);
      await sequelize.transaction({ isolationLevel: RC }, async (t) => {
        await insertRefresh(t, { userId: user.id, familyId: crypto.randomUUID(), refresh });
      }).catch((e) => { throw wrapLockError(e); });
    }
    await safeLog({ userId: user.id, eventType: 'LOGIN_SUCCESS', ...ctxOf(req) });
    return { ok: true, tokens: tokenResponse(access, refresh) };
  }

  /** Refresh rotation (7.5). Reuse of a revoked token revokes the whole family and returns 401. */
  async function refresh(req, { refreshToken }) {
    const failEvent = (reason, userId = null) => safeLog({
      userId, eventType: reason === 'REFRESH_REPLAY' ? 'REFRESH_REPLAY' : 'REFRESH_FAILURE', reason, ...ctxOf(req),
    });
    if (typeof refreshToken !== 'string') { await failEvent('MISSING_REFRESH_TOKEN'); return { ok: false }; }
    let claims;
    try { claims = tokenService.verifyRefresh(refreshToken); }
    catch (e) {
      if (e instanceof TokenError) { await failEvent(e.reason); return { ok: false }; }
      throw e;
    }
    const hash = sha256(refreshToken);
    const nextRefresh = tokenService.signRefresh(claims.userId);
    const access = tokenService.signAccess(claims.userId);
    let outcome;
    try {
      outcome = await sequelize.transaction({ isolationLevel: RC }, async (t) => {
        if (!(await lockUser(claims.userId, t))) return { ok: false, reason: 'REFRESH_USER_MISSING' };
        const found = await sequelize.query(
          `SELECT id, user_id, family_id, revoked_at, (expires_at <= NOW(3)) AS is_expired
             FROM refresh_tokens WHERE token_hash = :hash`,
          { replacements: { hash }, type: QueryTypes.SELECT, transaction: t });
        const row = found[0];
        if (!row || String(row.user_id) !== String(claims.userId)) return { ok: false, reason: 'REFRESH_UNKNOWN' };
        if (row.revoked_at) {
          const n = rows(await revokeFamily(t, row.family_id));
          return { ok: false, reason: 'REFRESH_REPLAY', familyRevoked: n }; // committed: the revocation must persist
        }
        if (Number(row.is_expired) === 1) return { ok: false, reason: 'REFRESH_EXPIRED' };
        await sequelize.query('UPDATE refresh_tokens SET revoked_at = NOW(3) WHERE id = :id AND revoked_at IS NULL',
          { replacements: { id: row.id }, type: QueryTypes.UPDATE, transaction: t });
        const ins = await insertRefresh(t, { userId: claims.userId, familyId: row.family_id, refresh: nextRefresh });
        await sequelize.query('UPDATE refresh_tokens SET replaced_by = :newId WHERE id = :id',
          { replacements: { newId: Array.isArray(ins) ? ins[0] : ins, id: row.id }, type: QueryTypes.UPDATE, transaction: t });
        return { ok: true };
      });
    } catch (e) { throw wrapLockError(e); }

    if (!outcome.ok) {
      await safeLog({
        userId: claims.userId, eventType: outcome.reason === 'REFRESH_REPLAY' ? 'REFRESH_REPLAY' : 'REFRESH_FAILURE',
        reason: outcome.reason, details: outcome.familyRevoked !== undefined ? { familyRevoked: outcome.familyRevoked } : null,
        ...ctxOf(req),
      });
      return { ok: false };
    }
    await safeLog({ userId: claims.userId, eventType: 'REFRESH_SUCCESS', ...ctxOf(req) });
    return { ok: true, tokens: tokenResponse(access, nextRefresh) };
  }

  /** Logout: revoke the presented access jti and (B/C/D) the refresh family, in one transaction. */
  async function logout(req, { auth, refreshToken }) {
    try {
      await sequelize.transaction({ isolationLevel: RC }, async (t) => {
        await lockUser(auth.userId, t);
        await revokeAccessToken(sequelize, { jti: auth.jti, userId: auth.userId, exp: auth.exp }, t);
        if (refreshEnabled && typeof refreshToken === 'string') {
          const found = await sequelize.query('SELECT user_id, family_id FROM refresh_tokens WHERE token_hash = :hash',
            { replacements: { hash: sha256(refreshToken) }, type: QueryTypes.SELECT, transaction: t });
          // Only the owner's family is revoked; a token belonging to someone else is silently ignored.
          if (found[0] && String(found[0].user_id) === String(auth.userId)) await revokeFamily(t, found[0].family_id);
        }
      });
    } catch (e) { throw wrapLockError(e); }
    await safeLog({ userId: auth.userId, eventType: 'LOGOUT', ...ctxOf(req) });
  }

  return { register, login, refresh, logout, refreshEnabled };
}

module.exports = { createAuthService };
