'use strict';
// Config C: OTT issuance, verification guard and consume-and-apply (EXPERIMENTS.md 7.2-7.4).
// Calls go through the `ott` module object (not destructured) so tests can stub individual functions.
const ott = require('../db/ottTransactions');
const { OPERATIONS } = require('../operations');
const { deliveryFailureReason } = require('./oobDelivery');

const OTT_FAIL_BODY = Object.freeze({ error: 'Invalid or unavailable one-time token' });
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function createOttService({ sequelize, config, delivery }) {
  const base = { authMode: config.authMode };
  const ctxOf = (req) => ({
    httpMethod: req.method,
    endpoint: String(req.originalUrl || '').split('?')[0].slice(0, 128),
    ip: req.ip,
  });
  async function safeLog(ev) {
    try { await ott.logEvent(sequelize, { ...base, ...ev }); }
    catch (e) { console.error('security event logging failed:', e.code || e.name); }
  }
  async function safeBump(ottId) { // failed-attempt bookkeeping must never change the response
    try { await ott.recordFailedAttempt(sequelize, ottId); }
    catch (e) { console.error('attempt_count update failed:', e.code || e.name); }
  }
  async function logLockError(req, e, operation) {
    if (e && e.code === 'DB_LOCK_ERROR') {
      await safeLog({ userId: req.auth ? req.auth.userId : null, eventType: 'DB_LOCK_ERROR', reason: String(e.errno),
        details: { operation }, ...ctxOf(req) });
    }
  }

  /** POST /api/ott/request. The OTT is NEVER returned to the caller; it goes to the OOB sink. */
  async function request(req, body) {
    const operation = body.operation;
    const op = typeof operation === 'string' && has(OPERATIONS, operation) ? OPERATIONS[operation] : null;
    if (!op || typeof body.purpose !== 'string' || body.purpose !== op.purpose
        || (op.simulated && !config.enableSimulatedOperations)) return { ok: false };
    const userId = req.auth.userId;
    let issued;
    try {
      issued = await ott.issueOtt(sequelize, { userId, purpose: op.purpose, method: op.method, endpoint: op.endpoint,
        ttlSeconds: config.ottTtlSeconds });
    } catch (e) { await logLockError(req, e, operation); throw e; }

    // Handoff after commit, not awaited: the response is not delayed by delivery.
    delivery.deliver({ userId, operation, purpose: op.purpose, token: issued.rawToken }).catch((e) => {
      safeLog({ userId, eventType: 'OTT_DELIVERY_FAILURE', reason: deliveryFailureReason(e), details: { operation }, ...ctxOf(req) });
    });
    await safeLog({ userId, eventType: 'OTT_ISSUED', details: { operation, supersededCount: issued.supersededCount }, ...ctxOf(req) });
    return { ok: true };
  }

  /** Step-up guard (7.4 steps 3-4): cheap read-only checks in the frozen order. Sets req.ott on success. */
  const guard = (operationName) => async (req, res, next) => {
    try {
      const op = OPERATIONS[operationName];
      const fail = async (reason, row = null) => {
        if (row) await safeBump(row.id);
        await safeLog({ userId: req.auth.userId, eventType: 'OTT_FAILURE', reason, details: { operation: operationName }, ...ctxOf(req) });
        return res.status(403).json(OTT_FAIL_BODY);
      };
      const raw = req.body && typeof req.body === 'object' ? req.body.ott : undefined;
      if (raw === undefined || raw === null || raw === '') return await fail('MISSING_OTT');
      if (typeof raw !== 'string' || raw.length > 128) return await fail('INVALID_TOKEN');
      const row = await ott.lookupOtt(sequelize, raw);
      if (!row) return await fail('INVALID_TOKEN'); // unmatched hash: no row to bump
      // Context comes from the server-side registry (== the registered route), never from client input.
      const reason = ott.checkBinding(row, { userId: req.auth.userId, purpose: op.purpose, method: op.method, endpoint: op.endpoint });
      if (reason) return await fail(reason, row);
      req.ott = { raw, id: row.id };
      return next();
    } catch (e) {
      return next(e);
    }
  };

  /** Atomic consume + the operation's write in ONE transaction (7.4 steps 6-11). */
  async function consumeAndApply(req, operationName, apply) {
    const op = OPERATIONS[operationName];
    let r;
    try {
      r = await ott.consumeOtt(sequelize, { ottId: req.ott.id, userId: req.auth.userId, operation: apply });
    } catch (e) { await logLockError(req, e, operationName); throw e; }
    if (r.consumed) return { ok: true };
    // Lost the race, or the state changed after the cheap check: classify, record, fail.
    const row = await ott.lookupOtt(sequelize, req.ott.raw);
    const reason = row
      ? (ott.checkBinding(row, { userId: req.auth.userId, purpose: op.purpose, method: op.method, endpoint: op.endpoint }) || 'ALREADY_USED')
      : 'INVALID_TOKEN';
    if (row) await safeBump(row.id);
    await safeLog({ userId: req.auth.userId, eventType: 'OTT_FAILURE', reason, details: { operation: operationName }, ...ctxOf(req) });
    return { ok: false };
  }

  return { request, guard, consumeAndApply, OTT_FAIL_BODY };
}

module.exports = { createOttService, OTT_FAIL_BODY };
