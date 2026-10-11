'use strict';
// Sensitive endpoints. Middleware order (EXPERIMENTS.md 3.2):
//   per-IP limiter -> authenticate -> per-user limiter -> [body validation] -> step-up guard -> handler
const express = require('express');
const { OPERATIONS } = require('../operations');
const { logEvent } = require('../db/ottTransactions');

function createSensitiveRouter({ sequelize, config, authenticate, limiters, passwords, stepUp, sensitiveService, ottService }) {
  const router = express.Router();
  const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  const rel = (endpoint) => endpoint.replace('/api/auth', '');
  const chain = (name, handler, pre = []) => [
    limiters.sensitiveIp, authenticate, limiters.sensitiveUser, ...pre, stepUp(name), wrap(handler),
  ];

  async function logSuccess(req, operation) {
    try {
      await logEvent(sequelize, {
        authMode: config.authMode, userId: req.auth.userId, eventType: 'SENSITIVE_OPERATION_SUCCESS',
        details: { operation }, httpMethod: req.method,
        endpoint: String(req.originalUrl || '').split('?')[0].slice(0, 128), ip: req.ip,
      });
    } catch (e) { console.error('security event logging failed:', e.code || e.name); }
  }

  // Runs the operation's write. Config C: inside the atomic OTT consumption transaction (7.4 steps 6-11);
  // A/B/D: directly. Returns false (after sending 403) if the OTT could not be consumed.
  async function execute(req, res, name, apply) {
    if (config.authMode === 'C') {
      const r = await ottService.consumeAndApply(req, name, apply);
      if (!r.ok) { res.status(403).json(ottService.OTT_FAIL_BODY); return false; }
    } else {
      await apply();
    }
    await logSuccess(req, name);
    return true;
  }

  const validateNewPassword = (req, res, next) => {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    if (passwords.validateNew(b.newPassword)) return res.status(400).json({ error: 'Invalid password' });
    return next();
  };

  const cp = OPERATIONS.change_password;
  router.post(rel(cp.endpoint), ...chain('change_password', async (req, res) => {
    const hash = await sensitiveService.preparePasswordChange(req.body.newPassword); // bcrypt, outside any tx
    const done = await execute(req, res, 'change_password', (t) => sensitiveService.writePasswordChange(req.auth.userId, hash, t));
    if (done) return res.json({ status: 'password_changed' });
    return undefined;
  }, [validateNewPassword]));

  if (config.enableSimulatedOperations) {
    for (const [name, op] of Object.entries(OPERATIONS)) {
      if (!op.simulated) continue;
      router[op.method.toLowerCase()](rel(op.endpoint), ...chain(name, async (req, res) => {
        const done = await execute(req, res, name, async () => {}); // simulated: consumes the OTT, writes nothing
        if (done) return res.json({ status: 'ok', operation: name });
        return undefined;
      }));
    }
  }
  return router;
}

module.exports = { createSensitiveRouter };
