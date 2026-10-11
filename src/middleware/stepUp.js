'use strict';
// Step-up guard for sensitive operations, selected by AUTH_MODE:
//   A, B : none (a valid access JWT is enough)
//   D    : current-password re-entry (bcrypt compare)
//   C    : OOB one-time token (see services/ottService.js). Fails closed if the OTT service is missing.
const { QueryTypes } = require('sequelize');
const { logEvent } = require('../db/ottTransactions');

const D_FAIL_BODY = { error: 'Invalid credentials for this operation' };

function createStepUp({ sequelize, config, passwords, ottService }) {
  const base = { authMode: config.authMode };
  const ctxOf = (req) => ({
    httpMethod: req.method,
    endpoint: String(req.originalUrl || '').split('?')[0].slice(0, 128),
    ip: req.ip,
  });

  if (config.authMode === 'A' || config.authMode === 'B') return () => (req, res, next) => next();

  if (config.authMode === 'C') {
    if (!ottService) return () => (req, res) => res.status(501).json({ error: 'Not implemented' }); // fail closed
    return (operation) => ottService.guard(operation);
  }

  // Config D
  return (operation) => async (req, res, next) => {
    const reject = async (reason) => {
      try {
        await logEvent(sequelize, { ...base, userId: req.auth.userId, eventType: 'PASSWORD_REENTRY_FAILURE',
          reason, details: { operation }, ...ctxOf(req) });
      } catch (e) { console.error('security event logging failed:', e.code || e.name); }
      return res.status(403).json(D_FAIL_BODY);
    };
    try {
      const pw = req.body && typeof req.body === 'object' ? req.body.currentPassword : undefined;
      if (pw === undefined) return await reject('MISSING_PASSWORD');
      if (!passwords.isPlausible(pw)) return await reject('INVALID_INPUT');
      const rows = await sequelize.query('SELECT password_hash FROM users WHERE id = :id',
        { replacements: { id: req.auth.userId }, type: QueryTypes.SELECT });
      if (rows.length === 0) return res.status(401).json({ error: 'Authentication failed' });
      if (!(await passwords.verify(pw, rows[0].password_hash))) return await reject('BAD_PASSWORD');
      return next();
    } catch (e) {
      return next(e);
    }
  };
}

module.exports = { createStepUp };
