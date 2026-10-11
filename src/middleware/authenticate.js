'use strict';
// authenticateAccessToken: Authorization: Bearer <access JWT> -> req.auth
// Every failure returns the SAME generic 401 body (no oracle). The precise reason is only logged
// internally as a security event. Fails CLOSED: if the revocation lookup fails the request is a 500,
// never an authenticated request.
const { TokenError } = require('../services/tokenService');
const { isRevoked } = require('../services/revocation');
const { logEvent } = require('../db/ottTransactions');

const BEARER_RE = /^bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)$/i;

function createAuthenticate({ sequelize, tokenService, authMode }) {
  async function reject(req, res, reason, userId = null) {
    // Synchronous (awaited) logging, identical in all configurations (EXPERIMENTS.md 3).
    // A logging failure must not change the response.
    try {
      await logEvent(sequelize, {
        userId, eventType: 'AUTH_FAILURE', reason, authMode,
        httpMethod: req.method, endpoint: String(req.originalUrl || '').split('?')[0].slice(0, 128),
        ip: req.ip,
      });
    } catch (e) {
      console.error('security event logging failed:', e.code || e.name);
    }
    res.set('WWW-Authenticate', 'Bearer');
    return res.status(401).json({ error: 'Authentication failed' });
  }

  return async function authenticateAccessToken(req, res, next) {
    try {
      const header = req.headers.authorization;
      if (!header) return await reject(req, res, 'MISSING_AUTH_HEADER');
      const m = BEARER_RE.exec(header);
      if (!m) return await reject(req, res, 'MALFORMED_AUTH_HEADER');

      let claims;
      try {
        claims = tokenService.verifyAccess(m[1]);
      } catch (e) {
        if (e instanceof TokenError) return await reject(req, res, e.reason);
        throw e;
      }

      if (await isRevoked(sequelize, claims.jti)) {
        return await reject(req, res, 'TOKEN_REVOKED', claims.userId);
      }

      req.auth = { userId: claims.userId, jti: claims.jti, exp: claims.exp };
      return next();
    } catch (err) {
      return next(err);
    }
  };
}

module.exports = { createAuthenticate };
