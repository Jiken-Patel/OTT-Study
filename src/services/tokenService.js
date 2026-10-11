'use strict';
// JWT signing/verification (HS256 only). jsonwebtoken does NOT require exp, iat, sub, jti or type,
// so this layer enforces them explicitly (EXPERIMENTS.md T21-T23).
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SUB_RE = /^[1-9][0-9]{0,19}$/;

class TokenError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'TokenError';
    this.reason = reason;
  }
}

function createTokenService(config) {
  const { algorithm, issuer, audience } = config.jwt;

  function sign(type, secret, ttlSeconds, userId) {
    const jti = crypto.randomUUID();
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + ttlSeconds;
    const token = jwt.sign({ type, iat, exp }, secret, {
      algorithm, issuer, audience, subject: String(userId), jwtid: jti,
    });
    return { token, jti, exp, expiresAt: new Date(exp * 1000) };
  }

  function verify(token, secret, expectedType) {
    let payload;
    try {
      payload = jwt.verify(token, secret, { algorithms: [algorithm], issuer, audience, clockTolerance: 0 });
    } catch (e) {
      if (e && e.name === 'TokenExpiredError') throw new TokenError('TOKEN_EXPIRED');
      if (e && e.name === 'NotBeforeError') throw new TokenError('TOKEN_NOT_YET_VALID');
      throw new TokenError('TOKEN_INVALID'); // bad signature, wrong alg, wrong iss/aud, malformed
    }
    if (payload.type !== expectedType) throw new TokenError('TOKEN_WRONG_TYPE');
    if (!Number.isInteger(payload.exp) || !Number.isInteger(payload.iat) || payload.exp <= payload.iat) {
      throw new TokenError('TOKEN_CLAIMS_INVALID');
    }
    if (typeof payload.sub !== 'string' || !SUB_RE.test(payload.sub)) throw new TokenError('TOKEN_CLAIMS_INVALID');
    if (typeof payload.jti !== 'string' || !UUID_RE.test(payload.jti)) throw new TokenError('TOKEN_CLAIMS_INVALID');
    return { userId: payload.sub, jti: payload.jti, exp: payload.exp, iat: payload.iat };
  }

  return {
    signAccess: (userId) => sign('access', config.jwt.accessSecret, config.jwt.accessTtlSeconds, userId),
    signRefresh: (userId) => sign('refresh', config.jwt.refreshSecret, config.jwt.refreshTtlSeconds, userId),
    verifyAccess: (token) => verify(token, config.jwt.accessSecret, 'access'),
    verifyRefresh: (token) => verify(token, config.jwt.refreshSecret, 'refresh'),
  };
}

module.exports = { createTokenService, TokenError };
