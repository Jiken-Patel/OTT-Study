'use strict';
// Rate limiters (EXPERIMENTS.md 3.1 / 3.2). Values are experimental parameters, not recommendations.
// Per-IP limiters run BEFORE authentication; per-user limiters run AFTER it (key = authenticated user id).
// The first blocked request in a window is logged once as RATE_LIMITED (not every blocked request,
// which would let a flood amplify into database writes).
const rateLimit = require('express-rate-limit');
const { logEvent } = require('../db/ottTransactions');

const WINDOW_MS = 60 * 1000;
const PROFILES = {
  standard: { login: 10, refresh: 30, ottIssue: 5, sensitiveUser: 10, sensitiveIp: 30 },
  relaxed: { login: 10000, refresh: 10000, ottIssue: 10000, sensitiveUser: 10000, sensitiveIp: 10000 },
};
const KEYS = { login: 'ip', refresh: 'ip', sensitiveIp: 'ip', ottIssue: 'user', sensitiveUser: 'user' };

function createRateLimiters({ sequelize, config }) {
  const names = Object.keys(KEYS);
  if (config.rateLimitProfile === 'off') {
    return Object.fromEntries(names.map((n) => [n, (req, res, next) => next()]));
  }
  const limits = PROFILES[config.rateLimitProfile];

  const make = (name) => rateLimit({
    windowMs: WINDOW_MS,
    limit: limits[name],
    standardHeaders: 'draft-6', // RateLimit-Limit / -Remaining / -Reset (recorded by the tests)
    legacyHeaders: false,
    validate: false,
    keyGenerator: KEYS[name] === 'ip' ? (req) => req.ip : (req) => String(req.auth.userId),
    handler: async (req, res) => {
      if (req.rateLimit && req.rateLimit.used === req.rateLimit.limit + 1) {
        try {
          await logEvent(sequelize, {
            userId: req.auth ? req.auth.userId : null, eventType: 'RATE_LIMITED', reason: name,
            authMode: config.authMode, httpMethod: req.method,
            endpoint: String(req.originalUrl || '').split('?')[0].slice(0, 128), ip: req.ip,
            details: { limiter: name, limit: req.rateLimit.limit, windowMs: WINDOW_MS },
          });
        } catch (e) {
          console.error('security event logging failed:', e.code || e.name);
        }
      }
      res.status(429).json({ error: 'Too many requests' });
    },
  });

  return Object.fromEntries(names.map((n) => [n, make(n)]));
}

module.exports = { createRateLimiters, PROFILES, WINDOW_MS };
