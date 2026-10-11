'use strict';
// POST /api/ott/request (Config C only). Chain: per-IP limiter -> authenticate -> per-user limiter -> handler.
// The per-IP limiter also guards this route so unauthenticated floods (each failed authentication writes an
// audit row) are limited before authentication, exactly as for the other sensitive routes (3.2).
// The response NEVER contains the OTT.
const express = require('express');

function createOttRouter({ ottService, authenticate, limiters, config }) {
  const router = express.Router();
  const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  router.post('/request', limiters.sensitiveIp, authenticate, limiters.ottIssue, wrap(async (req, res) => {
    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    const r = await ottService.request(req, body);
    if (!r.ok) return res.status(400).json({ error: 'Invalid request' });
    return res.status(202).json({ status: 'ott_issued', expiresIn: config.ottTtlSeconds });
  }));
  return router;
}

module.exports = { createOttRouter };
