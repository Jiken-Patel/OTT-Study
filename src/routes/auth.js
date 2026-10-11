'use strict';
const express = require('express');

function createAuthRouter({ authService, authenticate, limiters }) {
  const router = express.Router();
  const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  const body = (req) => (req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {});

  router.post('/register', wrap(async (req, res) => {
    const r = await authService.register(req, body(req));
    if (!r.ok) return res.status(r.status).json({ error: r.error });
    return res.status(201).json({ id: String(r.user.id), email: r.user.email });
  }));

  router.post('/login', limiters.login, wrap(async (req, res) => {
    const r = await authService.login(req, body(req));
    if (!r.ok) return res.status(401).json({ error: 'Invalid credentials' });
    return res.json(r.tokens);
  }));

  if (authService.refreshEnabled) { // Config A: the route does not exist
    router.post('/refresh', limiters.refresh, wrap(async (req, res) => {
      const r = await authService.refresh(req, body(req));
      if (!r.ok) return res.status(401).json({ error: 'Authentication failed' });
      return res.json(r.tokens);
    }));
  }

  router.post('/logout', authenticate, wrap(async (req, res) => {
    const { refreshToken } = body(req);
    if (authService.refreshEnabled && typeof refreshToken !== 'string') {
      return res.status(400).json({ error: 'Invalid logout request' }); // nothing is revoked
    }
    await authService.logout(req, { auth: req.auth, refreshToken });
    return res.status(204).end();
  }));

  return router;
}

module.exports = { createAuthRouter };
