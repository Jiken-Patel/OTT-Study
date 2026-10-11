'use strict';
const express = require('express');
const helmet = require('helmet');
const { QueryTypes } = require('sequelize');
const { createTokenService } = require('./services/tokenService');
const { createAuthenticate } = require('./middleware/authenticate');
const { createRateLimiters } = require('./middleware/rateLimit');
const { createPasswordService } = require('./services/passwords');
const { createAuthService } = require('./services/authService');
const { createAuthRouter } = require('./routes/auth');
const { createSensitiveRouter } = require('./routes/sensitive');
const { createSensitiveService } = require('./services/sensitiveService');
const { createStepUp } = require('./middleware/stepUp');
const { createOobDelivery } = require('./services/oobDelivery');
const { createOttService } = require('./services/ottService');
const { createOttRouter } = require('./routes/ott');

function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  if (res.headersSent) return next(err);
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed request body' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large' });
  if (err && err.code === 'DB_LOCK_ERROR') { console.error('unhandled error: DB_LOCK_ERROR', err.errno); return res.status(500).json({ error: 'Internal server error' }); }
  console.error('unhandled error:', (err && (err.code || err.name)) || 'unknown'); // never log messages/tokens
  return res.status(500).json({ error: 'Internal server error' });
}

function createApp({ sequelize, config }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use(helmet());
  app.use(express.json({ limit: '10kb' }));

  const tokenService = createTokenService(config);
  const authenticate = createAuthenticate({ sequelize, tokenService, authMode: config.authMode });
  app.locals.tokenService = tokenService;
  const limiters = createRateLimiters({ sequelize, config });
  const passwords = createPasswordService(config);
  const authService = createAuthService({ sequelize, config, tokenService, passwords });
  app.locals.limiters = limiters;
  app.locals.passwords = passwords;
  app.use('/api/auth', createAuthRouter({ authService, authenticate, limiters }));
  const sensitiveService = createSensitiveService({ sequelize, passwords });
  const ottService = config.authMode === 'C'
    ? createOttService({ sequelize, config, delivery: createOobDelivery({ config }) }) : null;
  const stepUp = createStepUp({ sequelize, config, passwords, ottService });
  app.use('/api/auth', createSensitiveRouter({ sequelize, config, authenticate, limiters, passwords, stepUp, sensitiveService, ottService }));
  if (ottService) app.use('/api/ott', createOttRouter({ ottService, authenticate, limiters, config }));

  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

  // Ordinary protected endpoint (benchmark P1; tests T01, T21-T24).
  app.get('/api/profile', authenticate, async (req, res, next) => {
    try {
      const rows = await sequelize.query('SELECT id, email, created_at FROM users WHERE id = :id', {
        replacements: { id: req.auth.userId }, type: QueryTypes.SELECT,
      });
      if (rows.length === 0) return res.status(401).json({ error: 'Authentication failed' });
      return res.json({ id: String(rows[0].id), email: rows[0].email, createdAt: rows[0].created_at });
    } catch (e) {
      return next(e);
    }
  });

  app.use((req, res) => res.status(404).json({ error: 'Not found' }));
  app.use(errorHandler);
  return app;
}

module.exports = { createApp };
