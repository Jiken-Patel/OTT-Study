'use strict';
// Test environment for the security harness: app instances per (configuration, variant), the OOB sink,
// a seeded user pool (users are inserted with one precomputed bcrypt hash, then log in through the real API),
// and an HTTP client that can bind a source address.
const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { QueryTypes } = require('sequelize');
const sequelize = require('../../src/config/db');
const { loadConfig } = require('../../src/config');
const { createApp } = require('../../src/app');
const { createSink } = require('../../sink/oobSink');
const { createSinkClient } = require('../../test/helpers/sinkClient');
const { OPERATIONS } = require('../../src/operations');
const ott = require('../../src/db/ottTransactions');

const PW = 'harness-initial-password-1';
const NEW_PW = 'harness-new-password-1';
const SECRETS = { JWT_ACCESS_SECRET: 'harness-access-secret-0123456789-abcdefgh',
  JWT_REFRESH_SECRET: 'harness-refresh-secret-9876543210-hgfedcba' };
const DELIVER_KEY = 'harness-deliver-key-0123456789';
const READ_KEY = 'harness-read-key-9876543210zy';

class Harness {
  constructor() { this.servers = []; this.agents = new Map(); this.seq = 0; }

  async init() {
    this.pwHash = await bcrypt.hash(PW, 12); // one hash for all seeded users (setup, not measured)
    this.sink = createSink({ deliverKey: DELIVER_KEY, readKey: READ_KEY });
    this.sinkBase = `http://127.0.0.1:${await this.sink.listen(0)}`;
    this.inbox = createSinkClient({ baseUrl: this.sinkBase, readKey: READ_KEY });
    const [v] = await sequelize.query('SELECT VERSION() AS v', { type: QueryTypes.SELECT });
    this.mysqlVersion = v.v;
  }

  async close() {
    for (const s of this.servers) { s.sockets.forEach((c) => c.destroy()); await new Promise((r) => s.close(r)); }
    this.servers = [];
    for (const a of this.agents.values()) a.destroy();
    await this.sink.close();
  }

  /** Start an application instance. variant: 'relaxed' | 'standard' | 'ott-expiry'. */
  async startApp(mode, variant = 'relaxed', extraEnv = {}) {
    const env = {
      APP_PROFILE: 'test', AUTH_MODE: mode, ...SECRETS, ENABLE_SIMULATED_OPERATIONS: 'true',
      RATE_LIMIT_PROFILE: variant === 'standard' ? 'standard' : 'relaxed',
      ...(variant === 'ott-expiry' ? { OTT_EXPIRES_IN_SECONDS: '2' } : {}),
      ...(mode === 'C' ? { OOB_SINK_URL: this.sinkBase, OOB_SINK_KEY: DELIVER_KEY } : {}),
      ...extraEnv,
    };
    const config = loadConfig(env);
    const app = createApp({ sequelize, config });
    const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    server.sockets = new Set();
    server.on('connection', (c) => { server.sockets.add(c); c.on('close', () => server.sockets.delete(c)); });
    this.servers.push(server);
    return { mode, variant, config, app, server, base: `http://127.0.0.1:${server.address().port}`,
      tokenService: app.locals.tokenService,
      stop: async () => { server.sockets.forEach((c) => c.destroy()); await new Promise((r) => server.close(r)); this.servers = this.servers.filter((x) => x !== server); } };
  }

  agentFor(localAddress) {
    const key = localAddress || 'default';
    if (!this.agents.has(key)) this.agents.set(key, new http.Agent({ keepAlive: true, maxSockets: 256, ...(localAddress ? { localAddress } : {}) }));
    return this.agents.get(key);
  }

  /** Per-instance context handed to a test. */
  context(app, onRestart) {
    const self = this;
    const ctx = {
      mode: app.mode, app, appConfig: app.config, tokenService: app.tokenService, inbox: this.inbox, PW, NEW_PW, OPERATIONS,
      sequelize, ottDb: ott,
      req(method, path, { body, token, headers = {}, from } = {}) {
        return new Promise((resolve, reject) => {
          const u = new URL(app.base + path);
          const payload = body === undefined ? undefined : JSON.stringify(body);
          const t0 = process.hrtime.bigint();
          const r = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method, agent: self.agentFor(from),
            headers: { ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
              ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers } }, (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => {
              const text = Buffer.concat(chunks).toString('utf8');
              resolve({ status: res.statusCode, text, headers: res.headers, ms: Number(process.hrtime.bigint() - t0) / 1e6,
                json() { try { return JSON.parse(text); } catch (e) { return null; } } });
            });
          });
          r.on('error', reject);
          if (payload) r.write(payload);
          r.end();
        });
      },
      async user() {
        const email = `h${Date.now()}_${self.seq++}_${crypto.randomBytes(3).toString('hex')}@example.test`;
        const ins = await sequelize.query('INSERT INTO users (email, password_hash) VALUES (:email, :hash)',
          { replacements: { email, hash: self.pwHash }, type: QueryTypes.INSERT });
        const id = ins[0];
        const login = (pw = PW) => ctx.req('POST', '/api/auth/login', { body: { email, password: pw } });
        const r = await login();
        if (r.status !== 200) throw new Error(`seeded login failed: ${r.status}`);
        const t = r.json();
        return { id, email, access: t.accessToken, refresh: t.refreshToken, login };
      },
      /** A valid access token for a seeded user without a login round trip (used where login limits would interfere). */
      async userNoLogin() {
        const email = `h${Date.now()}_${self.seq++}_${crypto.randomBytes(3).toString('hex')}@example.test`;
        const ins = await sequelize.query('INSERT INTO users (email, password_hash) VALUES (:email, :hash)',
          { replacements: { email, hash: self.pwHash }, type: QueryTypes.INSERT });
        return { id: ins[0], email, access: ctx.tokenService.signAccess(ins[0]).token };
      },
      cp(token, extra = {}, opts = {}) { return ctx.req('POST', '/api/auth/change-password', { body: { newPassword: NEW_PW, ...extra }, token, ...opts }); },
      async issue(user, operation) {
        return ctx.req('POST', '/api/ott/request', { body: { purpose: OPERATIONS[operation].purpose, operation }, token: user.access });
      },
      /** Issue an OTT and read it from the legitimate user's OOB inbox (C only). */
      async ott(user, operation) {
        const r = await ctx.issue(user, operation);
        if (r.status !== 202) throw new Error(`issuance failed: ${r.status}`);
        return (await self.inbox.waitFor(user.id, 1))[0].token;
      },
      async count(type, reason, userId) {
        const [r] = await sequelize.query(
          `SELECT COUNT(*) AS n FROM security_events WHERE event_type = :type AND (:reason IS NULL OR reason = :reason) AND (:userId IS NULL OR user_id = :userId)`,
          { replacements: { type, reason: reason ?? null, userId: userId ?? null }, type: QueryTypes.SELECT });
        return Number(r.n);
      },
      async hash(userId) {
        return (await sequelize.query('SELECT password_hash FROM users WHERE id = :id', { replacements: { id: userId }, type: QueryTypes.SELECT }))[0].password_hash;
      },
      /** Replace this instance with a fresh one (clears in-memory rate-limit stores). */
      restart: async (variant) => onRestart(variant),
    };
    return ctx;
  }
}

module.exports = { Harness, PW, NEW_PW, OPERATIONS };
